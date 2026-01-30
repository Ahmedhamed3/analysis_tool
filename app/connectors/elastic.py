from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from app.utils.checkpoint import ElasticCheckpoint, load_elastic_checkpoint, save_elastic_checkpoint
from app.utils.http_status import HttpStatusServer, tail_ndjson
from app.utils.ndjson_writer import append_ndjson
from app.utils.pathing import build_elastic_output_path
from app.utils.timeutil import to_utc_iso, utc_now_iso

DEFAULT_POLL_SECONDS = 10
DEFAULT_MAX_EVENTS = 500
DEFAULT_START_AGO_SECONDS = 3600
DEFAULT_INDICES = "logs-*"
DEFAULT_TAIL_SIZE = 200
DEFAULT_ES_URL = "http://127.0.0.1:9200"
DEFAULT_USERNAME = "elastic"
CHECKPOINT_PATH = "state/elastic_checkpoint.json"
BASE_OUTPUT_DIR = "out/raw/siem/elastic"


class TransientElasticsearchError(RuntimeError):
    pass


@dataclass
class ConnectorConfig:
    poll_seconds: int
    max_events: int
    http_port: int | None
    indices: str
    start_ago_seconds: int
    es_url: str
    username: str
    password: str


@dataclass
class ElasticStatusState:
    last_ts: str | None = None
    last_id: str | None = None
    events_written_total: int = 0
    last_batch_count: int = 0
    last_error: str | None = None
    updated_at_utc: str = field(default_factory=utc_now_iso)

    def as_health(self) -> dict:
        return {"ok": True}

    def as_status(self) -> dict:
        return {
            "last_ts": self.last_ts,
            "last_id": self.last_id,
            "events_written_total": self.events_written_total,
            "last_batch_count": self.last_batch_count,
            "last_error": self.last_error,
            "updated_at_utc": self.updated_at_utc,
        }

    def update(self, **kwargs: object) -> None:
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at_utc = utc_now_iso()


class ElasticConnector:
    def __init__(
        self,
        es_url: str,
        indices: str,
        username: str,
        password: str,
        start_ago_seconds: int,
        tail_size: int = DEFAULT_TAIL_SIZE,
    ) -> None:
        self.es_url = es_url.rstrip("/")
        self.indices = indices
        self.username = username
        self.password = password
        self.start_ago_seconds = start_ago_seconds
        self.tail_buffer: deque[dict] = deque(maxlen=tail_size)

    def run_forever(self, poll_seconds: int, max_events: int, http_port: int | None) -> None:
        checkpoint = load_elastic_checkpoint(CHECKPOINT_PATH)
        if not checkpoint.indices:
            checkpoint.indices = self.indices
        status_state = ElasticStatusState(
            last_ts=checkpoint.last_ts,
            last_id=checkpoint.last_id,
        )
        http_server = None
        if http_port is not None:
            http_server = HttpStatusServer(
                host="127.0.0.1",
                port=http_port,
                status_state=status_state,
                tail_buffer=self.tail_buffer,
                tail_reader=lambda limit: tail_elastic_ndjson(BASE_OUTPUT_DIR, limit),
            )
            http_server.start()
            log(f"HTTP status server listening on 127.0.0.1:{http_port}")
        backoff = 1
        try:
            while True:
                try:
                    hits = self.fetch_new_events(checkpoint, max_events)
                    if hits:
                        records = list(self._format_records(hits))
                        written = self._write_records(records)
                        for record in records[-DEFAULT_TAIL_SIZE:]:
                            self.tail_buffer.append(record)
                        last_hit = hits[-1]
                        last_ts = to_utc_iso(
                            (last_hit.get("_source") or {}).get("@timestamp")
                        )
                        checkpoint.last_ts = last_ts
                        checkpoint.last_id = last_hit.get("_id")
                        checkpoint.indices = self.indices
                        save_elastic_checkpoint(CHECKPOINT_PATH, checkpoint)
                        status_state.update(
                            last_ts=checkpoint.last_ts,
                            last_id=checkpoint.last_id,
                            events_written_total=status_state.events_written_total
                            + written,
                            last_batch_count=written,
                            last_error=None,
                        )
                        log(
                            f"Wrote {written} events (last_ts={checkpoint.last_ts}, last_id={checkpoint.last_id})"
                        )
                    else:
                        status_state.update(last_batch_count=0, last_error=None)
                        log("No new events")
                    backoff = 1
                    time.sleep(poll_seconds)
                except Exception as exc:  # noqa: BLE001
                    status_state.update(last_error=str(exc))
                    log(f"Error reading events: {exc}")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
        finally:
            if http_server:
                http_server.stop()

    def fetch_new_events(
        self, checkpoint: ElasticCheckpoint, max_events: int
    ) -> list[dict]:
        hits: list[dict] = []
        search_after = None
        while True:
            query = build_elastic_query(
                checkpoint,
                max_events=max_events,
                start_ago_seconds=self.start_ago_seconds,
                search_after=search_after,
            )
            payload = self._search(query)
            batch = payload.get("hits", {}).get("hits", []) or []
            if not batch:
                break
            hits.extend(batch)
            if len(batch) < max_events:
                break
            last_sort = batch[-1].get("sort")
            if not last_sort:
                break
            search_after = last_sort
        return hits

    def _search(self, query: dict) -> dict:
        url = f"{self.es_url}/{self.indices}/_search"
        data = json.dumps(query).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", _build_basic_auth(self.username, self.password))
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status == 429 or response.status >= 500:
                    raise TransientElasticsearchError(
                        f"Elasticsearch returned {response.status}"
                    )
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"Elasticsearch returned {response.status}")
                payload = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429 or exc.code >= 500:
                raise TransientElasticsearchError(
                    f"Elasticsearch returned {exc.code}"
                ) from exc
            raise RuntimeError(f"Elasticsearch returned {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise TransientElasticsearchError("Elasticsearch connection failed") from exc
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Elasticsearch returned invalid JSON") from exc

    def _format_records(self, hits: Iterable[dict]) -> Iterable[dict]:
        for hit in hits:
            source = hit.get("_source") or {}
            timestamp = to_utc_iso(source.get("@timestamp"))
            record = {
                "source_type": "elastic",
                "es_url": self.es_url,
                "index": hit.get("_index"),
                "doc_id": hit.get("_id"),
                "time_created_utc": timestamp,
                "raw_source": source,
                "raw_hit": hit,
            }
            yield record

    def _write_records(self, records: Iterable[dict]) -> int:
        grouped: dict[Path, list[dict]] = defaultdict(list)
        for record in records:
            time_created = record.get("time_created_utc")
            when = _parse_timestamp(time_created)
            output_path = build_elastic_output_path(
                BASE_OUTPUT_DIR, str(record.get("index")), when
            )
            grouped[output_path].append(record)
        written = 0
        for path, batch in grouped.items():
            written += append_ndjson(path, batch)
        return written


def build_elastic_query(
    checkpoint: ElasticCheckpoint,
    *,
    max_events: int,
    start_ago_seconds: int,
    search_after: list[Any] | None = None,
) -> dict:
    if checkpoint.last_ts and checkpoint.last_id:
        filter_clause = {
            "bool": {
                "should": [
                    {"range": {"@timestamp": {"gt": checkpoint.last_ts}}},
                    {
                        "bool": {
                            "must": [
                                {"term": {"@timestamp": checkpoint.last_ts}},
                                {"range": {"_id": {"gt": checkpoint.last_id}}},
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        }
    else:
        filter_clause = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{start_ago_seconds}s",
                }
            }
        }
    query = {
        "size": max_events,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        "query": {"bool": {"filter": [filter_clause]}},
        "track_total_hits": False,
    }
    if search_after is not None:
        query["search_after"] = search_after
    return query


def tail_elastic_ndjson(base_dir: str | Path, limit: int) -> list[dict]:
    base_path = Path(base_dir) / "local"
    if not base_path.exists():
        return []
    files = sorted(
        base_path.rglob("events.ndjson"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    records: list[dict] = []
    remaining = limit
    for path in files:
        if remaining <= 0:
            break
        batch = tail_ndjson(path, remaining)
        records = batch + records
        remaining = limit - len(records)
    return records


def _parse_timestamp(timestamp: str | None) -> datetime:
    if not timestamp:
        return datetime.now(timezone.utc)
    if timestamp.endswith("Z"):
        timestamp = timestamp.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _build_basic_auth(username: str, password: str) -> str:
    token = f"{username}:{password}".encode("utf-8")
    return f"Basic {base64.b64encode(token).decode('ascii')}"


def log(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    print(f"[{timestamp}] [connector:elastic] {message}", flush=True)


def parse_args(argv: list[str]) -> ConnectorConfig:
    parser = argparse.ArgumentParser(description="Elastic SIEM connector")
    parser.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    parser.add_argument("--http-port", type=int, default=None)
    parser.add_argument("--indices", type=str, default=DEFAULT_INDICES)
    parser.add_argument("--start-ago-seconds", type=int, default=DEFAULT_START_AGO_SECONDS)
    parser.add_argument("--es-url", type=str, default=DEFAULT_ES_URL)
    parser.add_argument("--username", type=str, default=DEFAULT_USERNAME)
    parser.add_argument("--password", type=str, default=None)
    args = parser.parse_args(argv)
    password = args.password or _load_env_password()
    if not password:
        raise RuntimeError(
            "Missing Elasticsearch password. Provide --password or set ELASTIC_PASSWORD."
        )
    return ConnectorConfig(
        poll_seconds=args.poll_seconds,
        max_events=args.max_events,
        http_port=args.http_port,
        indices=args.indices,
        start_ago_seconds=args.start_ago_seconds,
        es_url=args.es_url,
        username=args.username,
        password=password,
    )


def _load_env_password() -> str | None:
    return os.environ.get("ELASTIC_PASSWORD")


def main(argv: list[str] | None = None) -> None:
    config = parse_args(argv or sys.argv[1:])
    connector = ElasticConnector(
        es_url=config.es_url,
        indices=config.indices,
        username=config.username,
        password=config.password,
        start_ago_seconds=config.start_ago_seconds,
    )
    connector.run_forever(
        poll_seconds=config.poll_seconds,
        max_events=config.max_events,
        http_port=config.http_port,
    )


if __name__ == "__main__":
    main()
