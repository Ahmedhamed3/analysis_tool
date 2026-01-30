from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any


def local_timezone_name() -> str:
    offset = datetime.now().astimezone().strftime("%z") or "+0000"
    return f"UTC{offset}"


def map_security_severity(level: int | None) -> str:
    if level == 1:
        return "critical"
    if level == 2:
        return "high"
    if level == 3:
        return "medium"
    if level == 4:
        return "low"
    return "information"


def compute_dedupe_hash(
    source_type: str,
    hostname: str,
    record_id: int | None,
    event_id: int | None,
    observed_utc: str,
    provider: str | None,
    computer: str | None,
    channel: str | None,
) -> str:
    payload = "|".join(
        [
            source_type,
            hostname,
            str(record_id or ""),
            str(event_id or ""),
            observed_utc,
            provider or "",
            computer or "",
            channel or "",
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def build_security_raw_event(
    raw_record: dict[str, Any],
    observed_utc: str,
    hostname: str,
    timezone_name: str,
) -> dict[str, Any]:
    record_id = raw_record.get("record_id")
    event_id = raw_record.get("event_id")
    created_utc = raw_record.get("time_created_utc")
    provider = raw_record.get("provider")
    channel = raw_record.get("channel") or "Security"
    severity = map_security_severity(raw_record.get("level"))
    dedupe_hash = compute_dedupe_hash(
        "security",
        hostname,
        record_id,
        event_id,
        observed_utc,
        provider,
        raw_record.get("computer"),
        channel,
    )
    return {
        "envelope_version": "1.0",
        "source": {
            "type": "security",
            "vendor": "microsoft",
            "product": "windows-security-auditing",
            "channel": "Security",
            "collector": {
                "name": "security-connector",
                "instance_id": f"{hostname}:security",
                "host": hostname,
            },
        },
        "event": {
            "time": {
                "observed_utc": observed_utc,
                "created_utc": created_utc,
            }
        },
        "ids": {
            "record_id": record_id,
            "event_id": event_id,
            "activity_id": raw_record.get("activity_id"),
            "correlation_id": raw_record.get("correlation_id"),
            "dedupe_hash": dedupe_hash,
        },
        "host": {
            "hostname": hostname,
            "os": "windows",
            "timezone": timezone_name,
        },
        "severity": severity,
        "tags": ["live", "security"],
        "raw": {
            "format": "json",
            "data": raw_record,
            "rendered_message": raw_record.get("rendered_message"),
            "xml": raw_record.get("raw_xml"),
        },
    }
