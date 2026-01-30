from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Checkpoint:
    last_record_id: int = 0


@dataclass
class ElasticCheckpoint:
    last_ts: str | None = None
    last_id: str | None = None
    indices: str | list[str] | None = None


def load_checkpoint(path: str | Path) -> Checkpoint:
    path = Path(path)
    if not path.exists():
        return Checkpoint()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return Checkpoint()
    return Checkpoint(last_record_id=int(data.get("last_record_id", 0)))


def load_elastic_checkpoint(path: str | Path) -> ElasticCheckpoint:
    path = Path(path)
    if not path.exists():
        return ElasticCheckpoint()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return ElasticCheckpoint()
    last_ts = data.get("last_ts")
    last_id = data.get("last_id")
    indices = data.get("indices")
    return ElasticCheckpoint(
        last_ts=str(last_ts) if last_ts else None,
        last_id=str(last_id) if last_id else None,
        indices=indices,
    )


def save_checkpoint(path: str | Path, checkpoint: Checkpoint) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps({"last_record_id": checkpoint.last_record_id}))
    tmp_path.replace(path)


def save_elastic_checkpoint(path: str | Path, checkpoint: ElasticCheckpoint) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(
            {
                "last_ts": checkpoint.last_ts,
                "last_id": checkpoint.last_id,
                "indices": checkpoint.indices,
            }
        )
    )
    tmp_path.replace(path)
