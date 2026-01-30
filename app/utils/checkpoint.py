from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Checkpoint:
    last_record_id: int = 0


def load_checkpoint(path: str | Path) -> Checkpoint:
    path = Path(path)
    if not path.exists():
        return Checkpoint()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return Checkpoint()
    return Checkpoint(last_record_id=int(data.get("last_record_id", 0)))


def save_checkpoint(path: str | Path, checkpoint: Checkpoint) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps({"last_record_id": checkpoint.last_record_id}))
    tmp_path.replace(path)
