import json
from pathlib import Path
from typing import Any


def detect_suricata_eve_json(file_path: str) -> bool:
    """
    Detect Suricata eve.json JSONL (one object per line).

    Returns True if at least one of the first few lines parses as JSON and
    contains an "event_type" key.
    """
    try:
        path = Path(file_path)
        if path.suffix.lower() not in [".json", ".jsonl", ".ndjson", ".log", ".txt"]:
            return False

        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            parsed = 0
            for line in f:
                if parsed >= 3:
                    break
                line = line.strip()
                if not line:
                    continue
                if not line.startswith("{"):
                    return False
                try:
                    ev: Any = json.loads(line)
                except Exception:
                    continue
                parsed += 1
                if isinstance(ev, dict) and "event_type" in ev:
                    return True
        return False
    except Exception:
        return False
