import json
from pathlib import Path

def detect_sysmon_json(file_path: str) -> bool:
    """
    Detects Sysmon JSON (array or JSONL) by looking for typical keys.
    """
    p = Path(file_path)
    if p.suffix.lower() not in [".json", ".jsonl", ".ndjson", ".log", ".txt"]:
        return False

    # Read small sample
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        first = f.readline().strip()


    if not first:
        return False

    # JSON array
    if first.startswith("["):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                ev = data[0]
                return isinstance(ev, dict) and ("EventID" in ev or "EventId" in ev) and ("Image" in ev or "CommandLine" in ev)
        except Exception:
            return False

    # JSONL: first line is an object
    if first.startswith("{"):
        try:
            ev = json.loads(first)
            return isinstance(ev, dict) and ("EventID" in ev or "EventId" in ev) and ("Image" in ev or "CommandLine" in ev)
        except Exception:
            return False

    return False
