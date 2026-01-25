import json
from pathlib import Path
from typing import Any, Iterable

def detect_sysmon_json(file_path: str) -> bool:
    """
    Detects Sysmon JSON (array or JSONL) by looking for typical keys.
    """
    def _has_event_id(ev: Any) -> bool:
        return isinstance(ev, dict) and any(key in ev for key in ("EventID", "EventId", "event_id"))

    def _events_from_wrapper(obj: Any) -> Iterable[Any]:
        if isinstance(obj, dict):
            events = obj.get("Events") or obj.get("events")
            if isinstance(events, list):
                return events
        return []

    try:
        p = Path(file_path)
        if p.suffix.lower() not in [".json", ".jsonl", ".ndjson", ".log", ".txt"]:
            return False

        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            first = ""
            for line in f:
                line = line.strip()
                if line:
                    first = line
                    break

        if not first:
            return False

        if first.startswith("["):
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return any(_has_event_id(ev) for ev in data)
                if isinstance(data, dict):
                    return any(_has_event_id(ev) for ev in _events_from_wrapper(data))
                return False
            except Exception:
                return False

        if first.startswith("{"):
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    if _has_event_id(data):
                        return True
                    return any(_has_event_id(ev) for ev in _events_from_wrapper(data))
                if isinstance(data, list):
                    return any(_has_event_id(ev) for ev in data)
                return False
            except Exception:
                pass

            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or not line.startswith("{"):
                            continue
                        try:
                            ev = json.loads(line)
                        except Exception:
                            continue
                        if _has_event_id(ev):
                            return True
                return False
            except Exception:
                return False

        return False
    except Exception:
        return False
