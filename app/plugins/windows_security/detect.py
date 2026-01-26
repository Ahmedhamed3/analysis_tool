import json
from pathlib import Path
from typing import Any, Iterable


TARGET_EVENT_IDS = {4624, 4625}


def detect_windows_security_json(file_path: str) -> bool:
    """
    Detects Windows Security Event JSON (array, JSONL, or wrapper dict).
    Requires EventID 4624/4625 with EventData and TimeCreated.
    """

    def _safe_int(value: Any) -> int:
        try:
            return int(value)
        except Exception:
            return -1

    def _get_nested(ev: dict, *keys: str) -> Any:
        current: Any = ev
        for key in keys:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    def _has_required_fields(ev: Any) -> bool:
        if not isinstance(ev, dict):
            return False
        event_id = _safe_int(
            ev.get("EventID")
            or _get_nested(ev, "System", "EventID")
            or _get_nested(ev, "Event", "System", "EventID")
        )
        if event_id not in TARGET_EVENT_IDS:
            return False
        event_data = (
            ev.get("EventData")
            or _get_nested(ev, "EventData", "Data")
            or _get_nested(ev, "Event", "EventData")
            or _get_nested(ev, "Event", "EventData", "Data")
        )
        if event_data is None:
            return False
        time_created = (
            ev.get("TimeCreated")
            or _get_nested(ev, "System", "TimeCreated")
            or _get_nested(ev, "Event", "System", "TimeCreated")
        )
        return time_created is not None

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
                    return any(_has_required_fields(ev) for ev in data)
                if isinstance(data, dict):
                    return any(_has_required_fields(ev) for ev in _events_from_wrapper(data))
                return False
            except Exception:
                return False

        if first.startswith("{"):
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    if _has_required_fields(data):
                        return True
                    return any(_has_required_fields(ev) for ev in _events_from_wrapper(data))
                if isinstance(data, list):
                    return any(_has_required_fields(ev) for ev in data)
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
                        if _has_required_fields(ev):
                            return True
                return False
            except Exception:
                return False

        return False
    except Exception:
        return False
