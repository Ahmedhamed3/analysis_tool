import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, Optional


@dataclass
class WindowsSecurityNormalized:
    event_id: int
    time_created: str
    target_user_name: Optional[str] = None
    target_domain_name: Optional[str] = None
    logon_type: Optional[str] = None
    ip_address: Optional[str] = None
    workstation_name: Optional[str] = None
    status: Optional[str] = None
    failure_reason: Optional[str] = None
    original_event: Optional[Dict[str, Any]] = None


def _to_iso8601_utc(ts: Optional[Any]) -> str:
    if not ts:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, dict):
        ts = ts.get("SystemTime") or ts.get("system_time") or ts.get("time")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, str):
        normalized = ts.replace("Z", "+00:00")
        if normalized.endswith("+0000"):
            normalized = f"{normalized[:-5]}+00:00"
        try:
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return -1


def _event_data_to_dict(event_data: Any) -> Dict[str, Any]:
    if isinstance(event_data, dict):
        data = event_data.get("Data")
        if isinstance(data, list):
            return _event_data_to_dict(data)
        return event_data
    if isinstance(event_data, list):
        result: Dict[str, Any] = {}
        for item in event_data:
            if not isinstance(item, dict):
                continue
            name = item.get("Name") or item.get("name")
            value = item.get("Value")
            if value is None:
                value = item.get("#text") or item.get("text")
            if name:
                result[str(name)] = value
        return result
    return {}


def _extract_event_data(ev: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(ev.get("EventData"), (dict, list)):
        return _event_data_to_dict(ev.get("EventData"))
    event_wrapper = ev.get("Event")
    if isinstance(event_wrapper, dict):
        event_data = event_wrapper.get("EventData")
        if isinstance(event_data, (dict, list)):
            return _event_data_to_dict(event_data)
    return {}


def _get_nested(ev: Dict[str, Any], *keys: str) -> Any:
    current: Any = ev
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _extract_fields(ev: Dict[str, Any]) -> WindowsSecurityNormalized:
    event_id = _safe_int(
        ev.get("EventID")
        or _get_nested(ev, "System", "EventID")
        or _get_nested(ev, "Event", "System", "EventID")
    )
    time_created = (
        ev.get("TimeCreated")
        or _get_nested(ev, "System", "TimeCreated")
        or _get_nested(ev, "Event", "System", "TimeCreated")
        or ev.get("Timestamp")
    )

    event_data = _extract_event_data(ev)

    target_user_name = event_data.get("TargetUserName") or ev.get("TargetUserName")
    target_domain_name = event_data.get("TargetDomainName") or ev.get("TargetDomainName")
    logon_type = event_data.get("LogonType") or ev.get("LogonType")
    ip_address = event_data.get("IpAddress") or event_data.get("Ip") or ev.get("IpAddress")
    workstation_name = event_data.get("WorkstationName") or ev.get("WorkstationName")
    status = event_data.get("Status") or ev.get("Status")
    failure_reason = event_data.get("FailureReason") or ev.get("FailureReason")

    return WindowsSecurityNormalized(
        event_id=event_id,
        time_created=_to_iso8601_utc(time_created),
        target_user_name=str(target_user_name) if target_user_name else None,
        target_domain_name=str(target_domain_name) if target_domain_name else None,
        logon_type=str(logon_type) if logon_type else None,
        ip_address=str(ip_address) if ip_address else None,
        workstation_name=str(workstation_name) if workstation_name else None,
        status=str(status) if status else None,
        failure_reason=str(failure_reason) if failure_reason else None,
        original_event=dict(ev) if isinstance(ev, dict) else None,
    )


def normalize_windows_security_event(ev: Dict[str, Any]) -> WindowsSecurityNormalized:
    return _extract_fields(ev)


def iter_windows_security_events_from_events(
    events: Iterable[Dict[str, Any]],
) -> Iterator[WindowsSecurityNormalized]:
    for ev in events:
        if isinstance(ev, dict):
            yield _extract_fields(ev)


def iter_windows_security_events(file_path: str) -> Iterator[WindowsSecurityNormalized]:
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        first = f.readline().strip()

    if not first:
        return

    if first.startswith("["):
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            data = json.load(f)
        if isinstance(data, list):
            for ev in data:
                if isinstance(ev, dict):
                    yield _extract_fields(ev)
        return

    if first.startswith("{"):
        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, dict):
                events = data.get("Events") or data.get("events")
                if isinstance(events, list):
                    for ev in events:
                        if isinstance(ev, dict):
                            yield _extract_fields(ev)
                    return
                yield normalize_windows_security_event(data)
                return
            if isinstance(data, list):
                for ev in data:
                    if isinstance(ev, dict):
                        yield _extract_fields(ev)
                return
        except Exception:
            pass

    def _gen() -> Iterator[WindowsSecurityNormalized]:
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if isinstance(ev, dict):
                    yield _extract_fields(ev)

    yield from _gen()
