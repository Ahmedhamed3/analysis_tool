import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, Optional

@dataclass
class SysmonNormalized:
    ts: str
    utc_time: Optional[str]
    host: Optional[str]
    user: Optional[str]
    event_id: int
    pid: Optional[int]
    image: Optional[str]
    cmd: Optional[str]
    parent_pid: Optional[int]
    parent_image: Optional[str]
    parent_cmd: Optional[str]
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    process_guid: Optional[str] = None
    target_filename: Optional[str] = None
    creation_utctime: Optional[str] = None
    rule_name: Optional[str] = None
    query_name: Optional[str] = None
    query_results: Optional[str] = None
    query_status: Optional[str] = None
    event_data: Optional[Dict[str, Any]] = None

def _to_iso8601_z(ts: str) -> str:
    """
    Normalize timestamps to ISO8601 with Z.
    Sysmon JSON often uses 'UtcTime' like '2024-01-01 00:00:00.000'
    or ISO-like forms.
    """
    if not ts:
        # fallback to now
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Try common Sysmon format: "YYYY-MM-DD HH:MM:SS.sss"
    try:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        pass

    # Try ISO
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        # last resort
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _safe_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(x)
    except Exception:
        return None

def _extract_fields(ev: Dict[str, Any]) -> SysmonNormalized:
    # Sysmon exports vary. We handle common keys.
    event_id = _safe_int(ev.get("EventID") or ev.get("EventId") or ev.get("event_id")) or -1

    event_data = ev.get("EventData") if isinstance(ev.get("EventData"), dict) else None
    utc_time = ev.get("UtcTime") or (event_data.get("UtcTime") if event_data else None)

    ts = utc_time or ev.get("TimeCreated") or ev.get("time") or ev.get("Timestamp") or ""

    host = ev.get("Computer") or ev.get("Host") or ev.get("hostname")
    user = ev.get("User") or ev.get("UserName") or ev.get("user")

    pid = _safe_int(ev.get("ProcessId") or ev.get("ProcessID") or ev.get("pid"))
    image = ev.get("Image") or ev.get("ProcessImage") or ev.get("image")
    cmd = ev.get("CommandLine") or ev.get("cmd") or ev.get("CmdLine")

    parent_pid = _safe_int(ev.get("ParentProcessId") or ev.get("ParentProcessID"))
    parent_image = ev.get("ParentImage") or ev.get("ParentProcessImage")
    parent_cmd = ev.get("ParentCommandLine") or ev.get("ParentCmdLine")

    src_ip = ev.get("SourceIp") or ev.get("SourceIP") or ev.get("src_ip")
    src_port = _safe_int(ev.get("SourcePort") or ev.get("SourcePortNumber") or ev.get("src_port"))
    dst_ip = ev.get("DestinationIp") or ev.get("DestinationIP") or ev.get("dst_ip")
    dst_port = _safe_int(ev.get("DestinationPort") or ev.get("DestinationPortNumber") or ev.get("dst_port"))
    protocol = ev.get("Protocol") or ev.get("TransportProtocol") or ev.get("protocol")

    process_guid = ev.get("ProcessGuid") or ev.get("ProcessGUID")
    target_filename = ev.get("TargetFilename") or ev.get("TargetFileName")
    creation_utctime = ev.get("CreationUtcTime") or ev.get("CreationTime")
    rule_name = ev.get("RuleName") or ev.get("Rule")
    query_name = ev.get("QueryName") or (event_data.get("QueryName") if event_data else None)
    query_results = ev.get("QueryResults") or (event_data.get("QueryResults") if event_data else None)
    query_status = ev.get("QueryStatus") or (event_data.get("QueryStatus") if event_data else None)

    return SysmonNormalized(
        ts=_to_iso8601_z(str(ts)),
        utc_time=str(utc_time) if utc_time else None,
        host=str(host) if host else None,
        user=str(user) if user else None,
        event_id=event_id,
        pid=pid,
        image=str(image) if image else None,
        cmd=str(cmd) if cmd else None,
        parent_pid=parent_pid,
        parent_image=str(parent_image) if parent_image else None,
        parent_cmd=str(parent_cmd) if parent_cmd else None,
        src_ip=str(src_ip) if src_ip else None,
        src_port=src_port,
        dst_ip=str(dst_ip) if dst_ip else None,
        dst_port=dst_port,
        protocol=str(protocol) if protocol else None,
        process_guid=str(process_guid) if process_guid else None,
        target_filename=str(target_filename) if target_filename else None,
        creation_utctime=str(creation_utctime) if creation_utctime else None,
        rule_name=str(rule_name) if rule_name else None,
        query_name=str(query_name) if query_name else None,
        query_results=str(query_results) if query_results else None,
        query_status=str(query_status) if query_status else None,
        event_data=dict(ev) if isinstance(ev, dict) else None,
    )

def iter_sysmon_events(file_path: str) -> Iterator[SysmonNormalized]:
    """
    Supports:
      - JSON array file
      - JSONL (one object per line)
      - Wrapper dict {"Events": [...]} (or "events")
    """
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        first = f.readline().strip()

    if not first:
        return

    # JSON array
    if first.startswith("["):
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            data = json.load(f)
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
                if isinstance(data, dict):
                    yield _extract_fields(data)
                    return
            if isinstance(data, list):
                for ev in data:
                    if isinstance(ev, dict):
                        yield _extract_fields(ev)
                return
        except Exception:
            pass

    # JSONL
    def _gen() -> Iterator[SysmonNormalized]:
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if not line.startswith("{"):
                    continue
                try:
                    ev = json.loads(line)
                    if isinstance(ev, dict):
                        yield _extract_fields(ev)
                except Exception:
                    continue

    yield from _gen()
