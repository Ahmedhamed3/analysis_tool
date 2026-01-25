import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, Optional

@dataclass
class SysmonNormalized:
    ts: str
    host: Optional[str]
    user: Optional[str]
    event_id: int
    pid: Optional[int]
    image: Optional[str]
    cmd: Optional[str]
    parent_pid: Optional[int]
    parent_image: Optional[str]
    parent_cmd: Optional[str]

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

    ts = (
        ev.get("UtcTime")
        or ev.get("TimeCreated")
        or ev.get("time")
        or ev.get("Timestamp")
        or ""
    )

    host = ev.get("Computer") or ev.get("Host") or ev.get("hostname")
    user = ev.get("User") or ev.get("UserName") or ev.get("user")

    pid = _safe_int(ev.get("ProcessId") or ev.get("ProcessID") or ev.get("pid"))
    image = ev.get("Image") or ev.get("ProcessImage") or ev.get("image")
    cmd = ev.get("CommandLine") or ev.get("cmd") or ev.get("CmdLine")

    parent_pid = _safe_int(ev.get("ParentProcessId") or ev.get("ParentProcessID"))
    parent_image = ev.get("ParentImage") or ev.get("ParentProcessImage")
    parent_cmd = ev.get("ParentCommandLine") or ev.get("ParentCmdLine")

    return SysmonNormalized(
        ts=_to_iso8601_z(str(ts)),
        host=str(host) if host else None,
        user=str(user) if user else None,
        event_id=event_id,
        pid=pid,
        image=str(image) if image else None,
        cmd=str(cmd) if cmd else None,
        parent_pid=parent_pid,
        parent_image=str(parent_image) if parent_image else None,
        parent_cmd=str(parent_cmd) if parent_cmd else None,
    )

def iter_sysmon_events(file_path: str) -> Iterator[SysmonNormalized]:
    """
    Supports:
      - JSON array file
      - JSONL (one object per line)
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
