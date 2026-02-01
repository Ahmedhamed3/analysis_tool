from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from pathlib import Path

from app.normalizers.sysmon_to_ocsf import taxonomy
from app.normalizers.sysmon_to_ocsf.sysmon_xml import parse_event_data, parse_system_time


@dataclass(frozen=True)
class MappingContext:
    ocsf_version: str


def map_raw_event(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_id = _get_event_id(raw_event)
    if event_id == 1:
        return _map_process_activity(raw_event, context)
    if event_id == 3:
        return _map_network_activity(raw_event, context)
    if event_id == 11:
        return _map_file_activity(raw_event, context)
    return None


def _get_event_id(raw_event: Dict[str, Any]) -> Optional[int]:
    ids = raw_event.get("ids") or {}
    event_id = ids.get("event_id")
    if isinstance(event_id, int):
        return event_id
    if isinstance(event_id, str) and event_id.isdigit():
        return int(event_id)
    return None


def _get_event_time(raw_event: Dict[str, Any]) -> Optional[str]:
    event = raw_event.get("event") or {}
    time_info = event.get("time") or {}
    time_value = time_info.get("created_utc") or time_info.get("observed_utc")
    if time_value:
        return time_value
    xml = _get_raw_xml(raw_event)
    return parse_system_time(xml) if xml else None


def _get_raw_xml(raw_event: Dict[str, Any]) -> str:
    raw = raw_event.get("raw") or {}
    xml = raw.get("xml") or raw.get("data") or ""
    return xml


def _get_event_data(raw_event: Dict[str, Any]) -> Dict[str, str]:
    parsed = raw_event.get("parsed") or {}
    event_data = parsed.get("event_data")
    if isinstance(event_data, dict):
        return {str(k): "" if v is None else str(v) for k, v in event_data.items()}
    xml = _get_raw_xml(raw_event)
    if not xml:
        return {}
    return parse_event_data(xml)


def _split_domain_user(value: Optional[str]) -> Dict[str, str]:
    if not value:
        return {}
    if "\\" in value:
        domain, name = value.split("\\", 1)
        return {"name": name, "domain": domain}
    return {"name": value}


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _base_event(raw_event: Dict[str, Any], context: MappingContext, *, category_uid: int, class_uid: int, activity_id: int) -> Dict[str, Any]:
    ids = raw_event.get("ids") or {}
    source = raw_event.get("source") or {}
    host = raw_event.get("host") or {}
    time_value = _get_event_time(raw_event)
    record_id = ids.get("record_id")
    dedupe_hash = ids.get("dedupe_hash")
    event_code = ids.get("event_id")
    channel = source.get("channel")
    product_name = source.get("product") or "sysmon"
    product = {
        "name": product_name,
        "vendor_name": source.get("vendor"),
        "version": source.get("version"),
    }
    product = {key: value for key, value in product.items() if value}
    metadata = {
        "product": product,
        "version": context.ocsf_version,
        "event_code": str(event_code) if event_code is not None else None,
        "original_event_uid": str(record_id) if record_id is not None else None,
        "uid": dedupe_hash,
        "log_name": channel,
        "log_source": source.get("type"),
        "log_format": "xml",
        "original_time": time_value,
    }
    metadata = {key: value for key, value in metadata.items() if value is not None}
    device = {"type_id": taxonomy.DEVICE_TYPE_UNKNOWN_ID}
    if host.get("hostname"):
        device["hostname"] = host.get("hostname")
    base = {
        "activity_id": activity_id,
        "category_uid": category_uid,
        "class_uid": class_uid,
        "type_uid": taxonomy.to_type_uid(class_uid, activity_id),
        "time": time_value,
        "severity_id": _map_severity_id(raw_event.get("severity")),
        "metadata": metadata,
        "device": device,
    }
    return base


def _map_process_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)
    process = _build_process_entity(
        pid=_to_int(event_data.get("ProcessId")),
        uid=event_data.get("ProcessGuid"),
        path=event_data.get("Image"),
        cmd_line=event_data.get("CommandLine"),
        created_time=_normalize_sysmon_time(event_data.get("UtcTime")),
    )
    parent = _build_process_entity(
        pid=_to_int(event_data.get("ParentProcessId")),
        uid=event_data.get("ParentProcessGuid"),
        path=event_data.get("ParentImage"),
        cmd_line=event_data.get("ParentCommandLine"),
    )
    if parent:
        process = {**process, "parent_process": parent} if process else {"parent_process": parent}
    actor = _build_actor(
        process=parent or None,
        user=_split_domain_user(event_data.get("User")),
    )
    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.PROCESS_ACTIVITY_LAUNCH_ID,
    )
    base["actor"] = actor
    base["process"] = process
    return base


def _map_network_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)
    process = _build_process_entity(
        pid=_to_int(event_data.get("ProcessId")),
        uid=event_data.get("ProcessGuid"),
        path=event_data.get("Image"),
    )
    actor = _build_actor(process=process, user=_split_domain_user(event_data.get("User")))
    src_endpoint = _build_network_endpoint(
        ip=event_data.get("SourceIp"),
        port=_to_int(event_data.get("SourcePort")),
    )
    dst_endpoint = _build_network_endpoint(
        ip=event_data.get("DestinationIp"),
        port=_to_int(event_data.get("DestinationPort")),
    )
    class_uid = taxonomy.to_class_uid(taxonomy.NETWORK_CATEGORY_UID, taxonomy.NETWORK_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.NETWORK_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.NETWORK_ACTIVITY_OPEN_ID,
    )
    base["actor"] = actor
    base["src_endpoint"] = src_endpoint
    base["dst_endpoint"] = dst_endpoint
    return base


def _map_file_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)
    process = _build_process_entity(
        pid=_to_int(event_data.get("ProcessId")),
        uid=event_data.get("ProcessGuid"),
        path=event_data.get("Image"),
        cmd_line=event_data.get("CommandLine"),
    )
    actor = _build_actor(process=process, user=_split_domain_user(event_data.get("User")))
    file_obj = _build_file(path=event_data.get("TargetFilename"))
    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.FILE_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.FILE_ACTIVITY_CREATE_ID,
    )
    base["actor"] = actor
    base["file"] = file_obj
    return base


def _build_actor(process: Optional[Dict[str, Any]], user: Dict[str, str]) -> Dict[str, Any]:
    actor: Dict[str, Any] = {}
    if process:
        actor["process"] = process
    if user:
        actor["user"] = user
    return actor


def _build_process_entity(
    *,
    pid: Optional[int],
    uid: Optional[str],
    path: Optional[str],
    cmd_line: Optional[str] = None,
    created_time: Optional[str] = None,
) -> Dict[str, Any]:
    entity: Dict[str, Any] = {}
    if pid is not None:
        entity["pid"] = pid
    if uid:
        entity["uid"] = uid
    if path:
        entity["path"] = path
        entity["name"] = Path(path).name
    if cmd_line:
        entity["cmd_line"] = cmd_line
    if created_time:
        entity["created_time"] = created_time
    return entity


def _normalize_sysmon_time(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip()
    if "T" in value and value.endswith("Z"):
        return value
    if " " in value:
        return f"{value.replace(' ', 'T')}Z"
    return value


def _build_network_endpoint(*, ip: Optional[str], port: Optional[int]) -> Dict[str, Any]:
    endpoint: Dict[str, Any] = {}
    if ip:
        endpoint["ip"] = ip
    if port is not None:
        endpoint["port"] = port
    return endpoint


def _build_file(*, path: Optional[str]) -> Dict[str, Any]:
    file_obj: Dict[str, Any] = {"type_id": taxonomy.FILE_TYPE_UNKNOWN_ID}
    if path:
        file_obj["path"] = path
        file_obj["name"] = Path(path).name
    return file_obj


def _map_severity_id(value: Any) -> int:
    if not value:
        return 1
    if isinstance(value, int):
        return value
    text = str(value).lower()
    if text in {"information", "informational"}:
        return 1
    if text in {"low"}:
        return 2
    if text in {"medium"}:
        return 3
    if text in {"high"}:
        return 4
    if text in {"critical"}:
        return 5
    return 0
