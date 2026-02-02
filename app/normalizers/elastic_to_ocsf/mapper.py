from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from app.normalizers.elastic_to_ocsf import taxonomy
from app.utils.timeutil import to_utc_iso


@dataclass(frozen=True)
class MappingContext:
    ocsf_version: str


def map_raw_event(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if _is_authentication_event(source):
        return _map_authentication_activity(raw_event, context)
    if _is_process_event(source):
        return _map_process_activity(raw_event, context)
    if _is_network_event(source):
        return _map_network_activity(raw_event, context)
    return _map_generic_activity(raw_event, context)


def mapping_attempted(raw_event: Dict[str, Any]) -> bool:
    return True


def missing_required_fields(raw_event: Dict[str, Any]) -> list[str]:
    source = _extract_source(raw_event)
    if _is_authentication_event(source):
        return _missing_required_authentication_fields(raw_event, source)
    if _is_process_event(source):
        return _missing_required_process_fields(raw_event, source)
    if _is_network_event(source):
        return _missing_required_network_fields(raw_event, source)
    return []


def _extract_hit(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    raw = raw_event.get("raw") or {}
    data = raw.get("data")
    return data if isinstance(data, dict) else {}


def _extract_source(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    hit = _extract_hit(raw_event)
    source = hit.get("_source")
    return source if isinstance(source, dict) else {}


def _get_event_block(source: Dict[str, Any]) -> Dict[str, Any]:
    event = source.get("event")
    return event if isinstance(event, dict) else {}


def _get_network_block(source: Dict[str, Any]) -> Dict[str, Any]:
    network = source.get("network")
    return network if isinstance(network, dict) else {}


def _get_user_block(source: Dict[str, Any]) -> Dict[str, Any]:
    user = source.get("user")
    return user if isinstance(user, dict) else {}


def _get_process_block(source: Dict[str, Any]) -> Dict[str, Any]:
    process = source.get("process")
    return process if isinstance(process, dict) else {}


def _get_host_block(source: Dict[str, Any]) -> Dict[str, Any]:
    host = source.get("host")
    return host if isinstance(host, dict) else {}


def _coerce_str(value: Any) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _coerce_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in (str(part).strip() for part in value) if item]
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    return []


def _contains_any(values: Iterable[str], options: Iterable[str]) -> bool:
    lowered = {value.lower() for value in values}
    return any(option.lower() in lowered for option in options)


def _is_authentication_event(source: Dict[str, Any]) -> bool:
    event = _get_event_block(source)
    categories = _coerce_list(event.get("category"))
    actions = [_coerce_str(event.get("action"))] + _coerce_list(event.get("type"))
    actions = [action for action in actions if action]
    if _contains_any(categories, ["authentication", "iam"]):
        return True
    return _contains_any(actions, ["login", "logon", "logout", "logoff", "authentication"])


def _is_process_event(source: Dict[str, Any]) -> bool:
    event = _get_event_block(source)
    categories = _coerce_list(event.get("category"))
    if _contains_any(categories, ["process"]):
        return True
    process = _get_process_block(source)
    for key in ("pid", "name", "executable", "entity_id"):
        if process.get(key) is not None:
            return True
    parent = process.get("parent")
    return isinstance(parent, dict) and any(parent.get(key) is not None for key in ("pid", "name", "executable"))


def _is_network_event(source: Dict[str, Any]) -> bool:
    event = _get_event_block(source)
    categories = _coerce_list(event.get("category"))
    if _contains_any(categories, ["network"]):
        return True
    if _extract_ip(source, "source") or _extract_ip(source, "destination"):
        network = _get_network_block(source)
        return bool(_coerce_str(network.get("transport")) or _coerce_str(network.get("protocol")))
    return False


def _extract_event_time(raw_event: Dict[str, Any], source: Dict[str, Any]) -> Optional[str]:
    for key_path in (
        ("@timestamp",),
        ("event", "created"),
        ("event", "ingested"),
        ("timestamp",),
    ):
        value = _extract_nested_value(source, key_path)
        if isinstance(value, str) and value:
            return to_utc_iso(value) or value
    event = raw_event.get("event") or {}
    time_block = event.get("time") or {}
    observed = time_block.get("observed_utc")
    if isinstance(observed, str) and observed:
        return observed
    return None


def _extract_nested_value(source: Dict[str, Any], path: Iterable[str]) -> Any:
    cursor: Any = source
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor


def _extract_event_code(source: Dict[str, Any], hit: Dict[str, Any]) -> Optional[str]:
    event = _get_event_block(source)
    for key in ("code", "action", "id"):
        value = _coerce_str(event.get(key))
        if value:
            return value
    dataset = _coerce_str(event.get("dataset"))
    if dataset:
        return dataset
    return _coerce_str(hit.get("_index"))


def _extract_ip(source: Dict[str, Any], key: str) -> Optional[str]:
    block = source.get(key)
    if not isinstance(block, dict):
        return None
    return _coerce_str(block.get("ip"))


def _extract_port(source: Dict[str, Any], key: str) -> Optional[int]:
    block = source.get(key)
    if not isinstance(block, dict):
        return None
    value = block.get("port")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _extract_hostname(source: Dict[str, Any], key: str) -> Optional[str]:
    block = source.get(key)
    if not isinstance(block, dict):
        return None
    return _coerce_str(block.get("domain")) or _coerce_str(block.get("hostname")) or _coerce_str(block.get("name"))


def _extract_host_name(source: Dict[str, Any]) -> Optional[str]:
    host = _get_host_block(source)
    return _coerce_str(host.get("name")) or _coerce_str(host.get("hostname"))


def _extract_host_ip(source: Dict[str, Any]) -> Optional[str]:
    host = _get_host_block(source)
    return _coerce_str(host.get("ip"))


def _extract_user(source: Dict[str, Any]) -> Dict[str, Any]:
    user = _get_user_block(source)
    user_name = _coerce_str(user.get("name")) or _coerce_str(user.get("username")) or _coerce_str(user.get("email"))
    user_id = _coerce_str(user.get("id")) or _coerce_str(user.get("uid"))
    domain = _coerce_str(user.get("domain"))
    payload: Dict[str, Any] = {}
    if user_name:
        payload["name"] = user_name
    if user_id:
        payload["uid"] = user_id
    if domain:
        payload["domain"] = domain
    return payload


def _extract_process(source: Dict[str, Any]) -> Dict[str, Any]:
    process = _get_process_block(source)
    pid = process.get("pid")
    if isinstance(pid, str) and pid.isdigit():
        pid = int(pid)
    entity_id = _coerce_str(process.get("entity_id"))
    path = _coerce_str(process.get("executable"))
    name = _coerce_str(process.get("name"))
    if not name and path:
        name = Path(path).name
    cmd_line = _coerce_str(process.get("command_line"))
    payload: Dict[str, Any] = {}
    if pid is not None:
        payload["pid"] = pid
    if entity_id:
        payload["uid"] = entity_id
    if path:
        payload["path"] = path
    if name:
        payload["name"] = name
    if cmd_line:
        payload["cmd_line"] = cmd_line
    parent = process.get("parent")
    if isinstance(parent, dict):
        parent_pid = parent.get("pid")
        if isinstance(parent_pid, str) and parent_pid.isdigit():
            parent_pid = int(parent_pid)
        parent_entity = _coerce_str(parent.get("entity_id"))
        parent_path = _coerce_str(parent.get("executable"))
        parent_name = _coerce_str(parent.get("name"))
        if not parent_name and parent_path:
            parent_name = Path(parent_path).name
        parent_payload: Dict[str, Any] = {}
        if parent_pid is not None:
            parent_payload["pid"] = parent_pid
        if parent_entity:
            parent_payload["uid"] = parent_entity
        if parent_path:
            parent_payload["path"] = parent_path
        if parent_name:
            parent_payload["name"] = parent_name
        if parent_payload:
            payload["parent_process"] = parent_payload
    return payload


def _extract_network_protocol(source: Dict[str, Any]) -> Optional[str]:
    network = _get_network_block(source)
    protocol = _coerce_str(network.get("transport")) or _coerce_str(network.get("protocol"))
    return protocol.lower() if protocol else None


def _extract_source_endpoint(source: Dict[str, Any]) -> Dict[str, Any]:
    endpoint: Dict[str, Any] = {}
    ip = _extract_ip(source, "source")
    port = _extract_port(source, "source")
    hostname = _extract_hostname(source, "source")
    if ip:
        endpoint["ip"] = ip
    if port is not None:
        endpoint["port"] = port
    if hostname:
        endpoint["hostname"] = hostname
    return endpoint


def _extract_destination_endpoint(source: Dict[str, Any]) -> Dict[str, Any]:
    endpoint: Dict[str, Any] = {}
    ip = _extract_ip(source, "destination")
    port = _extract_port(source, "destination")
    hostname = _extract_hostname(source, "destination")
    if ip:
        endpoint["ip"] = ip
    if port is not None:
        endpoint["port"] = port
    if hostname:
        endpoint["hostname"] = hostname
    return endpoint


def _missing_required_authentication_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    user = _extract_user(source)
    if not user:
        missing.append("user")
    service_name = _coerce_str(_extract_nested_value(source, ("service", "name")))
    dst_endpoint = _extract_destination_endpoint(source)
    if not service_name and not dst_endpoint:
        host_name = _extract_host_name(source)
        host_ip = _extract_host_ip(source)
        if not host_name and not host_ip:
            missing.append("dst_endpoint/service")
    return missing


def _missing_required_process_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    process = _extract_process(source)
    if not process or not (process.get("pid") or process.get("uid")):
        missing.append("process.pid/process.uid")
    if not _extract_host_name(source) and not _extract_host_ip(source):
        missing.append("host.name")
    if _process_activity_id(source) is None:
        missing.append("event.action")
    return missing


def _missing_required_network_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    protocol = _extract_network_protocol(source)
    if not protocol:
        missing.append("network.transport")
    src_ip = _extract_ip(source, "source")
    if not src_ip:
        missing.append("source.ip")
    dst_ip = _extract_ip(source, "destination")
    if not dst_ip:
        missing.append("destination.ip")
    src_port = _extract_port(source, "source")
    if src_port is None:
        missing.append("source.port")
    dst_port = _extract_port(source, "destination")
    if dst_port is None:
        missing.append("destination.port")
    if _network_activity_id(source) is None:
        missing.append("event.action")
    return missing


def _map_generic_activity(raw_event: Dict[str, Any], context: MappingContext) -> Dict[str, Any]:
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.OTHER_CATEGORY_UID,
        class_uid=taxonomy.BASE_EVENT_CLASS_UID,
        activity_id=0,
    )
    return base


def _map_authentication_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    missing_fields = _missing_required_authentication_fields(raw_event, source)
    if missing_fields:
        return None
    class_uid = taxonomy.to_class_uid(taxonomy.IAM_CATEGORY_UID, taxonomy.AUTHENTICATION_ACTIVITY_UID)
    activity_id = _authentication_activity_id(source)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.IAM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
    )
    user = _extract_user(source)
    if user:
        base["user"] = user
    src_endpoint = _extract_source_endpoint(source)
    if src_endpoint:
        base["src_endpoint"] = src_endpoint
    dst_endpoint = _extract_destination_endpoint(source)
    if not dst_endpoint:
        host_name = _extract_host_name(source)
        host_ip = _extract_host_ip(source)
        if host_name or host_ip:
            dst_endpoint = {k: v for k, v in {"hostname": host_name, "ip": host_ip}.items() if v}
    if dst_endpoint:
        base["dst_endpoint"] = dst_endpoint
    service_name = _coerce_str(_extract_nested_value(source, ("service", "name")))
    if service_name:
        base["service"] = {"name": service_name}
    status = _coerce_str(_extract_nested_value(source, ("event", "outcome")))
    if status:
        base["status"] = status
    return base


def _map_process_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    missing_fields = _missing_required_process_fields(raw_event, source)
    if missing_fields:
        return None
    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    activity_id = _process_activity_id(source)
    if activity_id is None:
        return None
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
    )
    process = _extract_process(source)
    if process:
        base["process"] = process
    actor = _build_actor(source, process.get("parent_process") if process else None, process)
    if actor:
        base["actor"] = actor
    return base


def _map_network_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    missing_fields = _missing_required_network_fields(raw_event, source)
    if missing_fields:
        return None
    class_uid = taxonomy.to_class_uid(taxonomy.NETWORK_CATEGORY_UID, taxonomy.NETWORK_ACTIVITY_UID)
    activity_id = _network_activity_id(source)
    if activity_id is None:
        return None
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.NETWORK_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
    )
    protocol = _extract_network_protocol(source)
    base["connection_info"] = {
        "direction_id": taxonomy.NETWORK_DIRECTION_UNKNOWN_ID,
        "protocol_name": protocol,
    }
    src_endpoint = _extract_source_endpoint(source)
    if src_endpoint:
        base["src_endpoint"] = src_endpoint
    dst_endpoint = _extract_destination_endpoint(source)
    if dst_endpoint:
        base["dst_endpoint"] = dst_endpoint
    return base


def _authentication_activity_id(source: Dict[str, Any]) -> int:
    action = _event_action_text(source)
    if action and any(term in action for term in ("logoff", "logout")):
        return taxonomy.AUTHENTICATION_LOGOFF_ID
    return taxonomy.AUTHENTICATION_LOGON_ID


def _process_activity_id(source: Dict[str, Any]) -> Optional[int]:
    action = _event_action_text(source)
    if not action:
        return None
    if any(term in action for term in ("terminate", "terminated", "stop", "end", "kill", "exit")):
        return taxonomy.PROCESS_ACTIVITY_TERMINATE_ID
    if any(term in action for term in ("start", "launch", "create", "exec", "spawn", "fork")):
        return taxonomy.PROCESS_ACTIVITY_LAUNCH_ID
    return None


def _network_activity_id(source: Dict[str, Any]) -> Optional[int]:
    action = _event_action_text(source)
    if not action:
        return None
    if any(term in action for term in ("close", "end", "stop", "reset", "terminate")):
        return taxonomy.NETWORK_ACTIVITY_CLOSE_ID
    if "traffic" in action:
        return taxonomy.NETWORK_ACTIVITY_TRAFFIC_ID
    if any(term in action for term in ("open", "start", "connect", "connection", "allow", "accept")):
        return taxonomy.NETWORK_ACTIVITY_OPEN_ID
    return None


def _event_action_text(source: Dict[str, Any]) -> str:
    event = _get_event_block(source)
    candidates = []
    action = _coerce_str(event.get("action"))
    if action:
        candidates.append(action)
    candidates.extend(_coerce_list(event.get("type")))
    return " ".join(candidates).lower()


def _build_actor(
    source: Dict[str, Any],
    parent_process: Optional[Dict[str, Any]],
    fallback_process: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    actor: Dict[str, Any] = {}
    if parent_process:
        actor["process"] = parent_process
    elif fallback_process:
        actor["process"] = fallback_process
    user = _extract_user(source)
    if user:
        actor["user"] = user
    return actor


def _base_event(
    raw_event: Dict[str, Any],
    context: MappingContext,
    *,
    category_uid: int,
    class_uid: int,
    activity_id: int,
) -> Dict[str, Any]:
    hit = _extract_hit(raw_event)
    source = _extract_source(raw_event)
    time_value = _extract_event_time(raw_event, source)
    ids = raw_event.get("ids") or {}
    dedupe_hash = ids.get("dedupe_hash")
    event_code = _extract_event_code(source, hit)
    index_name = hit.get("_index")
    doc_id = hit.get("_id")
    metadata = {
        "product": {
            "name": "elastic",
            "vendor_name": "elastic",
        },
        "version": context.ocsf_version,
        "event_code": event_code,
        "original_event_uid": str(doc_id) if doc_id is not None else None,
        "uid": dedupe_hash,
        "log_name": str(index_name) if index_name is not None else None,
        "log_source": "elastic",
        "log_format": "json",
        "original_time": time_value,
    }
    metadata = {key: value for key, value in metadata.items() if value is not None}
    device: Dict[str, Any] = {"type_id": taxonomy.DEVICE_TYPE_UNKNOWN_ID}
    host_name = _extract_host_name(source)
    host_ip = _extract_host_ip(source)
    if host_name:
        device["hostname"] = host_name
    if host_ip:
        device["ip"] = host_ip
    base = {
        "activity_id": activity_id,
        "category_uid": category_uid,
        "class_uid": class_uid,
        "type_uid": taxonomy.to_type_uid(class_uid, activity_id),
        "time": time_value,
        "severity_id": _map_severity_id(raw_event.get("severity")),
        "metadata": metadata,
    }
    if device.get("hostname") or device.get("ip"):
        base["device"] = device
    base["unmapped"] = _build_unmapped(hit, source)
    return base


def _build_unmapped(hit: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    elastic_block: Dict[str, Any] = {
        "_index": hit.get("_index"),
        "_id": hit.get("_id"),
        "_version": hit.get("_version"),
        "_source": source,
    }
    elastic_block = {key: value for key, value in elastic_block.items() if value is not None}
    return {
        "elastic": elastic_block,
        "elastic_source": source,
    }


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
