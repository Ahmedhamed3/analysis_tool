from typing import Any, Dict, Optional

from app.ocsf.constants import AUTHENTICATION_ACTIVITY_CLASS_UID, calc_type_uid
from app.plugins.windows_security.parse import WindowsSecurityNormalized

AUTH_LOGON_SUCCESS_ID = 1
AUTH_LOGON_FAILURE_ID = 2


def _safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def map_windows_security_authentication_to_ocsf(
    ev: WindowsSecurityNormalized,
) -> Optional[Dict[str, Any]]:
    if ev.event_id not in (4624, 4625):
        return None

    activity_id = AUTH_LOGON_SUCCESS_ID if ev.event_id == 4624 else AUTH_LOGON_FAILURE_ID
    type_uid = calc_type_uid(AUTHENTICATION_ACTIVITY_CLASS_UID, activity_id)

    actor: Dict[str, Any] = {}
    user: Dict[str, Any] = {}
    if ev.target_user_name:
        user["name"] = ev.target_user_name
    if ev.target_domain_name:
        user["domain"] = ev.target_domain_name
    if user:
        actor["user"] = user

    auth: Dict[str, Any] = {
        "result": "success" if ev.event_id == 4624 else "failure",
    }
    logon_type = _safe_int(ev.logon_type) if ev.logon_type else None
    if logon_type is not None:
        auth["logon_type"] = logon_type
    elif ev.logon_type:
        auth["logon_type"] = ev.logon_type

    failure_reason = ev.failure_reason or ev.status
    if ev.event_id == 4625 and failure_reason:
        auth["failure_reason"] = failure_reason

    ocsf_event: Dict[str, Any] = {
        "activity_id": activity_id,
        "class_uid": AUTHENTICATION_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.time_created,
        "metadata": {"product": "Windows Security"},
        "auth": auth,
        "unmapped": {"original_event": ev.original_event},
    }

    if actor:
        ocsf_event["actor"] = actor
    if ev.ip_address:
        ocsf_event["src_endpoint"] = {"ip": ev.ip_address}
    if ev.workstation_name:
        ocsf_event["dst_endpoint"] = {"hostname": ev.workstation_name}

    return ocsf_event
