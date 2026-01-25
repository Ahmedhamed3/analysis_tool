import os
from typing import Any, Dict, Optional

from app.ocsf.constants import (
    CATEGORY_UID_SYSTEM,
    PROCESS_ACTIVITY_CLASS_UID,
    PROCESS_ACTIVITY_LAUNCH_ID,
    DEFAULT_SEVERITY_ID,
    DEFAULT_METADATA_PRODUCT,
    DEFAULT_METADATA_VERSION,
    DEFAULT_DEVICE_TYPE_ID,
    DEFAULT_FILE_TYPE_ID,
    calc_type_uid,
)
from app.plugins.sysmon.parse import SysmonNormalized

def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return os.path.basename(path)

def map_sysmon_eventid1_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 1 (Process Create) -> OCSF process_activity Launch.
    Returns None if event is not EventID 1.
    """
    if ev.event_id != 1:
        return None

    type_uid = calc_type_uid(PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_LAUNCH_ID)

    # Required by system.json: actor + device
    actor: Dict[str, Any] = {}
    if ev.user:
        actor["user"] = {"name": ev.user}  # minimal to satisfy actor

    device: Dict[str, Any] = {"type_id": DEFAULT_DEVICE_TYPE_ID}
    if ev.host:
        device["hostname"] = ev.host

    # Required by process_activity: process (and process constraint wants pid or uid)
    process: Dict[str, Any] = {}
    if ev.pid is not None:
        process["pid"] = ev.pid
    if ev.cmd:
        process["cmd_line"] = ev.cmd

    # Prefer file object for Image (more schema-accurate than process.name)
    if ev.image:
        fname = _basename(ev.image)
        # If process.file exists, file.json usually requires name + type_id
        process["file"] = {
            "name": fname or "unknown",
            "type_id": DEFAULT_FILE_TYPE_ID,
            "path": ev.image,  # recommended
        }

    # Parent process (recommended)
    if ev.parent_pid is not None or ev.parent_image or ev.parent_cmd:
        parent: Dict[str, Any] = {}
        if ev.parent_pid is not None:
            parent["pid"] = ev.parent_pid
        if ev.parent_cmd:
            parent["cmd_line"] = ev.parent_cmd
        if ev.parent_image:
            pfname = _basename(ev.parent_image)
            parent["file"] = {
                "name": pfname or "unknown",
                "type_id": DEFAULT_FILE_TYPE_ID,
                "path": ev.parent_image,
            }
        process["parent_process"] = parent

    # If we still don't have pid/uid, we can't emit a valid process object
    if "pid" not in process and "uid" not in process:
        return None

    # Build OCSF event
    ocsf_event: Dict[str, Any] = {
        "activity_id": PROCESS_ACTIVITY_LAUNCH_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": PROCESS_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor if actor else {"app_name": "unknown"},  # still satisfies "actor has at least one"
        "device": device,
        "process": process,
    }

    return ocsf_event
