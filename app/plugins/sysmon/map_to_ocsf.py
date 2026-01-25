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

NETWORK_CATEGORY_UID = 4
NETWORK_ACTIVITY_CLASS_UID = 4001
NETWORK_ACTIVITY_OPEN_ID = 1
NETWORK_ACTIVITY_OPEN_TYPE_UID = 400101
FILE_SYSTEM_ACTIVITY_CLASS_UID = 1001
FILE_SYSTEM_ACTIVITY_CREATE_ID = 1
FILE_SYSTEM_ACTIVITY_CREATE_TYPE_UID = 100101

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

def map_sysmon_eventid3_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 3 (Network Connect) -> OCSF network activity Open.
    Returns None if event is not EventID 3.
    """
    if ev.event_id != 3:
        return None

    actor: Dict[str, Any] = {}
    if ev.user:
        actor["user"] = {"name": ev.user}

    device: Dict[str, Any] = {"type_id": DEFAULT_DEVICE_TYPE_ID}
    if ev.host:
        device["hostname"] = ev.host

    network: Dict[str, Any] = {}
    if ev.src_ip or ev.src_port is not None:
        src: Dict[str, Any] = {}
        if ev.src_ip:
            src["ip"] = ev.src_ip
        if ev.src_port is not None:
            src["port"] = ev.src_port
        network["src_endpoint"] = src
    if ev.dst_ip or ev.dst_port is not None:
        dst: Dict[str, Any] = {}
        if ev.dst_ip:
            dst["ip"] = ev.dst_ip
        if ev.dst_port is not None:
            dst["port"] = ev.dst_port
        network["dst_endpoint"] = dst

    if ev.protocol:
        network["protocol"] = ev.protocol

    ocsf_event: Dict[str, Any] = {
        "activity_id": NETWORK_ACTIVITY_OPEN_ID,
        "category_uid": NETWORK_CATEGORY_UID,
        "class_uid": NETWORK_ACTIVITY_CLASS_UID,
        "type_uid": NETWORK_ACTIVITY_OPEN_TYPE_UID,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor if actor else {"app_name": "unknown"},
        "device": device,
    }

    if network:
        ocsf_event["network"] = network

    return ocsf_event


def map_sysmon_eventid11_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 11 (File Create) -> OCSF File System Activity Create.
    Returns None if event is not EventID 11.
    """
    if ev.event_id != 11:
        return None

    actor: Dict[str, Any] = {}
    process: Dict[str, Any] = {}
    if ev.image:
        process["name"] = ev.image
    if ev.pid is not None:
        process["pid"] = ev.pid
    if process:
        actor["process"] = process

    file_obj: Dict[str, Any] = {}
    if ev.target_filename:
        file_obj["path"] = ev.target_filename
        file_obj["name"] = _basename(ev.target_filename) or ev.target_filename
        file_obj["type_id"] = DEFAULT_FILE_TYPE_ID

    unmapped: Dict[str, Any] = {}
    if ev.process_guid:
        unmapped["process_guid"] = ev.process_guid
    if ev.rule_name:
        unmapped["rule_name"] = ev.rule_name
    if ev.user:
        unmapped["user"] = ev.user
    if ev.creation_utctime:
        unmapped["creation_utctime"] = ev.creation_utctime
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": FILE_SYSTEM_ACTIVITY_CREATE_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": FILE_SYSTEM_ACTIVITY_CLASS_UID,
        "type_uid": FILE_SYSTEM_ACTIVITY_CREATE_TYPE_UID,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor if actor else {"app_name": "unknown"},
    }

    if file_obj:
        ocsf_event["file"] = file_obj
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event
