# OCSF v1.2.0 (based on your schema files)

CATEGORY_UID_SYSTEM = 1

# From events/system/process.json snippet you pasted:
PROCESS_ACTIVITY_CLASS_UID = 7

# From activity_id enum in process_activity:
PROCESS_ACTIVITY_LAUNCH_ID = 1  # Launch

# In your schema, Codex computed:
# type_uid = class_uid * 100 + activity_id  (for this class)
def calc_type_uid(class_uid: int, activity_id: int) -> int:
    return class_uid * 100 + activity_id

DEFAULT_SEVERITY_ID = 1  # informational/low (safe default for MVP)

DEFAULT_METADATA_PRODUCT = "Microsoft Sysmon"
DEFAULT_METADATA_VERSION = "unknown"  # replace later if you can extract Sysmon version

DEFAULT_DEVICE_TYPE_ID = 0  # unknown (we’ll refine after reading device.json enum)
DEFAULT_FILE_TYPE_ID = 0    # unknown (we’ll refine after reading file.json enum)

# Security Finding (OCSF class UID for findings)
SECURITY_FINDING_CLASS_UID = 2004
SECURITY_FINDING_ACTIVITY_ALERT_ID = 1

# Authentication Activity
AUTHENTICATION_ACTIVITY_CLASS_UID = 3002
