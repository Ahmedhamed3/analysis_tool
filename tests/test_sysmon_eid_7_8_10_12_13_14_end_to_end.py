import json
from pathlib import Path

from app.conversion import convert_events_to_ocsf_jsonl
from app.ocsf.constants import (
    MODULE_ACTIVITY_CLASS_UID,
    MODULE_ACTIVITY_LOAD_ID,
    PROCESS_ACTIVITY_CLASS_UID,
    PROCESS_ACTIVITY_INJECT_ID,
    PROCESS_ACTIVITY_OPEN_ID,
    REGISTRY_KEY_ACTIVITY_CLASS_UID,
    REGISTRY_KEY_ACTIVITY_CREATE_ID,
    REGISTRY_VALUE_ACTIVITY_CLASS_UID,
    REGISTRY_VALUE_ACTIVITY_SET_ID,
    REGISTRY_VALUE_ACTIVITY_MODIFY_ID,
    calc_type_uid,
)


SAMPLE_PATH = Path("samples/sysmon_7_8_10_12_13_14.ndjson")

EXPECTED = {
    7: (MODULE_ACTIVITY_CLASS_UID, MODULE_ACTIVITY_LOAD_ID),
    8: (PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_INJECT_ID),
    10: (PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_OPEN_ID),
    12: (REGISTRY_KEY_ACTIVITY_CLASS_UID, REGISTRY_KEY_ACTIVITY_CREATE_ID),
    13: (REGISTRY_VALUE_ACTIVITY_CLASS_UID, REGISTRY_VALUE_ACTIVITY_SET_ID),
    14: (REGISTRY_VALUE_ACTIVITY_CLASS_UID, REGISTRY_VALUE_ACTIVITY_MODIFY_ID),
}


def _load_events():
    events = []
    for line in SAMPLE_PATH.read_text().splitlines():
        if not line.strip():
            continue
        events.append(json.loads(line))
    return events


def test_sysmon_eventids_7_8_10_12_13_14_end_to_end():
    events = _load_events()
    assert len(events) == 6

    output_lines = list(convert_events_to_ocsf_jsonl(events))
    assert len(output_lines) == len(events)

    outputs = [json.loads(line) for line in output_lines]

    for original, mapped in zip(events, outputs):
        event_id = original["EventID"]
        class_uid, activity_id = EXPECTED[event_id]
        assert mapped["class_uid"] == class_uid
        assert mapped["type_uid"] == calc_type_uid(class_uid, activity_id)
        assert "unmapped" in mapped
        assert "original_event" in mapped["unmapped"]
        assert mapped["unmapped"]["original_event"]["EventID"] == event_id
        assert "actor" in mapped
        assert "device" in mapped
