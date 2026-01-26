import json
from typing import Iterator

from app.plugins.sysmon.parse import iter_sysmon_events
from app.plugins.sysmon.map_to_ocsf import (
    map_sysmon_eventid1_to_ocsf,
    map_sysmon_eventid3_to_ocsf,
    map_sysmon_eventid11_to_ocsf,
    map_sysmon_eventid22_to_ocsf,
)

EVENT_MAPPERS = {
    1: map_sysmon_eventid1_to_ocsf,
    3: map_sysmon_eventid3_to_ocsf,
    11: map_sysmon_eventid11_to_ocsf,
    22: map_sysmon_eventid22_to_ocsf,
}

def convert_sysmon_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    """
    Yields JSONL lines (strings) for mapped events.
    """
    for ev in iter_sysmon_events(file_path):
        mapper = EVENT_MAPPERS.get(ev.event_id)
        if not mapper:
            continue
        out = mapper(ev)
        if out is None:
            continue
        yield json.dumps(out, ensure_ascii=False)
