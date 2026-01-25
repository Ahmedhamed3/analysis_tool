import json
from typing import Dict, Iterator, Callable

from app.plugins.sysmon.parse import iter_sysmon_events
from app.plugins.sysmon.map_to_ocsf import (
    map_sysmon_eventid1_to_ocsf,
    map_sysmon_eventid3_to_ocsf,
)

EVENT_MAPPERS: Dict[int, Callable] = {
    1: map_sysmon_eventid1_to_ocsf,
    3: map_sysmon_eventid3_to_ocsf,
}

def convert_sysmon_events_to_ocsf(evs) -> Iterator[dict]:
    for ev in evs:
        fn = EVENT_MAPPERS.get(ev.event_id)
        if not fn:
            continue
        out = fn(ev)
        if out is None:
            continue
        yield out

def convert_sysmon_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    """
    Yields JSONL lines (strings) for mapped events.
    """
    events = iter_sysmon_events(file_path)
    for out in convert_sysmon_events_to_ocsf(events):
        yield json.dumps(out, ensure_ascii=False)
