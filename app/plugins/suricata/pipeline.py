import json
from typing import Iterator

from app.plugins.suricata.parse import iter_suricata_events
from app.plugins.suricata.map_to_ocsf import map_suricata_alert_to_ocsf


def convert_suricata_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    for ev in iter_suricata_events(file_path):
        out = map_suricata_alert_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)
