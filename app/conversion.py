import json
from typing import Iterable, Iterator

from app.detect import detect_event
from app.ocsf.unknown import map_unknown_event_to_ocsf
from app.plugins.azure_ad_signin.pipeline import convert_azure_ad_signin_events_to_ocsf_jsonl
from app.plugins.file_artifact.pipeline import convert_file_artifact_events_to_ocsf_jsonl
from app.plugins.suricata.pipeline import convert_suricata_events_to_ocsf_jsonl
from app.plugins.sysmon.pipeline import convert_sysmon_events_to_ocsf_jsonl
from app.plugins.windows_security.pipeline import convert_windows_security_events_to_ocsf_jsonl
from app.plugins.zeek.pipeline import convert_zeek_dns_events_to_ocsf_jsonl
from app.plugins.zeek_http.pipeline import convert_zeek_http_events_to_ocsf_jsonl
from app.plugins.proxy_http.pipeline import convert_proxy_http_events_to_ocsf_jsonl


SOURCE_PIPELINES = {
    "azure_ad_signin": convert_azure_ad_signin_events_to_ocsf_jsonl,
    "sysmon": convert_sysmon_events_to_ocsf_jsonl,
    "zeek": convert_zeek_dns_events_to_ocsf_jsonl,
    "zeek_http": convert_zeek_http_events_to_ocsf_jsonl,
    "suricata": convert_suricata_events_to_ocsf_jsonl,
    "windows-security": convert_windows_security_events_to_ocsf_jsonl,
    "file-artifact": convert_file_artifact_events_to_ocsf_jsonl,
    "proxy_http": convert_proxy_http_events_to_ocsf_jsonl,
}


def _ensure_unmapped_original(event: dict, mapped: dict) -> dict:
    unmapped = mapped.get("unmapped")
    if not isinstance(unmapped, dict):
        unmapped = {}
        mapped["unmapped"] = unmapped
    if "original_event" not in unmapped:
        unmapped["original_event"] = event
    return mapped


def convert_events_to_ocsf_jsonl(
    events: Iterable[dict],
    *,
    threshold: float = 0.6,
) -> Iterator[str]:
    for event in events:
        detection = detect_event(event, threshold=threshold)
        source_type = detection["source_type"]
        if source_type != "unknown":
            converter = SOURCE_PIPELINES.get(source_type)
            if converter:
                mapped_lines = list(converter([event]))
                if mapped_lines:
                    mapped_line = mapped_lines[0]
                    try:
                        mapped_event = json.loads(mapped_line)
                    except json.JSONDecodeError:
                        mapped_event = None
                    if isinstance(mapped_event, dict):
                        mapped_event = _ensure_unmapped_original(event, mapped_event)
                        yield json.dumps(mapped_event, ensure_ascii=False)
                        continue
                    yield mapped_line
                    continue
        unknown_event = map_unknown_event_to_ocsf(event)
        yield json.dumps(unknown_event, ensure_ascii=False)
