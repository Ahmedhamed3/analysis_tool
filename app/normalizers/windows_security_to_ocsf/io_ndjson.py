from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from app.normalizers.sysmon_to_ocsf.report import build_report
from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader
from app.normalizers.windows_security_to_ocsf.mapper import MappingContext, map_raw_event


def read_raw_events(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def convert_events(
    raw_events: Iterable[Dict[str, Any]],
    *,
    schema_loader: OcsfSchemaLoader,
    strict: bool,
) -> Iterator[Tuple[Optional[Dict[str, Any]], Dict[str, Any]]]:
    context = MappingContext(ocsf_version=schema_loader.version)
    for raw_event in raw_events:
        ocsf_event = map_raw_event(raw_event, context)
        supported = ocsf_event is not None
        validation_errors: List[str] = []
        if supported and ocsf_event is not None:
            class_path = class_path_for_event(ocsf_event)
            if class_path:
                result = schema_loader.validate_event(ocsf_event, class_path)
                validation_errors = result.errors
                if strict and not result.valid:
                    ocsf_event = None
            else:
                supported = False
                ocsf_event = None
        report = build_report(
            raw_event=raw_event,
            ocsf_event=ocsf_event,
            supported=supported,
            validation_errors=validation_errors,
        )
        yield ocsf_event, report


def write_ndjson(path: Path, payloads: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for payload in payloads:
            handle.write(json.dumps(payload))
            handle.write("\n")


def class_path_for_event(event: Dict[str, Any]) -> Optional[str]:
    class_uid = event.get("class_uid")
    if class_uid == 3002:
        return "iam/authentication"
    if class_uid == 1007:
        return "system/process_activity"
    return None
