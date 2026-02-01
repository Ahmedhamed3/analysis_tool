from __future__ import annotations

from pathlib import Path

from app.normalizers.sysmon_to_ocsf.io_ndjson import class_path_for_event
from app.normalizers.sysmon_to_ocsf.mapper import MappingContext, map_raw_event
from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader


SYSmon_EID1_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-01-02T03:04:05.678Z" />
    <EventRecordID>123</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST-A</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2024-01-02 03:04:05.678</Data>
    <Data Name="ProcessId">1234</Data>
    <Data Name="ProcessGuid">{11111111-1111-1111-1111-111111111111}</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessId">2222</Data>
    <Data Name="ParentProcessGuid">{22222222-2222-2222-2222-222222222222}</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentCommandLine">explorer.exe</Data>
    <Data Name="User">CONTOSO\\jdoe</Data>
  </EventData>
</Event>"""

SYSmon_EID3_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>3</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-01-02T03:05:05.678Z" />
    <EventRecordID>124</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST-A</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">4321</Data>
    <Data Name="ProcessGuid">{33333333-3333-3333-3333-333333333333}</Data>
    <Data Name="Image">C:\\Windows\\System32\\svchost.exe</Data>
    <Data Name="User">CONTOSO\\svc</Data>
    <Data Name="SourceIp">10.0.0.10</Data>
    <Data Name="SourcePort">50000</Data>
    <Data Name="DestinationIp">10.0.0.20</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="Protocol">tcp</Data>
  </EventData>
</Event>"""

SYSmon_EID11_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>11</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-01-02T03:06:05.678Z" />
    <EventRecordID>125</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST-A</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">5555</Data>
    <Data Name="ProcessGuid">{44444444-4444-4444-4444-444444444444}</Data>
    <Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
    <Data Name="CommandLine">notepad.exe C:\\Temp\\notes.txt</Data>
    <Data Name="TargetFilename">C:\\Temp\\notes.txt</Data>
    <Data Name="User">CONTOSO\\jdoe</Data>
  </EventData>
</Event>"""


def build_raw_event(xml: str, event_id: int, record_id: int, dedupe_hash: str) -> dict:
    return {
        "envelope_version": "1.0",
        "source": {
            "type": "sysmon",
            "vendor": "microsoft",
            "product": "sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "event": {"time": {"observed_utc": "2024-01-02T03:04:06.000Z", "created_utc": "2024-01-02T03:04:05.678Z"}},
        "ids": {
            "record_id": record_id,
            "event_id": event_id,
            "activity_id": None,
            "correlation_id": None,
            "dedupe_hash": dedupe_hash,
        },
        "host": {"hostname": "HOST-A", "os": "windows", "timezone": "UTC+0000"},
        "severity": "information",
        "tags": ["live", "sysmon"],
        "raw": {"format": "xml", "data": xml, "rendered_message": None, "xml": xml},
    }


def test_sysmon_mapping_is_schema_valid() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_events = [
        build_raw_event(SYSmon_EID1_XML, 1, 123, "sha256:one"),
        build_raw_event(SYSmon_EID3_XML, 3, 124, "sha256:two"),
        build_raw_event(SYSmon_EID11_XML, 11, 125, "sha256:three"),
    ]
    for raw_event in raw_events:
        mapped = map_raw_event(raw_event, context)
        assert mapped is not None
        class_path = class_path_for_event(mapped)
        assert class_path is not None
        result = schema_loader.validate_event(mapped, class_path)
        assert result.valid, result.errors


def test_sysmon_mapping_is_deterministic() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID11_XML, 11, 125, "sha256:three")
    mapped_first = map_raw_event(raw_event, context)
    mapped_second = map_raw_event(raw_event, context)
    assert mapped_first == mapped_second


def test_validator_reports_errors() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID3_XML, 3, 124, "sha256:two")
    mapped = map_raw_event(raw_event, context)
    assert mapped is not None
    mapped.pop("metadata", None)
    class_path = class_path_for_event(mapped)
    assert class_path is not None
    result = schema_loader.validate_event(mapped, class_path)
    assert not result.valid
    assert any("metadata" in error for error in result.errors)
