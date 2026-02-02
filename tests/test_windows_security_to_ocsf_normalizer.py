from __future__ import annotations

from pathlib import Path
from typing import Dict

from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader
from app.normalizers.windows_security_to_ocsf.io_ndjson import convert_events
from app.utils.raw_envelope import build_security_raw_event


def _build_raw_event(event_id: int, event_data: Dict[str, str], *, record_id: int = 100) -> dict:
    raw_record = {
        "record_id": record_id,
        "time_created_utc": "2024-01-01T12:00:00Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": event_id,
        "level": 4,
        "computer": "WIN-TEST",
        "event_data": event_data,
        "raw_xml": None,
    }
    return build_security_raw_event(
        raw_record,
        observed_utc="2024-01-01T12:00:00Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )


def _schema_loader() -> OcsfSchemaLoader:
    return OcsfSchemaLoader(Path("app/ocsf_schema"))


def test_windows_security_auth_4624_json() -> None:
    raw_event = _build_raw_event(
        4624,
        {
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "TargetUserSid": "S-1-5-21-111",
            "TargetUserName": "alice",
            "TargetDomainName": "CONTOSO",
            "LogonType": "3",
            "IpAddress": "10.0.0.5",
            "IpPort": "12345",
            "WorkstationName": "CLIENT1",
            "AuthenticationPackageName": "Kerberos",
            "LogonProcessName": "User32",
            "LogonId": "0x123",
        },
        record_id=200,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["class_uid"] == 3002
    assert ocsf_event["activity_id"] == 1
    assert ocsf_event["user"]["name"] == "alice"
    assert ocsf_event["status"] == "Success"


def test_windows_security_auth_4625_xml() -> None:
    xml_payload = """
    <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
      <System>
        <EventID>4625</EventID>
        <EventRecordID>201</EventRecordID>
        <TimeCreated SystemTime=\"2024-01-01T12:01:00.000Z\" />
        <Computer>WIN-TEST</Computer>
      </System>
      <EventData>
        <Data Name=\"SubjectUserSid\">S-1-5-18</Data>
        <Data Name=\"SubjectUserName\">SYSTEM</Data>
        <Data Name=\"SubjectDomainName\">NT AUTHORITY</Data>
        <Data Name=\"TargetUserSid\">S-1-5-21-222</Data>
        <Data Name=\"TargetUserName\">bob</Data>
        <Data Name=\"TargetDomainName\">CONTOSO</Data>
        <Data Name=\"LogonType\">2</Data>
        <Data Name=\"IpAddress\">10.0.0.10</Data>
        <Data Name=\"IpPort\">55000</Data>
        <Data Name=\"WorkstationName\">CLIENT2</Data>
        <Data Name=\"AuthenticationPackageName\">Negotiate</Data>
        <Data Name=\"LogonProcessName\">User32</Data>
        <Data Name=\"Status\">0xC000006D</Data>
        <Data Name=\"SubStatus\">0xC000006A</Data>
        <Data Name=\"FailureReason\">%%2313</Data>
      </EventData>
    </Event>
    """.strip()
    raw_event = _build_raw_event(
        4625,
        {
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
        },
        record_id=201,
    )
    raw_event["raw"]["format"] = "xml"
    raw_event["raw"]["data"] = xml_payload
    raw_event["raw"]["xml"] = xml_payload
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["status"] == "Failure"
    assert ocsf_event["status_code"] == "0xC000006D"
    assert "SubStatus" in ocsf_event["status_detail"]


def test_windows_security_unsupported_event() -> None:
    raw_event = _build_raw_event(9999, {"SubjectUserName": "SYSTEM"}, record_id=300)
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert ocsf_event is None
    assert report["status"] == "unsupported"
    assert report["supported"] is False
