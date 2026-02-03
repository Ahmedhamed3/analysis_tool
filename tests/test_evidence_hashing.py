from __future__ import annotations

from pathlib import Path

from app.normalizers.elastic_to_ocsf.mapper import MappingContext as ElasticMappingContext
from app.normalizers.elastic_to_ocsf.mapper import map_raw_event as map_elastic_raw_event
from app.normalizers.sysmon_to_ocsf.mapper import MappingContext as SysmonMappingContext
from app.normalizers.sysmon_to_ocsf.mapper import map_raw_event as map_sysmon_raw_event
from app.normalizers.windows_security_to_ocsf.mapper import MappingContext as SecurityMappingContext
from app.normalizers.windows_security_to_ocsf.mapper import map_raw_event as map_security_raw_event
from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader
from app.utils.evidence_hashing import (
    apply_evidence_hashing,
    canonicalize_json,
    hash_sha256_hex,
)
from app.utils.raw_envelope import build_elastic_raw_event, build_security_raw_event


SYS_MON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
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
  </EventData>
</Event>"""


def _schema_loader() -> OcsfSchemaLoader:
    return OcsfSchemaLoader(Path("app/ocsf_schema"))


def _build_sysmon_raw_event() -> dict:
    return {
        "envelope_version": "1.0",
        "source": {
            "type": "sysmon",
            "vendor": "microsoft",
            "product": "sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "event": {
            "time": {
                "observed_utc": "2024-01-02T03:04:06.000Z",
                "created_utc": "2024-01-02T03:04:05.678Z",
            }
        },
        "ids": {
            "record_id": 123,
            "event_id": 1,
            "activity_id": None,
            "correlation_id": None,
            "dedupe_hash": "sha256:sysmon-test",
        },
        "host": {"hostname": "HOST-A", "os": "windows", "timezone": "UTC+0000"},
        "severity": "information",
        "tags": ["live", "sysmon"],
        "raw": {"format": "xml", "data": SYS_MON_XML, "rendered_message": None, "xml": SYS_MON_XML},
    }


def _build_security_raw_event() -> dict:
    raw_record = {
        "record_id": 200,
        "time_created_utc": "2024-01-01T12:00:00Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": 4624,
        "level": 4,
        "computer": "WIN-TEST",
        "event_data": {
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "TargetUserSid": "S-1-5-21-111",
            "TargetUserName": "alice",
            "TargetDomainName": "CONTOSO",
            "LogonType": "3",
            "IpAddress": "10.0.0.5",
        },
        "raw_xml": None,
    }
    return build_security_raw_event(
        raw_record,
        observed_utc="2024-01-01T12:00:00Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )


def _build_elastic_raw_event() -> dict:
    hit = {
        "_index": "logs-test-0001",
        "_id": "doc-1",
        "_source": {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": {
                "kind": "event",
                "category": ["process"],
                "action": "start",
            },
            "process": {
                "pid": 4321,
                "executable": "C:\\\\Windows\\\\System32\\\\cmd.exe",
                "command_line": "cmd.exe /c whoami",
            },
            "host": {"name": "elastic-host"},
        },
    }
    return build_elastic_raw_event(
        hit,
        now_utc="2024-01-01T00:00:01Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )


def test_canonicalization_is_deterministic() -> None:
    payload = {"b": 1, "a": ["z", {"c": 2, "d": 3}]}
    first = canonicalize_json(payload)
    second = canonicalize_json(payload)
    assert first == second
    assert hash_sha256_hex(first) == hash_sha256_hex(second)


def test_canonicalization_key_order_is_stable() -> None:
    payload_a = {"b": 1, "a": {"y": 2, "x": 3}}
    payload_b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert canonicalize_json(payload_a) == canonicalize_json(payload_b)


def test_hash_changes_on_single_bit_change() -> None:
    payload_a = {"message": "alpha"}
    payload_b = {"message": "alphb"}
    hash_a = hash_sha256_hex(canonicalize_json(payload_a))
    hash_b = hash_sha256_hex(canonicalize_json(payload_b))
    assert hash_a != hash_b


def test_evidence_hashing_regression_sysmon_windows_elastic() -> None:
    schema_loader = _schema_loader()
    sysmon_context = SysmonMappingContext(ocsf_version=schema_loader.version)
    security_context = SecurityMappingContext(ocsf_version=schema_loader.version)
    elastic_context = ElasticMappingContext(ocsf_version=schema_loader.version)

    sysmon_raw = _build_sysmon_raw_event()
    security_raw = _build_security_raw_event()
    elastic_raw = _build_elastic_raw_event()

    sysmon_ocsf = map_sysmon_raw_event(sysmon_raw, sysmon_context)
    security_ocsf = map_security_raw_event(security_raw, security_context)
    elastic_ocsf = map_elastic_raw_event(elastic_raw, elastic_context)

    assert sysmon_ocsf is not None
    assert security_ocsf is not None
    assert elastic_ocsf is not None

    sysmon_result = apply_evidence_hashing(
        sysmon_raw,
        sysmon_ocsf,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    security_result = apply_evidence_hashing(
        security_raw,
        security_ocsf,
        ocsf_schema="iam/authentication",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    elastic_result = apply_evidence_hashing(
        elastic_raw,
        elastic_ocsf,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )

    assert sysmon_result.raw_envelope["derived"]["ocsf_event_hash"] == sysmon_result.evidence_commit["ocsf"]["hash_sha256"]
    assert security_result.raw_envelope["derived"]["ocsf_event_hash"] == security_result.evidence_commit["ocsf"]["hash_sha256"]
    assert elastic_result.raw_envelope["derived"]["ocsf_event_hash"] == elastic_result.evidence_commit["ocsf"]["hash_sha256"]

    assert sysmon_result.ocsf_event["forensics"]["raw_envelope_hash"] == sysmon_result.evidence_commit["raw_envelope"]["hash_sha256"]
    assert security_result.ocsf_event["forensics"]["raw_envelope_hash"] == security_result.evidence_commit["raw_envelope"]["hash_sha256"]
    assert elastic_result.ocsf_event["forensics"]["raw_envelope_hash"] == elastic_result.evidence_commit["raw_envelope"]["hash_sha256"]

    assert sysmon_result.evidence_commit["raw_envelope"]["hash_sha256"] == "e2ed1a5c33d797113624efeb5a1983a1100af20b8cb576127f928933c75a2bf2"
    assert sysmon_result.evidence_commit["ocsf"]["hash_sha256"] == "d74f9cfa85a69d4b83ca9b806a58c7dbf5b2edf9e09741e6aa29bd51f18b91aa"
    assert security_result.evidence_commit["raw_envelope"]["hash_sha256"] == "4dd4d225d5cf6d858031a31d826fca92c6e09540519da1d91d9eb2c11120a11d"
    assert security_result.evidence_commit["ocsf"]["hash_sha256"] == "1bc6129c8cd1d79e44c3716c29596b5b5c634ff7c1e3f5f13bd66c3f4f68e3f3"
    assert elastic_result.evidence_commit["raw_envelope"]["hash_sha256"] == "c17ff2418de6101acd7c368ad2eab31b6055840b30d8936123d05d6f305372a3"
    assert elastic_result.evidence_commit["ocsf"]["hash_sha256"] == "c0b0faf8ca8d12e0db8fe5d9b77abf1eb64b98d5d71533df82b0b67390173c14"
