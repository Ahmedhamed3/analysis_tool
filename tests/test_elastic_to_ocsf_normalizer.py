from __future__ import annotations

from pathlib import Path

from app.normalizers.elastic_to_ocsf.io_ndjson import class_path_for_event, convert_events
from app.normalizers.elastic_to_ocsf.mapper import MappingContext, map_raw_event
from app.normalizers.elastic_to_ocsf.validator import OcsfSchemaLoader
from app.utils.raw_envelope import build_elastic_raw_event


def build_raw_event(hit: dict) -> dict:
    return build_elastic_raw_event(
        hit,
        now_utc="2024-06-01T12:00:00Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )


def test_elastic_authentication_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-auth-default",
        "_id": "auth-1",
        "_source": {
            "@timestamp": "2024-06-01T11:59:00Z",
            "event": {
                "category": ["authentication"],
                "action": "user_login",
                "code": "AUTH-100",
                "outcome": "success",
            },
            "user": {"name": "alice", "id": "1001"},
            "source": {"ip": "10.0.0.10", "port": 51515},
            "host": {"name": "auth-host"},
        },
    }
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 3002
    assert mapped["activity_id"] == 1
    class_path = class_path_for_event(mapped)
    assert class_path == "iam/authentication"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_network_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-network-default",
        "_id": "net-1",
        "_source": {
            "@timestamp": "2024-06-01T11:58:00Z",
            "event": {
                "category": ["network"],
                "action": "connection",
                "dataset": "network.flow",
            },
            "network": {"transport": "tcp"},
            "source": {"ip": "10.0.0.20", "port": 12345},
            "destination": {"ip": "10.0.0.30", "port": 443},
        },
    }
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 4001
    assert mapped["activity_id"] == 1
    class_path = class_path_for_event(mapped)
    assert class_path == "network/network_activity"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_process_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-process-default",
        "_id": "proc-1",
        "_source": {
            "@timestamp": "2024-06-01T11:57:00Z",
            "event": {"category": ["process"], "action": "start"},
            "process": {
                "pid": 4321,
                "executable": "/usr/bin/bash",
                "entity_id": "proc-123",
            },
            "user": {"name": "bob"},
            "host": {"name": "endpoint-1"},
        },
    }
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 1007
    assert mapped["activity_id"] == 1
    class_path = class_path_for_event(mapped)
    assert class_path == "system/process_activity"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_generic_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-generic-default",
        "_id": "generic-1",
        "_source": {
            "@timestamp": "2024-06-01T11:56:00Z",
            "message": "Unclassified event",
        },
    }
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 0
    assert mapped["category_uid"] == 0
    class_path = class_path_for_event(mapped)
    assert class_path == "base_event"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_authentication_missing_required_fields_reported() -> None:
    hit = {
        "_index": "logs-auth-default",
        "_id": "auth-missing",
        "_source": {
            "@timestamp": "2024-06-01T11:55:00Z",
            "event": {"category": ["authentication"], "action": "user_login"},
            "host": {"name": "auth-host"},
        },
    }
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    raw_event = build_raw_event(hit)

    results = list(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )

    assert results
    mapped, report = results[0]
    assert mapped is None
    assert report["status"] == "unmapped"
    assert "user" in report.get("missing_fields", [])
