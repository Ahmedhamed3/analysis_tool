import json

from fastapi.testclient import TestClient

from app.main import app


def test_convert_sysmon_upload_json_array_mixed_events():
    client = TestClient(app)

    payload = [
        {
            "EventID": 1,
            "UtcTime": "2024-01-01 00:00:00.000",
            "Computer": "host1",
            "User": "user1",
            "ProcessId": 1234,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        },
        {
            "EventID": 3,
            "UtcTime": "2024-01-01 00:00:01.000",
            "Computer": "host1",
            "User": "user1",
            "SourceIp": "10.0.0.1",
            "SourcePort": 12345,
            "DestinationIp": "10.0.0.2",
            "DestinationPort": 443,
            "Protocol": "tcp",
        },
        {"EventID": 99, "UtcTime": "2024-01-01 00:00:02.000"},
    ]

    files = {
        "file": (
            "mixed.json",
            json.dumps(payload).encode("utf-8"),
            "application/json",
        )
    }

    response = client.post("/convert/sysmon", files=files)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")

    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) == 2

    events = [json.loads(line) for line in lines]
    type_pairs = {(event["class_uid"], event["type_uid"]) for event in events}

    assert (7, 701) in type_pairs
    assert (4001, 400101) in type_pairs
