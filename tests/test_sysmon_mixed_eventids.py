import json

from app.plugins.sysmon.parse import iter_sysmon_events
from app.plugins.sysmon.pipeline import convert_sysmon_events_to_ocsf


def test_mixed_eventids_dispatcher(tmp_path):
    payload = [
        {
            "EventID": 1,
            "UtcTime": "2024-01-01 00:00:00.000",
            "Computer": "PC-1",
            "User": "CONTOSO\\jdoe",
            "ProcessId": 1234,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        },
        {
            "EventID": 3,
            "UtcTime": "2024-02-03 04:05:06.789",
            "Computer": "PC-2",
            "User": "CONTOSO\\alice",
            "ProcessId": 4321,
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "svchost.exe -k netsvcs",
            "SourceIp": "10.0.0.5",
            "SourcePort": "51515",
            "DestinationIp": "93.184.216.34",
            "DestinationPort": "443",
            "Protocol": "tcp",
        },
        {
            "EventID": 7,
            "UtcTime": "2024-02-03 04:05:06.789",
            "Computer": "PC-3",
        },
    ]
    path = tmp_path / "sysmon.json"
    path.write_text(json.dumps(payload))

    events = iter_sysmon_events(str(path))
    outputs = list(convert_sysmon_events_to_ocsf(events))

    assert len(outputs) == 2
    assert any(out["class_uid"] == 7 and out["type_uid"] == 701 for out in outputs)
    assert any(out["class_uid"] == 4001 and out["type_uid"] == 400101 for out in outputs)
