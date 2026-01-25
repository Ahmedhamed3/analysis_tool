import json
from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid1_to_ocsf
from app.plugins.sysmon.parse import SysmonNormalized

def test_eventid1_maps_to_process_launch():
    ev = SysmonNormalized(
        ts="2024-01-01T00:00:00Z",
        host="PC-1",
        user="CONTOSO\\jdoe",
        event_id=1,
        pid=1234,
        image="C:\\Windows\\System32\\cmd.exe",
        cmd="cmd.exe /c whoami",
        parent_pid=2222,
        parent_image="C:\\Windows\\explorer.exe",
        parent_cmd="explorer.exe",
    )

    out = map_sysmon_eventid1_to_ocsf(ev)
    assert out is not None
    assert out["class_uid"] == 7
    assert out["activity_id"] == 1
    assert out["category_uid"] == 1
    assert out["type_uid"] == 701
    assert out["time"] == "2024-01-01T00:00:00Z"
    assert "actor" in out and "device" in out and "process" in out
    assert out["process"]["pid"] == 1234
