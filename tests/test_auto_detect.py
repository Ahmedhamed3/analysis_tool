from pathlib import Path

import pytest

from app.detect import auto_detect_source
from app.formats.reader import iter_events_from_upload


SAMPLES = [
    ("sysmon", "sysmon.ndjson"),
    ("sysmon", "sysmon.json"),
    ("suricata", "suricata.ndjson"),
    ("suricata", "suricata.json"),
    ("zeek", "zeek_dns.ndjson"),
    ("zeek", "zeek_dns.json"),
    ("windows-security", "windows_security.ndjson"),
    ("windows-security", "windows_security.json"),
    ("file-artifact", "file_artifact.ndjson"),
    ("file-artifact", "file_artifact.json"),
]


@pytest.mark.parametrize("expected_source, sample_name", SAMPLES)
def test_auto_detect_source(expected_source: str, sample_name: str):
    sample_path = Path("samples") / sample_name
    events = list(iter_events_from_upload(sample_path.read_bytes()))
    detection = auto_detect_source(events[:10])

    assert detection["source_type"] == expected_source
    assert detection["confidence"] >= 0.6
