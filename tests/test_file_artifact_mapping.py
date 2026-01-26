import json
import tempfile

from app.plugins.file_artifact.pipeline import convert_file_artifact_file_to_ocsf_jsonl


def test_file_artifact_mapping_hashes_and_paths():
    record = {
        "timestamp": "2024-05-01T12:00:00Z",
        "file_path": "C:/Evidence/sample.bin",
        "sha256": "a" * 64,
        "sha1": "b" * 40,
        "md5": "c" * 32,
        "file_size": 2048,
        "source": "Acme Collector",
    }

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tmp:
        json.dump([record], tmp)
        tmp.flush()
        tmp_path = tmp.name

    output_lines = list(convert_file_artifact_file_to_ocsf_jsonl(tmp_path))
    assert len(output_lines) == 1

    parsed = json.loads(output_lines[0])

    assert parsed["file"]["path"] == "C:/Evidence/sample.bin"
    assert parsed["file"]["name"] == "sample.bin"
    assert parsed["file"]["hash"]["sha256"] == record["sha256"]
    assert parsed["file"]["hash"]["sha1"] == record["sha1"]
    assert parsed["file"]["hash"]["md5"] == record["md5"]
    assert parsed["file"]["size"] == 2048
    assert parsed["metadata"]["product"] == "Acme Collector"
    assert parsed["unmapped"]["original_event"] == record
