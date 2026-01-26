import json

import pytest

from app.formats.reader import iter_events_from_upload


def test_iter_events_from_upload_handles_json_variants():
    events = [{"alpha": 1, "beta": "two"}]

    ndjson_payload = "\n".join(json.dumps(ev) for ev in events).encode("utf-8")
    array_payload = json.dumps(events).encode("utf-8")
    object_payload = json.dumps(events[0]).encode("utf-8")

    assert list(iter_events_from_upload(ndjson_payload)) == events
    assert list(iter_events_from_upload(array_payload)) == events
    assert list(iter_events_from_upload(object_payload)) == events


def test_iter_events_from_upload_rejects_malformed_json():
    payload = b"{not: valid json"
    with pytest.raises(Exception):
        list(iter_events_from_upload(payload))
