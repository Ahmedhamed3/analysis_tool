import json
from json import JSONDecodeError
from typing import Iterable, Iterator, List

from fastapi import HTTPException


WRAPPER_KEYS = ("Events", "events", "records")


def _ensure_dict_list(items: Iterable[object]) -> List[dict]:
    events: List[dict] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise HTTPException(
                status_code=400,
                detail=f"Expected JSON object at index {idx}, got {type(item).__name__}.",
            )
        events.append(item)
    return events


def _unwrap_events(obj: object) -> List[dict]:
    if isinstance(obj, list):
        return _ensure_dict_list(obj)
    if isinstance(obj, dict):
        for key in WRAPPER_KEYS:
            value = obj.get(key)
            if isinstance(value, list):
                return _ensure_dict_list(value)
        return [obj]
    raise HTTPException(
        status_code=400,
        detail="Top-level JSON must be an object or array of objects.",
    )


def _iter_ndjson(text: str) -> Iterator[dict]:
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Malformed NDJSON at line {line_no}: {exc.msg}.",
            ) from exc
        if not isinstance(value, dict):
            raise HTTPException(
                status_code=400,
                detail=f"Expected JSON object at line {line_no}, got {type(value).__name__}.",
            )
        yield value


def iter_events_from_upload(file_bytes: bytes) -> Iterable[dict]:
    """
    Parse uploaded JSON in NDJSON, JSON array, or single-object format.
    """
    text = file_bytes.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    if not stripped:
        return iter([])

    first_char = stripped[0]
    if first_char == "[":
        try:
            payload = json.loads(stripped)
        except JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Malformed JSON array: {exc.msg}.",
            ) from exc
        return iter(_unwrap_events(payload))

    if first_char == "{":
        try:
            payload = json.loads(stripped)
            return iter(_unwrap_events(payload))
        except JSONDecodeError:
            events = list(_iter_ndjson(text))
            return iter(events)

    events = list(_iter_ndjson(text))
    return iter(events)
