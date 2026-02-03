from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.utils.timeutil import utc_now_iso


CANONICALIZATION_NAME = "rfc8785"
HASH_ALGORITHM = "SHA-256"


def canonicalize_json(value: Any) -> bytes:
    """
    Canonicalize JSON using RFC 8785-style rules (sorted keys, UTF-8, no whitespace).
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def hash_sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _evidence_id(raw_envelope: Dict[str, Any]) -> Optional[str]:
    ids = raw_envelope.get("ids") or {}
    return ids.get("dedupe_hash") or ids.get("record_id")


def _time_block(raw_envelope: Dict[str, Any]) -> Dict[str, Any]:
    event = raw_envelope.get("event") or {}
    return event.get("time") or {}


def _raw_source(raw_envelope: Dict[str, Any]) -> Dict[str, Any]:
    source = raw_envelope.get("source")
    return source if isinstance(source, dict) else {}


@dataclass(frozen=True)
class EvidenceHashResult:
    raw_envelope: Dict[str, Any]
    ocsf_event: Dict[str, Any]
    evidence_commit: Dict[str, Any]


def compute_evidence_commit(
    raw_envelope: Dict[str, Any],
    ocsf_event: Dict[str, Any],
    *,
    ocsf_schema: Optional[str] = None,
    ocsf_version: Optional[str] = None,
    hashed_utc: Optional[str] = None,
    canonicalization: str = CANONICALIZATION_NAME,
    hash_alg: str = HASH_ALGORITHM,
    raw_hash_sha256: Optional[str] = None,
    ocsf_hash_sha256: Optional[str] = None,
    raw_size_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    raw_bytes = canonicalize_json(raw_envelope)
    ocsf_bytes = canonicalize_json(ocsf_event)
    raw_hash = raw_hash_sha256 or hash_sha256_hex(raw_bytes)
    ocsf_hash = ocsf_hash_sha256 or hash_sha256_hex(ocsf_bytes)
    ids = raw_envelope.get("ids") or {}
    time_block = _time_block(raw_envelope)
    ocsf_schema_value = ocsf_schema or None
    ocsf_version_value = ocsf_version or (ocsf_event.get("metadata") or {}).get("version")
    return {
        "commit_version": "1.0",
        "evidence_id": _evidence_id(raw_envelope),
        "source": _raw_source(raw_envelope),
        "timestamps": {
            "observed_utc": time_block.get("observed_utc"),
            "created_utc": time_block.get("created_utc"),
            "hashed_utc": hashed_utc or utc_now_iso(),
        },
        "raw_envelope": {
            "hash_sha256": raw_hash,
            "size_bytes": raw_size_bytes if raw_size_bytes is not None else len(raw_bytes),
            "format": (raw_envelope.get("raw") or {}).get("format"),
        },
        "ocsf": {
            "hash_sha256": ocsf_hash,
            "schema": ocsf_schema_value,
            "version": ocsf_version_value,
            "class_uid": ocsf_event.get("class_uid"),
            "type_uid": ocsf_event.get("type_uid"),
        },
        "linkage": {
            "record_id": ids.get("record_id"),
            "correlation_id": ids.get("correlation_id"),
            "dedupe_hash": ids.get("dedupe_hash"),
        },
        "integrity": {
            "canonicalization": canonicalization,
            "hash_alg": hash_alg,
        },
    }


def apply_evidence_hashing(
    raw_envelope: Dict[str, Any],
    ocsf_event: Dict[str, Any],
    *,
    ocsf_schema: Optional[str] = None,
    ocsf_version: Optional[str] = None,
    hashed_utc: Optional[str] = None,
) -> EvidenceHashResult:
    raw_copy = copy.deepcopy(raw_envelope)
    ocsf_copy = copy.deepcopy(ocsf_event)

    ocsf_hash = hash_sha256_hex(canonicalize_json(ocsf_copy))
    raw_copy.setdefault("derived", {})["ocsf_event_hash"] = ocsf_hash
    raw_copy["derived"]["ocsf_schema"] = ocsf_schema
    raw_copy["derived"]["ocsf_version"] = ocsf_version or (ocsf_copy.get("metadata") or {}).get("version")

    raw_bytes = canonicalize_json(raw_copy)
    raw_hash = hash_sha256_hex(raw_bytes)
    ids = raw_copy.get("ids") or {}
    ocsf_copy.setdefault("forensics", {})
    ocsf_copy["forensics"].update(
        {
            "evidence_id": _evidence_id(raw_copy),
            "raw_envelope_hash": raw_hash,
            "raw_record_id": ids.get("record_id"),
            "source": _raw_source(raw_copy),
        }
    )

    evidence_commit = compute_evidence_commit(
        raw_copy,
        ocsf_copy,
        ocsf_schema=ocsf_schema,
        ocsf_version=ocsf_version,
        hashed_utc=hashed_utc,
        raw_hash_sha256=raw_hash,
        ocsf_hash_sha256=ocsf_hash,
        raw_size_bytes=len(raw_bytes),
    )
    return EvidenceHashResult(
        raw_envelope=raw_copy,
        ocsf_event=ocsf_copy,
        evidence_commit=evidence_commit,
    )
