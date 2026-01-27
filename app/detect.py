from typing import Dict, List

from app.plugins.file_artifact.detect import score_events as score_file_artifact
from app.plugins.suricata.detect import score_events as score_suricata
from app.plugins.sysmon.detect import score_events as score_sysmon
from app.plugins.windows_security.detect import score_events as score_windows_security
from app.plugins.zeek.detect import score_events as score_zeek


SCORE_FUNCS = {
    "windows-security": score_windows_security,
    "sysmon": score_sysmon,
    "suricata": score_suricata,
    "zeek": score_zeek,
    "file-artifact": score_file_artifact,
}


def auto_detect_source(
    events: List[dict],
    *,
    threshold: float = 0.6,
) -> Dict[str, object]:
    if not events:
        return {
            "source_type": "unknown",
            "confidence": 0.0,
            "reason": "No events provided for detection.",
        }

    scored = []
    for source_type, scorer in SCORE_FUNCS.items():
        confidence, reason = scorer(events)
        scored.append((source_type, confidence, reason))

    best_source, best_confidence, best_reason = max(scored, key=lambda item: item[1])

    if best_confidence < threshold:
        return {
            "source_type": "unknown",
            "confidence": best_confidence,
            "reason": (
                f"Low confidence. Best guess: {best_source}. {best_reason}"
            ),
        }

    return {
        "source_type": best_source,
        "confidence": best_confidence,
        "reason": best_reason,
    }
