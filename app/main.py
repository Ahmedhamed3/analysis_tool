import asyncio
import json
import urllib.parse
import urllib.request
from html import escape
from string import Template
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.correlation.process_chain import build_process_chains
from app.conversion import (
    SOURCE_PIPELINES,
    convert_events_to_ocsf_jsonl,
    convert_events_with_source_to_ocsf_jsonl,
)
from app.detect import auto_detect_source, summarize_event_detection
from app.formats.reader import iter_events_from_upload
from app.plugins.azure_ad_signin.detect import score_events as score_azure_ad_signin
from app.plugins.file_artifact.detect import score_events as score_file_artifact
from app.plugins.suricata.detect import score_events as score_suricata
from app.plugins.sysmon.detect import score_events as score_sysmon
from app.plugins.windows_security.detect import score_events as score_windows_security
from app.plugins.zeek.detect import score_events as score_zeek
from app.plugins.zeek_http.detect import score_events as score_zeek_http
from app.plugins.proxy_http.detect import score_events as score_proxy_http
from app.ui.highlight import (
    collect_unmapped_original_events,
    extract_values,
    highlight_json_text,
)

app = FastAPI(
    title="Log → OCSF Converter (MVP)",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
DETECTION_SAMPLE_SIZE = 10
DETECTION_THRESHOLD = 0.6

SOURCE_SCORERS = {
    "azure_ad_signin": score_azure_ad_signin,
    "sysmon": score_sysmon,
    "zeek": score_zeek,
    "zeek_http": score_zeek_http,
    "suricata": score_suricata,
    "windows-security": score_windows_security,
    "file-artifact": score_file_artifact,
    "proxy_http": score_proxy_http,
}

SOURCE_OPTIONS = [
    ("auto", "Auto Detect"),
    ("sysmon", "Sysmon"),
    ("azure_ad_signin", "Azure AD Sign-In"),
    ("zeek", "Zeek DNS"),
    ("zeek_http", "Zeek HTTP"),
    ("suricata", "Suricata Alerts"),
    ("windows-security", "Windows Security"),
    ("file-artifact", "File Artifact"),
    ("proxy_http", "Proxy HTTP"),
]

HTML_PAGE_TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Log → OCSF Converter</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin: 24px;
        color: #1f2933;
        background: #f8f9fb;
      }
      .controls {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        align-items: center;
        margin-bottom: 16px;
      }
      select {
        padding: 6px 10px;
        border-radius: 6px;
        border: 1px solid #cbd2d9;
        background: #fff;
      }
      button {
        padding: 8px 12px;
        border-radius: 6px;
        border: 1px solid #cbd2d9;
        background: #fff;
        cursor: pointer;
      }
      button.primary {
        background: #2563eb;
        border-color: #2563eb;
        color: #fff;
      }
      button.toggle-on {
        background: #16a34a;
        border-color: #16a34a;
        color: #fff;
      }
      .live-controls {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .hl {
        padding: 0 2px;
        border-radius: 4px;
      }
      .status-note {
        font-size: 12px;
        color: #52606d;
      }
      .pane-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 16px;
      }
      .detect-panel {
        background: #fff;
        border: 1px solid #e4e7eb;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 16px;
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .detect-panel h3 {
        margin: 0;
        font-size: 13px;
        text-transform: uppercase;
        color: #52606d;
        letter-spacing: 0.04em;
      }
      .detect-row {
        font-size: 13px;
        color: #1f2933;
      }
      .pane {
        background: #fff;
        border: 1px solid #e4e7eb;
        border-radius: 8px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        min-height: 360px;
      }
      .pane h2 {
        font-size: 14px;
        margin: 0 0 8px 0;
        color: #52606d;
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }
      pre {
        flex: 1;
        margin: 0;
        padding: 12px;
        background: #0f172a;
        color: #e2e8f0;
        border-radius: 6px;
        overflow: auto;
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        font-size: 12px;
        white-space: pre-wrap;
        word-break: break-word;
      }
    </style>
  </head>
  <body>
    <form class="controls" method="post" action="/" enctype="multipart/form-data">
      <input type="file" id="fileInput" name="file" required />
      <select id="sourceSelect" name="source">
        $source_options
      </select>
      <label>
        <input type="checkbox" name="highlight" value="1" $highlight_checked />
        Highlight mappings/values
      </label>
      <button class="primary" id="previewBtn" type="submit">Convert</button>
      <div class="live-controls">
        <button type="button" id="liveToggle">Live Sysmon: OFF</button>
        <label for="liveLimit">
          Live limit
          <select id="liveLimit">
            <option value="20">20</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
          </select>
        </label>
      </div>
    </form>
    <div class="detect-panel" id="detectPanel">
      <h3>Detection</h3>
      <div class="detect-row" id="detectSource">Source: $detect_source</div>
      <div class="detect-row" id="detectConfidence">Confidence: $detect_confidence</div>
      <div class="detect-row" id="detectReason">Reason: $detect_reason</div>
      <div class="detect-row" id="detectBreakdown">Breakdown: $detect_breakdown</div>
    </div>
    <div class="detect-panel" id="connectorStatusPanel">
      <h3>Connector Status</h3>
      <div class="detect-row" id="sysmonLastRecord">Last record id: —</div>
      <div class="detect-row" id="sysmonEventsWritten">Events written total: —</div>
      <div class="detect-row" id="sysmonLastBatch">Last batch count: —</div>
      <div class="detect-row" id="sysmonLastEventTime">Last event time (UTC): —</div>
      <div class="detect-row" id="sysmonLastError">Last error: —</div>
      <div class="status-note" id="sysmonStatusMessage"></div>
    </div>
    <div class="pane-grid">
      <div class="pane">
        <h2>Original Logs</h2>
        <pre id="originalPane">$original_text</pre>
      </div>
      <div class="pane">
        <h2>Unified Logs (OCSF)</h2>
        <pre id="unifiedPane">$unified_text</pre>
      </div>
    </div>
    <script>
      const sysmonState = {
        enabled: false,
        timerId: null,
      };
      const liveToggle = document.getElementById("liveToggle");
      const liveLimit = document.getElementById("liveLimit");
      const originalPane = document.getElementById("originalPane");
      const statusMessage = document.getElementById("sysmonStatusMessage");
      const statusFields = {
        last_record_id: document.getElementById("sysmonLastRecord"),
        events_written_total: document.getElementById("sysmonEventsWritten"),
        last_batch_count: document.getElementById("sysmonLastBatch"),
        last_event_time_utc: document.getElementById("sysmonLastEventTime"),
        last_error: document.getElementById("sysmonLastError"),
      };

      function setStatusMessage(message) {
        statusMessage.textContent = message || "";
      }

      function updateStatusFields(data) {
        statusFields.last_record_id.textContent = `Last record id: ${data?.last_record_id ?? "—"}`;
        statusFields.events_written_total.textContent = `Events written total: ${
          data?.events_written_total ?? "—"
        }`;
        statusFields.last_batch_count.textContent = `Last batch count: ${data?.last_batch_count ?? "—"}`;
        statusFields.last_event_time_utc.textContent = `Last event time (UTC): ${
          data?.last_event_time_utc ?? "—"
        }`;
        statusFields.last_error.textContent = `Last error: ${data?.last_error ?? "—"}`;
      }

      function renderTailEvents(events) {
        if (!Array.isArray(events) || events.length === 0) {
          return "No Sysmon events returned yet.";
        }
        return events.map((ev) => JSON.stringify(ev)).join("\\n");
      }

      async function fetchJson(url) {
        const response = await fetch(url, { method: "GET" });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      }

      async function pollSysmon() {
        const limit = liveLimit.value || "50";
        try {
          const [statusData, tailData] = await Promise.all([
            fetchJson("/api/sysmon/status"),
            fetchJson(`/api/sysmon/tail?limit=${encodeURIComponent(limit)}`),
          ]);
          updateStatusFields(statusData);
          setStatusMessage("");
          originalPane.textContent = renderTailEvents(tailData);
        } catch (error) {
          const message = "Sysmon connector not running. Start it with --http-port 8787.";
          setStatusMessage(message);
          originalPane.textContent = message;
        }
      }

      function setLiveState(enabled) {
        sysmonState.enabled = enabled;
        if (enabled) {
          liveToggle.textContent = "Live Sysmon: ON";
          liveToggle.classList.add("toggle-on");
          pollSysmon();
          sysmonState.timerId = setInterval(pollSysmon, 2000);
        } else {
          liveToggle.textContent = "Live Sysmon: OFF";
          liveToggle.classList.remove("toggle-on");
          if (sysmonState.timerId) {
            clearInterval(sysmonState.timerId);
            sysmonState.timerId = null;
          }
        }
      }

      liveToggle.addEventListener("click", () => {
        setLiveState(!sysmonState.enabled);
      });
    </script>
  </body>
</html>
"""
)


def _build_source_options(selected_source: str) -> str:
    options = []
    for value, label in SOURCE_OPTIONS:
        selected = " selected" if value == selected_source else ""
        options.append(f'<option value="{value}"{selected}>{label}</option>')
    return "\n        ".join(options)


def _format_confidence(confidence: Optional[float]) -> str:
    if confidence is None:
        return "—"
    return f"{confidence:.2f}"


def _render_index(
    *,
    detection: Optional[Dict[str, Any]] = None,
    original_html: str = "",
    unified_html: str = "",
    error_message: Optional[str] = None,
    selected_source: str = "auto",
    highlight_enabled: bool = False,
) -> str:
    if not detection:
        detect_source = "—"
        detect_confidence = "—"
        detect_reason = "—"
        detect_breakdown = "—"
    else:
        detect_source = detection.get("source_type") or "unknown"
        confidence = detection.get("confidence")
        detect_confidence = _format_confidence(confidence if isinstance(confidence, (int, float)) else None)
        reason_text = detection.get("reason") or "—"
        if error_message:
            reason_text = f"{reason_text} ({error_message})"
        detect_reason = reason_text
        breakdown = detection.get("breakdown")
        if isinstance(breakdown, list) and breakdown:
            breakdown_lines = []
            for item in breakdown:
                source = item.get("source", "unknown")
                count = item.get("count", 0)
                total = item.get("total", 0)
                ratio = item.get("ratio", 0)
                ratio_text = f"{ratio:.2f}" if isinstance(ratio, (int, float)) else "0.00"
                breakdown_lines.append(f"{source}: {count}/{total} ({ratio_text})")
            detect_breakdown = ", ".join(breakdown_lines)
        else:
            detect_breakdown = "—"
    return HTML_PAGE_TEMPLATE.safe_substitute(
        source_options=_build_source_options(selected_source),
        detect_source=escape(str(detect_source)),
        detect_confidence=escape(str(detect_confidence)),
        detect_reason=escape(str(detect_reason)),
        detect_breakdown=escape(str(detect_breakdown)),
        original_text=original_html,
        unified_text=unified_html,
        highlight_checked="checked" if highlight_enabled else "",
    )


def _pretty_json(obj: Any) -> str:
    if isinstance(obj, list) and len(obj) == 1:
        obj = obj[0]
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _parse_ocsf_json_lines(lines: List[str]) -> Optional[Any]:
    objects: List[Any] = []
    for line in lines:
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not objects:
        return None
    if len(objects) == 1:
        return objects[0]
    return objects


@app.get("/", response_class=HTMLResponse)
async def index():
    return _render_index()


@app.post("/", response_class=HTMLResponse)
async def index_post(
    file: UploadFile = File(...),
    source: str = Form("auto"),
    highlight: Optional[str] = Form(None),
):
    upload = await _read_upload(file)
    error_message = None
    if source == "auto":
        detection = summarize_event_detection(
            upload["events"],
            threshold=DETECTION_THRESHOLD,
        )
        detection["auto"] = True
        unified_lines = list(
            convert_events_to_ocsf_jsonl(upload["events"], threshold=DETECTION_THRESHOLD)
        )
        if detection.get("source_type") == "unknown":
            error_message = "Unable to confidently auto-detect source."
    else:
        _validate_selected_source(source, upload["events"])
        unified_lines = list(
            convert_events_with_source_to_ocsf_jsonl(
                upload["events"],
                source_type=source,
            )
        )
        detection = _build_detection_payload(
            source,
            auto=False,
            reason="Selected manually.",
        )
    highlight_enabled = highlight is not None
    original_json = _pretty_json(upload["events"])
    ocsf_objects = _parse_ocsf_json_lines(unified_lines)
    if ocsf_objects is None:
        unified_json = "\n".join(unified_lines)
    else:
        unified_json = _pretty_json(ocsf_objects)
    if highlight_enabled and ocsf_objects is not None:
        original_values = extract_values(upload["events"])
        ocsf_values = extract_values(ocsf_objects)
        shared_values = original_values & ocsf_values
        preserve_values = collect_unmapped_original_events(ocsf_objects)
        original_panel_html = highlight_json_text(original_json, shared_values)
        unified_panel_html = highlight_json_text(
            unified_json,
            shared_values,
            preserve_values=preserve_values,
        )
    else:
        original_panel_html = escape(original_json)
        unified_panel_html = escape(unified_json)
    return _render_index(
        detection=detection,
        original_html=original_panel_html,
        unified_html=unified_panel_html,
        error_message=error_message,
        selected_source=source,
        highlight_enabled=highlight_enabled,
    )


async def _read_upload(file: UploadFile) -> Dict[str, Any]:
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
    events = list(iter_events_from_upload(content))
    if not events:
        raise HTTPException(status_code=400, detail="No events found in upload.")
    original_text = content.decode("utf-8-sig", errors="replace")
    return {"content": content, "events": events, "original_text": original_text}


def _validate_selected_source(source_type: str, events: List[dict]) -> Dict[str, Any]:
    scorer = SOURCE_SCORERS.get(source_type)
    if not scorer:
        raise HTTPException(status_code=400, detail=f"Unknown source type: {source_type}.")
    confidence, reason = scorer(events[:DETECTION_SAMPLE_SIZE])
    if confidence < DETECTION_THRESHOLD:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Unsupported file or not detected as {source_type}.",
                "confidence": confidence,
                "reason": reason,
            },
        )
    return {"confidence": confidence, "reason": reason}


def _get_converter(source_type: str):
    converter = SOURCE_PIPELINES.get(source_type)
    if not converter:
        raise HTTPException(status_code=400, detail=f"Unknown source type: {source_type}.")
    return converter


def _build_detection_payload(
    source_type: str,
    *,
    auto: bool,
    confidence: Optional[float] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "source_type": source_type,
        "confidence": confidence,
        "reason": reason or "—",
        "auto": auto,
    }


def _extract_actor_process(event: Dict[str, Any]) -> Dict[str, Any]:
    actor = event.get("actor", {})
    if isinstance(actor, dict):
        process = actor.get("process", {})
        if isinstance(process, dict):
            return process
    return {}


def _extract_target_process(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    target = event.get("process", {})
    if not isinstance(target, dict):
        return None
    if not any(target.get(key) for key in ("uid", "executable", "command_line")):
        return None
    return {
        "uid": target.get("uid"),
        "executable": target.get("executable"),
        "command_line": target.get("command_line"),
    }


def _format_chain_event(event: Dict[str, Any]) -> Dict[str, Any]:
    actor_process = _extract_actor_process(event)
    formatted = {
        "time": event.get("time"),
        "activity_id": event.get("activity_id"),
        "type_uid": event.get("type_uid"),
        "executable": actor_process.get("executable"),
        "command_line": actor_process.get("command_line"),
    }
    target_process = _extract_target_process(event)
    if target_process:
        formatted["target_process"] = target_process
    return formatted


def _format_chain(chain) -> Dict[str, Any]:
    return {
        "process_uid": chain.process_uid,
        "parent_process_uid": chain.parent_process_uid,
        "event_count": len(chain.events),
        "events": [_format_chain_event(event) for event in chain.events],
    }


@app.post("/correlate/process-chains")
async def correlate_process_chains(events: List[Dict[str, Any]]):
    chains = build_process_chains(events)
    return JSONResponse([_format_chain(chain) for chain in chains])

def _stream_ndjson(events: List[dict], source_type: str, filename: str) -> StreamingResponse:
    return StreamingResponse(
        (
            line + "\n"
            for line in convert_events_with_source_to_ocsf_jsonl(
                events,
                source_type=source_type,
            )
        ),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _stream_auto_ndjson(events: List[dict], filename: str) -> StreamingResponse:
    return StreamingResponse(
        (line + "\n" for line in convert_events_to_ocsf_jsonl(events, threshold=DETECTION_THRESHOLD)),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _build_preview_response(
    *,
    original_text: str,
    unified_lines: List[str],
    detection: Dict[str, Any],
    error: Optional[str] = None,
) -> JSONResponse:
    payload: Dict[str, Any] = {
        "original": original_text,
        "unified_ndjson": "\n".join(unified_lines),
        "detection": detection,
    }
    if error:
        payload["error"] = error
    return JSONResponse(payload)


SYS_MON_PROXY_BASE = "http://127.0.0.1:8787"


async def _fetch_sysmon_json(path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{SYS_MON_PROXY_BASE}{path}{query}"

    def _load() -> bytes:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.read()

    try:
        payload = await asyncio.to_thread(_load)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Sysmon connector not reachable.",
        ) from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail="Sysmon connector returned invalid JSON.",
        ) from exc


@app.get("/api/sysmon/status")
async def sysmon_status_proxy():
    return JSONResponse(await _fetch_sysmon_json("/status"))


@app.get("/api/sysmon/tail")
async def sysmon_tail_proxy(limit: int = 50):
    safe_limit = max(1, min(limit, 1000))
    return JSONResponse(await _fetch_sysmon_json("/tail", {"limit": safe_limit}))


@app.post("/convert/sysmon")
async def convert_sysmon(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("sysmon", upload["events"])
    return _stream_ndjson(upload["events"], "sysmon", "output.ocsf.jsonl")


@app.post("/convert/sysmon/preview")
async def convert_sysmon_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("sysmon", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="sysmon",
        )
    )
    detection = _build_detection_payload(
        "sysmon",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/zeek")
async def convert_zeek(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("zeek", upload["events"])
    return _stream_ndjson(upload["events"], "zeek", "output.zeek.ocsf.jsonl")


@app.post("/convert/zeek/preview")
async def convert_zeek_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("zeek", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="zeek",
        )
    )
    detection = _build_detection_payload(
        "zeek",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/zeek_http")
async def convert_zeek_http(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("zeek_http", upload["events"])
    return _stream_ndjson(upload["events"], "zeek_http", "output.zeek_http.ocsf.jsonl")


@app.post("/convert/zeek_http/preview")
async def convert_zeek_http_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("zeek_http", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="zeek_http",
        )
    )
    detection = _build_detection_payload(
        "zeek_http",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/suricata")
async def convert_suricata(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("suricata", upload["events"])
    return _stream_ndjson(upload["events"], "suricata", "output.suricata.ocsf.jsonl")


@app.post("/convert/suricata/preview")
async def convert_suricata_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("suricata", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="suricata",
        )
    )
    detection = _build_detection_payload(
        "suricata",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/windows-security")
async def convert_windows_security(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("windows-security", upload["events"])
    return _stream_ndjson(
        upload["events"],
        "windows-security",
        "output.windows-security.ocsf.jsonl",
    )


@app.post("/convert/windows-security/preview")
async def convert_windows_security_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("windows-security", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="windows-security",
        )
    )
    detection = _build_detection_payload(
        "windows-security",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/file-artifact")
async def convert_file_artifact(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("file-artifact", upload["events"])
    return _stream_ndjson(
        upload["events"],
        "file-artifact",
        "output.file-artifact.ocsf.jsonl",
    )


@app.post("/convert/file-artifact/preview")
async def convert_file_artifact_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("file-artifact", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="file-artifact",
        )
    )
    detection = _build_detection_payload(
        "file-artifact",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/proxy_http")
async def convert_proxy_http(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("proxy_http", upload["events"])
    return _stream_ndjson(upload["events"], "proxy_http", "output.proxy_http.ocsf.jsonl")


@app.post("/convert/proxy_http/preview")
async def convert_proxy_http_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("proxy_http", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="proxy_http",
        )
    )
    detection = _build_detection_payload(
        "proxy_http",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/auto")
async def convert_auto(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    detection = auto_detect_source(
        upload["events"][:DETECTION_SAMPLE_SIZE],
        threshold=DETECTION_THRESHOLD,
    )
    detection["auto"] = True
    return _stream_auto_ndjson(upload["events"], "output.auto.ocsf.jsonl")


@app.post("/convert/auto/preview")
async def convert_auto_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    detection = summarize_event_detection(
        upload["events"],
        threshold=DETECTION_THRESHOLD,
    )
    detection["auto"] = True
    unified_lines = list(
        convert_events_to_ocsf_jsonl(upload["events"], threshold=DETECTION_THRESHOLD)
    )
    error = None
    if detection["source_type"] == "unknown":
        error = "Unable to confidently auto-detect source."
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
        error=error,
    )
