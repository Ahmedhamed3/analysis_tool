from typing import Any, Dict, List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.correlation.process_chain import build_process_chains
from app.detect import auto_detect_source
from app.formats.reader import iter_events_from_upload
from app.plugins.file_artifact.detect import score_events as score_file_artifact
from app.plugins.file_artifact.pipeline import convert_file_artifact_events_to_ocsf_jsonl
from app.plugins.suricata.detect import score_events as score_suricata
from app.plugins.suricata.pipeline import convert_suricata_events_to_ocsf_jsonl
from app.plugins.sysmon.detect import score_events as score_sysmon
from app.plugins.sysmon.pipeline import convert_sysmon_events_to_ocsf_jsonl
from app.plugins.windows_security.detect import score_events as score_windows_security
from app.plugins.windows_security.pipeline import convert_windows_security_events_to_ocsf_jsonl
from app.plugins.zeek.detect import score_events as score_zeek
from app.plugins.zeek.pipeline import convert_zeek_dns_events_to_ocsf_jsonl

app = FastAPI(
    title="Log → OCSF Converter (MVP)",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
DETECTION_SAMPLE_SIZE = 10
DETECTION_THRESHOLD = 0.6

SOURCE_PIPELINES = {
    "sysmon": convert_sysmon_events_to_ocsf_jsonl,
    "zeek": convert_zeek_dns_events_to_ocsf_jsonl,
    "suricata": convert_suricata_events_to_ocsf_jsonl,
    "windows-security": convert_windows_security_events_to_ocsf_jsonl,
    "file-artifact": convert_file_artifact_events_to_ocsf_jsonl,
}

SOURCE_SCORERS = {
    "sysmon": score_sysmon,
    "zeek": score_zeek,
    "suricata": score_suricata,
    "windows-security": score_windows_security,
    "file-artifact": score_file_artifact,
}

HTML_PAGE = """<!doctype html>
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
      .panel-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }
      .chain-results {
        flex: 1;
        overflow: auto;
        padding-right: 4px;
      }
      .chain-card {
        border: 1px solid #e4e7eb;
        border-radius: 8px;
        padding: 8px 12px;
        background: #f9fafb;
        margin-bottom: 12px;
      }
      .chain-card summary {
        cursor: pointer;
        font-weight: 600;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .chain-meta {
        font-size: 12px;
        color: #52606d;
      }
      .chain-events {
        list-style: none;
        padding: 0;
        margin: 12px 0 0 0;
        display: flex;
        flex-direction: column;
        gap: 10px;
      }
      .chain-event {
        border-left: 3px solid #2563eb;
        padding-left: 10px;
        font-size: 12px;
      }
      .chain-event strong {
        font-size: 13px;
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
    <div class="controls">
      <input type="file" id="fileInput" />
      <select id="sourceSelect">
        <option value="auto">Auto Detect</option>
        <option value="sysmon">Sysmon</option>
        <option value="zeek">Zeek DNS</option>
        <option value="suricata">Suricata Alerts</option>
        <option value="windows-security">Windows Security</option>
        <option value="file-artifact">File Artifact</option>
      </select>
      <button class="primary" id="previewBtn">Convert</button>
    </div>
    <div class="detect-panel" id="detectPanel">
      <h3>Detection</h3>
      <div class="detect-row" id="detectSource">Source: —</div>
      <div class="detect-row" id="detectConfidence">Confidence: —</div>
      <div class="detect-row" id="detectReason">Reason: —</div>
    </div>
    <div class="pane-grid">
      <div class="pane">
        <h2>Original Logs</h2>
        <pre id="originalPane"></pre>
      </div>
      <div class="pane">
        <h2>Unified Logs (OCSF)</h2>
        <pre id="unifiedPane"></pre>
      </div>
      <div class="pane">
        <div class="panel-header">
          <h2>Process Behavior Chains</h2>
          <button id="correlateBtn">Correlate Processes</button>
        </div>
        <div class="chain-results" id="chainsContainer"></div>
      </div>
    </div>
    <script>
      const fileInput = document.getElementById("fileInput");
      const previewBtn = document.getElementById("previewBtn");
      const correlateBtn = document.getElementById("correlateBtn");
      const sourceSelect = document.getElementById("sourceSelect");
      const originalPane = document.getElementById("originalPane");
      const unifiedPane = document.getElementById("unifiedPane");
      const chainsContainer = document.getElementById("chainsContainer");
      const detectSource = document.getElementById("detectSource");
      const detectConfidence = document.getElementById("detectConfidence");
      const detectReason = document.getElementById("detectReason");
      let cachedOcsfEvents = [];

      function parseNdjson(value) {
        if (!value) {
          return [];
        }
        const lines = value.split("\\n").map((line) => line.trim()).filter(Boolean);
        const events = [];
        for (const line of lines) {
          try {
            events.push(JSON.parse(line));
          } catch (error) {
            console.warn("Failed to parse line", error);
          }
        }
        return events;
      }

      function renderChains(chains) {
        chainsContainer.innerHTML = "";
        if (!chains || chains.length === 0) {
          const empty = document.createElement("div");
          empty.textContent = "No process chains to display.";
          empty.className = "chain-meta";
          chainsContainer.appendChild(empty);
          return;
        }
        chains.forEach((chain) => {
          const details = document.createElement("details");
          details.className = "chain-card";
          details.open = true;

          const summary = document.createElement("summary");
          summary.innerHTML = `<span>${chain.process_uid}</span>`;

          const meta = document.createElement("span");
          meta.className = "chain-meta";
          const parent = chain.parent_process_uid ? chain.parent_process_uid : "None";
          meta.textContent = `Parent: ${parent} · Events: ${chain.event_count}`;
          summary.appendChild(meta);

          details.appendChild(summary);

          const list = document.createElement("ul");
          list.className = "chain-events";

          chain.events.forEach((event) => {
            const item = document.createElement("li");
            item.className = "chain-event";
            const activity = event.activity_id ?? "n/a";
            const typeUid = event.type_uid ?? "n/a";
            const command = event.command_line ? event.command_line : "—";
            const executable = event.executable ? event.executable : "Unknown executable";
            const time = event.time ? event.time : "Unknown time";
            const target = event.target_process
              ? `Target: ${event.target_process.executable || "Unknown"} (${event.target_process.uid || "n/a"})`
              : "";

            item.innerHTML = `
              <div><strong>${time}</strong> · Activity ${activity} / Type ${typeUid}</div>
              <div>${executable}</div>
              <div>${command}</div>
              ${target ? `<div>${target}</div>` : ""}
            `;
            list.appendChild(item);
          });

          details.appendChild(list);
          chainsContainer.appendChild(details);
        });
      }

      function updateDetectionPanel(detection, errorMessage) {
        if (!detection) {
          detectSource.textContent = "Source: —";
          detectConfidence.textContent = "Confidence: —";
          detectReason.textContent = "Reason: —";
          return;
        }
        detectSource.textContent = `Source: ${detection.source_type || "unknown"}`;
        if (detection.auto && typeof detection.confidence === "number") {
          detectConfidence.textContent = `Confidence: ${detection.confidence.toFixed(2)}`;
        } else {
          detectConfidence.textContent = "Confidence: —";
        }
        const reasonText = detection.reason ? detection.reason : "—";
        detectReason.textContent = `Reason: ${reasonText}${errorMessage ? ` (${errorMessage})` : ""}`;
      }

      async function postPreview() {
        const file = fileInput.files[0];
        if (!file) {
          return;
        }
        const formData = new FormData();
        formData.append("file", file);
        let endpoint = "/convert/sysmon/preview";
        if (sourceSelect.value === "auto") {
          endpoint = "/convert/auto/preview";
        } else if (sourceSelect.value === "zeek") {
          endpoint = "/convert/zeek/preview";
        } else if (sourceSelect.value === "suricata") {
          endpoint = "/convert/suricata/preview";
        } else if (sourceSelect.value === "windows-security") {
          endpoint = "/convert/windows-security/preview";
        } else if (sourceSelect.value === "file-artifact") {
          endpoint = "/convert/file-artifact/preview";
        }
        const response = await fetch(endpoint, {
          method: "POST",
          body: formData,
        });
        if (!response.ok) {
          const detail = await response.text();
          originalPane.textContent = detail;
          unifiedPane.textContent = "";
          cachedOcsfEvents = [];
          updateDetectionPanel(null, null);
          return;
        }
        const data = await response.json();
        originalPane.textContent = data.original;
        unifiedPane.textContent = data.unified_ndjson || "";
        cachedOcsfEvents = parseNdjson(data.unified_ndjson || "");
        updateDetectionPanel(data.detection, data.error);
        renderChains([]);
      }

      async function correlateProcesses() {
        if (!cachedOcsfEvents.length) {
          renderChains([]);
          return;
        }
        const response = await fetch("/correlate/process-chains", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(cachedOcsfEvents),
        });
        if (!response.ok) {
          const detail = await response.text();
          chainsContainer.textContent = detail;
          return;
        }
        const data = await response.json();
        renderChains(data);
      }

      previewBtn.addEventListener("click", postPreview);
      correlateBtn.addEventListener("click", correlateProcesses);
    </script>
  </body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_PAGE


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
    converter = _get_converter(source_type)
    return StreamingResponse(
        (line + "\n" for line in converter(events)),
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


@app.post("/convert/sysmon")
async def convert_sysmon(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("sysmon", upload["events"])
    return _stream_ndjson(upload["events"], "sysmon", "output.ocsf.jsonl")


@app.post("/convert/sysmon/preview")
async def convert_sysmon_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("sysmon", upload["events"])
    unified_lines = list(convert_sysmon_events_to_ocsf_jsonl(upload["events"]))
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
    unified_lines = list(convert_zeek_dns_events_to_ocsf_jsonl(upload["events"]))
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


@app.post("/convert/suricata")
async def convert_suricata(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("suricata", upload["events"])
    return _stream_ndjson(upload["events"], "suricata", "output.suricata.ocsf.jsonl")


@app.post("/convert/suricata/preview")
async def convert_suricata_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("suricata", upload["events"])
    unified_lines = list(convert_suricata_events_to_ocsf_jsonl(upload["events"]))
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
    unified_lines = list(convert_windows_security_events_to_ocsf_jsonl(upload["events"]))
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
    unified_lines = list(convert_file_artifact_events_to_ocsf_jsonl(upload["events"]))
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


@app.post("/convert/auto")
async def convert_auto(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    detection = auto_detect_source(
        upload["events"][:DETECTION_SAMPLE_SIZE],
        threshold=DETECTION_THRESHOLD,
    )
    detection["auto"] = True
    if detection["source_type"] == "unknown":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Unable to confidently auto-detect source.",
                "detection": detection,
            },
        )
    return _stream_ndjson(
        upload["events"],
        detection["source_type"],
        "output.auto.ocsf.jsonl",
    )


@app.post("/convert/auto/preview")
async def convert_auto_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    detection = auto_detect_source(
        upload["events"][:DETECTION_SAMPLE_SIZE],
        threshold=DETECTION_THRESHOLD,
    )
    detection["auto"] = True
    if detection["source_type"] == "unknown":
        return _build_preview_response(
            original_text=upload["original_text"],
            unified_lines=[],
            detection=detection,
            error="Unable to confidently auto-detect source.",
        )
    converter = _get_converter(detection["source_type"])
    unified_lines = list(converter(upload["events"]))
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )
