import os
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.correlation.process_chain import build_process_chains
from app.plugins.sysmon.detect import detect_sysmon_json
from app.plugins.sysmon.pipeline import convert_sysmon_file_to_ocsf_jsonl
from app.plugins.suricata.detect import detect_suricata_eve_json
from app.plugins.suricata.pipeline import convert_suricata_file_to_ocsf_jsonl
from app.plugins.zeek.detect import detect_zeek_dns_json
from app.plugins.zeek.pipeline import convert_zeek_dns_file_to_ocsf_jsonl
from app.plugins.windows_security.detect import detect_windows_security_json
from app.plugins.windows_security.pipeline import convert_windows_security_file_to_ocsf_jsonl
from app.plugins.file_artifact.detect import detect_file_artifact_json
from app.plugins.file_artifact.pipeline import convert_file_artifact_file_to_ocsf_jsonl

app = FastAPI(
    title="Log → OCSF Converter (MVP)",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

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
        <option value="sysmon">Sysmon</option>
        <option value="zeek">Zeek DNS</option>
        <option value="suricata">Suricata Alerts</option>
        <option value="windows-security">Windows Security</option>
        <option value="file-artifact">File Artifact</option>
      </select>
      <button class="primary" id="previewBtn">Convert</button>
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

      async function postPreview() {
        const file = fileInput.files[0];
        if (!file) {
          return;
        }
        const formData = new FormData();
        formData.append("file", file);
        let endpoint = "/convert/sysmon/preview";
        if (sourceSelect.value === "zeek") {
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
          return;
        }
        const data = await response.json();
        originalPane.textContent = data.original;
        unifiedPane.textContent = data.unified_ndjson;
        cachedOcsfEvents = parseNdjson(data.unified_ndjson);
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

@app.post("/convert/sysmon")
async def convert_sysmon(file: UploadFile = File(...)):
    # Save upload temporarily
    suffix = os.path.splitext(file.filename or "")[1] or ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        # basic size guard (50MB)
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_sysmon_json(tmp_path):
        preview_bytes = content[:200]
        preview = preview_bytes.decode("utf-8-sig", errors="replace").strip()
        detail = {
            "error": "Unsupported file or not detected as Sysmon JSON.",
            "filename": file.filename,
            "suffix": suffix,
            "preview": preview,
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    def _line_gen():
        try:
            yield from convert_sysmon_file_to_ocsf_jsonl(tmp_path)
        finally:
            _cleanup()

    # Stream as NDJSON/JSONL
    return StreamingResponse(
        (line + "\n" for line in _line_gen()),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=output.ocsf.jsonl"},
    )


@app.post("/convert/sysmon/preview")
async def convert_sysmon_preview(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name
    original_text = content.decode("utf-8-sig", errors="replace")

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_sysmon_json(tmp_path):
        detail = {
            "error": "Unsupported file or not detected as Sysmon JSON.",
            "filename": file.filename,
            "preview": original_text.strip(),
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    try:
        unified_lines = list(convert_sysmon_file_to_ocsf_jsonl(tmp_path))
        unified_text = "\n".join(unified_lines)
        return JSONResponse(
            {
                "original": original_text,
                "unified_ndjson": unified_text,
            }
        )
    finally:
        _cleanup()


@app.post("/convert/zeek")
async def convert_zeek(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".log"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_zeek_dns_json(tmp_path):
        preview_bytes = content[:200]
        preview = preview_bytes.decode("utf-8-sig", errors="replace").strip()
        detail = {
            "error": "Unsupported file or not detected as Zeek DNS JSONL.",
            "filename": file.filename,
            "suffix": suffix,
            "preview": preview,
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    def _line_gen():
        try:
            yield from convert_zeek_dns_file_to_ocsf_jsonl(tmp_path)
        finally:
            _cleanup()

    return StreamingResponse(
        (line + "\n" for line in _line_gen()),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=output.zeek.ocsf.jsonl"},
    )


@app.post("/convert/zeek/preview")
async def convert_zeek_preview(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".log"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name
    original_text = content.decode("utf-8-sig", errors="replace")

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_zeek_dns_json(tmp_path):
        detail = {
            "error": "Unsupported file or not detected as Zeek DNS JSONL.",
            "filename": file.filename,
            "preview": original_text.strip(),
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    try:
        unified_lines = list(convert_zeek_dns_file_to_ocsf_jsonl(tmp_path))
        unified_text = "\n".join(unified_lines)
        return JSONResponse(
            {
                "original": original_text,
                "unified_ndjson": unified_text,
            }
        )
    finally:
        _cleanup()


@app.post("/convert/suricata")
async def convert_suricata(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_suricata_eve_json(tmp_path):
        preview_bytes = content[:200]
        preview = preview_bytes.decode("utf-8-sig", errors="replace").strip()
        detail = {
            "error": "Unsupported file or not detected as Suricata eve.json JSONL.",
            "filename": file.filename,
            "suffix": suffix,
            "preview": preview,
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    def _line_gen():
        try:
            yield from convert_suricata_file_to_ocsf_jsonl(tmp_path)
        finally:
            _cleanup()

    return StreamingResponse(
        (line + "\n" for line in _line_gen()),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=output.suricata.ocsf.jsonl"},
    )


@app.post("/convert/suricata/preview")
async def convert_suricata_preview(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name
    original_text = content.decode("utf-8-sig", errors="replace")

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_suricata_eve_json(tmp_path):
        detail = {
            "error": "Unsupported file or not detected as Suricata eve.json JSONL.",
            "filename": file.filename,
            "preview": original_text.strip(),
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    try:
        unified_lines = list(convert_suricata_file_to_ocsf_jsonl(tmp_path))
        unified_text = "\n".join(unified_lines)
        return JSONResponse(
            {
                "original": original_text,
                "unified_ndjson": unified_text,
            }
        )
    finally:
        _cleanup()


@app.post("/convert/windows-security")
async def convert_windows_security(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_windows_security_json(tmp_path):
        preview_bytes = content[:200]
        preview = preview_bytes.decode("utf-8-sig", errors="replace").strip()
        detail = {
            "error": "Unsupported file or not detected as Windows Security JSON.",
            "filename": file.filename,
            "suffix": suffix,
            "preview": preview,
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    def _line_gen():
        try:
            yield from convert_windows_security_file_to_ocsf_jsonl(tmp_path)
        finally:
            _cleanup()

    return StreamingResponse(
        (line + "\n" for line in _line_gen()),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=output.windows-security.ocsf.jsonl"},
    )


@app.post("/convert/windows-security/preview")
async def convert_windows_security_preview(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name
    original_text = content.decode("utf-8-sig", errors="replace")

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_windows_security_json(tmp_path):
        detail = {
            "error": "Unsupported file or not detected as Windows Security JSON.",
            "filename": file.filename,
            "preview": original_text.strip(),
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    try:
        unified_lines = list(convert_windows_security_file_to_ocsf_jsonl(tmp_path))
        unified_text = "\n".join(unified_lines)
        return JSONResponse(
            {
                "original": original_text,
                "unified_ndjson": unified_text,
            }
        )
    finally:
        _cleanup()


@app.post("/convert/file-artifact")
async def convert_file_artifact(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_file_artifact_json(tmp_path):
        preview_bytes = content[:200]
        preview = preview_bytes.decode("utf-8-sig", errors="replace").strip()
        detail = {
            "error": "Unsupported file or not detected as File Artifact JSON.",
            "filename": file.filename,
            "suffix": suffix,
            "preview": preview,
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    def _line_gen():
        try:
            yield from convert_file_artifact_file_to_ocsf_jsonl(tmp_path)
        finally:
            _cleanup()

    return StreamingResponse(
        (line + "\n" for line in _line_gen()),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=output.file-artifact.ocsf.jsonl"},
    )


@app.post("/convert/file-artifact/preview")
async def convert_file_artifact_preview(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1] or ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
        tmp.write(content)
        tmp.flush()
        tmp_path = tmp.name
    original_text = content.decode("utf-8-sig", errors="replace")

    def _cleanup() -> None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not detect_file_artifact_json(tmp_path):
        detail = {
            "error": "Unsupported file or not detected as File Artifact JSON.",
            "filename": file.filename,
            "preview": original_text.strip(),
        }
        _cleanup()
        raise HTTPException(status_code=400, detail=detail)

    try:
        unified_lines = list(convert_file_artifact_file_to_ocsf_jsonl(tmp_path))
        unified_text = "\n".join(unified_lines)
        return JSONResponse(
            {
                "original": original_text,
                "unified_ndjson": unified_text,
            }
        )
    finally:
        _cleanup()
