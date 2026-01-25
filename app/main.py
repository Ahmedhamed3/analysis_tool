import os
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.plugins.sysmon.detect import detect_sysmon_json
from app.plugins.sysmon.pipeline import convert_sysmon_file_to_ocsf_jsonl

app = FastAPI(
    title="Sysmon → OCSF Converter (MVP)",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

HTML_PAGE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sysmon → OCSF Converter</title>
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
    </div>
    <script>
      const fileInput = document.getElementById("fileInput");
      const previewBtn = document.getElementById("previewBtn");
      const originalPane = document.getElementById("originalPane");
      const unifiedPane = document.getElementById("unifiedPane");

      async function postPreview() {
        const file = fileInput.files[0];
        if (!file) {
          return;
        }
        const formData = new FormData();
        formData.append("file", file);
        const response = await fetch("/convert/sysmon/preview", {
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
      }

      previewBtn.addEventListener("click", postPreview);
    </script>
  </body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_PAGE

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
