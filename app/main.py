import os
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse

from app.plugins.sysmon.detect import detect_sysmon_json
from app.plugins.sysmon.pipeline import convert_sysmon_file_to_ocsf_jsonl

app = FastAPI(title="Sysmon → OCSF Converter (MVP)")

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
