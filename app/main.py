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
        tmp_path = tmp.name

    try:
        if not detect_sysmon_json(tmp_path):
            raise HTTPException(status_code=400, detail="Unsupported file or not detected as Sysmon JSON.")

        gen = convert_sysmon_file_to_ocsf_jsonl(tmp_path)
        # Stream as NDJSON/JSONL
        return StreamingResponse(
            (line + "\n" for line in gen),
            media_type="application/x-ndjson",
            headers={"Content-Disposition": "attachment; filename=output.ocsf.jsonl"},
        )
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
