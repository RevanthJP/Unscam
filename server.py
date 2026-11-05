"""Web server for Unscam: serves the page and the two check endpoints."""
import time
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import pipeline

DAILY_CAP = 300  # protects the free model quota on a shared link
MAX_AUDIO_BYTES = 4 * 1024 * 1024  # Vercel rejects request bodies over 4.5 MB
PUBLIC = Path(__file__).parent / "public"  # Vercel serves this folder directly
_usage = {"day": "", "count": 0}

app = FastAPI(title="Unscam", docs_url=None, redoc_url=None)


def _spend():
    today = time.strftime("%Y-%m-%d")
    if _usage["day"] != today:
        _usage.update(day=today, count=0)
    if _usage["count"] >= DAILY_CAP:
        raise HTTPException(429, "The demo reached its daily limit. Please try again tomorrow.")
    _usage["count"] += 1


def _public(res):
    """Only what the page needs."""
    def texts(t):
        return {
            "verdict_text": t["verdict_text"],
            "reasons": [{k: r[k] for k in ("text", "source_label", "source_tier", "source_url")} for r in t["reasons"]],
            "next_steps": t["next_steps"],
        }

    return {
        "verdict": res["verdict"],
        "lang": res["lang"],
        "can_report": res["can_report"],
        "translations": {code: texts(t) for code, t in res["translations"].items()},
        "transcript": res.get("transcript"),
        "ai_unavailable": bool(res.get("llm_error")),
    }


class TextIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@app.post("/api/check-text")
def check_text(body: TextIn):
    text = body.text.strip()
    if not text:
        raise HTTPException(400, "Please type or paste something first.")
    _spend()
    return _public(pipeline.analyze_text(text))


@app.post("/api/check-audio")
def check_audio(file: UploadFile = File(...)):
    data = file.file.read(MAX_AUDIO_BYTES + 1)
    if len(data) > MAX_AUDIO_BYTES:
        raise HTTPException(413, "That recording is too large. Please keep it under 4 MB, or type it instead.")
    if not data:
        raise HTTPException(400, "We did not receive any audio. Please try again.")
    _spend()
    try:
        res = pipeline.analyze_audio(data, filename=Path(file.filename or "clip.webm").name)
    except Exception:
        raise HTTPException(502, "We could not process that audio right now. Please try typing it instead.")
    if not res["transcript"]:
        message = ("Please tell us a little more about what happened."
                   if res.get("reason") == "too_short"
                   else "We could not hear you. Tap the mic and speak, or type it instead.")
        raise HTTPException(422, message)
    return _public(res)


@app.get("/")
def index():
    return FileResponse(PUBLIC / "index.html")


app.mount("/static", StaticFiles(directory=PUBLIC / "static", check_dir=False), name="static")
