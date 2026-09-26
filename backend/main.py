"""
main.py -- FastAPI backend for the SSH brute-force detector.

Endpoints:
  GET  /health           liveness check (Render pings this kind of thing)
  POST /predict           upload a log CSV, get back per-session risk scores

Run locally:
    uvicorn main:app --reload
Deploy on Render: see ../render.yaml and ../DEPLOY.md
"""

import joblib
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from pipeline import load_log_dataframe, segment_sessions, build_session_results

MODEL_PATH = "ssh_bruteforce_model_v2.joblib"

app = FastAPI(title="SSH Brute-Force Detector API")

# Locked to the deployed static frontend's origin. Add more origins here
# (e.g. a custom domain, or http://localhost:8000 for local testing) if needed.
ALLOWED_ORIGINS = [
    "https://sshml-frontend.onrender.com",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

_model_bundle = None


@app.on_event("startup")
def load_model():
    global _model_bundle
    _model_bundle = joblib.load(MODEL_PATH)


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _model_bundle is not None}


@app.post("/predict")
async def predict(
    file: UploadFile = File(...),
    gap_minutes: float = Query(30, ge=1, le=1440, description="Session-gap threshold in minutes"),
):
    if _model_bundle is None:
        raise HTTPException(503, "Model not loaded yet")

    raw = await file.read()
    try:
        df = load_log_dataframe(raw)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if len(df) == 0:
        raise HTTPException(400, "No rows found in the uploaded file")

    df = segment_sessions(df, gap_minutes)
    results = build_session_results(df, _model_bundle["model"])

    return {
        "n_rows": len(df),
        "n_sessions": len(results),
        "gap_minutes": gap_minutes,
        "feature_columns": _model_bundle["feature_columns"],
        "sessions": results,
    }
