"""
main.py -- FastAPI backend for the SSH brute-force detector (v3 model:
session + IP-level + cross-IP time-window features; see pipeline.py).

Endpoints:
  GET  /health           liveness check (Render pings this kind of thing)
  POST /predict           upload a log CSV, get back per-session risk scores
                          (+ stage-2 attack type for each session)

Run locally:
    uvicorn main:app --reload
Deploy on Render: see ../render.yaml
"""

import os

import joblib
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from pipeline import load_log_dataframe, segment_sessions, build_session_results

MODEL_PATH = "ssh_bruteforce_model_v3.joblib"
TYPE_MODEL_PATH = "ssh_attack_type_model_v3.joblib"  # stage 2 (optional)

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
_type_bundle = None


@app.on_event("startup")
def load_model():
    global _model_bundle, _type_bundle
    _model_bundle = joblib.load(MODEL_PATH)
    if os.path.exists(TYPE_MODEL_PATH):
        try:
            _type_bundle = joblib.load(TYPE_MODEL_PATH)
        except Exception as e:  # stage 2 is optional: keep serving Attack/Legit
            print(f"WARNING: could not load {TYPE_MODEL_PATH}: {e}")
            _type_bundle = None


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _model_bundle is not None,
            "type_model_loaded": _type_bundle is not None}


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
    results = build_session_results(df, _model_bundle["model"], _type_bundle)

    return {
        "n_rows": len(df),
        "n_sessions": len(results),
        "gap_minutes": gap_minutes,
        "feature_columns": _model_bundle["feature_columns"],
        "type_classes": _type_bundle["classes"] if _type_bundle else None,
        "sessions": results,
    }
