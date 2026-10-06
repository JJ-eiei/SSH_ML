"""
main.py -- FastAPI backend for the SSH brute-force detector.

Model (v4): ONE multiclass Random Forest over the 16 session + IP-level +
cross-IP time-window features (see pipeline.py). It returns, per session,
the probability of each of 11 classes (3 legit behaviours, 8 attack types);
risk = sum of the attack-class probabilities.

Endpoints:
  GET  /health    liveness check (Render pings this kind of thing)
  POST /predict   upload a log CSV, get back per-session risk + class

Run locally:
    uvicorn main:app --reload
Deploy on Render: see ../render.yaml
"""

import joblib
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from pipeline import load_log_dataframe, segment_sessions, build_session_results

MODEL_PATH = "ssh_bruteforce_multiclass.joblib"

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

_bundle = None


@app.on_event("startup")
def load_model():
    global _bundle
    _bundle = joblib.load(MODEL_PATH)


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _bundle is not None,
            "model": _bundle.get("model_name") if _bundle else None}


@app.post("/predict")
async def predict(
    file: UploadFile = File(...),
    gap_minutes: float = Query(10, ge=1, le=1440,
                               description="Session-gap threshold in minutes (the model was trained with 10)"),
):
    if _bundle is None:
        raise HTTPException(503, "Model not loaded yet")

    raw = await file.read()
    try:
        df = load_log_dataframe(raw)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if len(df) == 0:
        raise HTTPException(400, "No readable rows found in the uploaded file")

    df = segment_sessions(df, gap_minutes)
    results = build_session_results(df, _bundle)

    return {
        "n_rows": len(df),
        "n_sessions": len(results),
        "gap_minutes": gap_minutes,
        "feature_columns": _bundle["feature_columns"],
        "classes": _bundle["classes"],
        "attack_classes": _bundle["attack_classes"],
        "legit_classes": _bundle["legit_classes"],
        "threshold": _bundle["threshold"],
        "sessions": results,
    }
