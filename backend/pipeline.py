"""
pipeline.py -- shared log-parsing / session-segmentation / feature-extraction
logic for the backend API. This is the Python twin of web/js/features.js;
keep the two in sync if either changes (same session-gap segmentation rule,
same 14 features, same formulas -- see ssh_bruteforce_pipeline_v2.ipynb for
where this was derived from).
"""

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = ["Timestamp", "Event", "Username", "Source_IP", "Source_Port"]

DEFAULT_USERNAMES = {
    "root", "admin", "test", "guest", "pi", "oracle",
    "ubuntu", "mysql", "postgres", "ftpuser",
}

FEATURE_COLUMNS = [
    "n_events", "n_failed", "n_success", "fail_ratio",
    "n_unique_usernames", "username_entropy", "targets_default_username",
    "n_unique_ports", "duration_seconds",
    "mean_inter_arrival_s", "median_inter_arrival_s", "std_inter_arrival_s", "min_inter_arrival_s",
    "attempts_per_minute",
]


def load_log_dataframe(file_bytes: bytes) -> pd.DataFrame:
    import io
    df = pd.read_csv(io.BytesIO(file_bytes))
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"CSV is missing required column(s): {', '.join(missing)}")
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    # Password, if present, is intentionally never used below -- leakage, and
    # real production logs won't have it anyway.
    return df


def segment_sessions(df: pd.DataFrame, gap_minutes: float) -> pd.DataFrame:
    """Time-gap segmentation per Source_IP -- a judgment call, not ground
    truth (see README / project notes). Assigns a Session_ID column."""
    gap = pd.Timedelta(minutes=gap_minutes)
    df = df.sort_values(["Source_IP", "Timestamp"]).reset_index(drop=True)
    session_id = np.zeros(len(df), dtype=int)
    counter = 0
    prev_ip = None
    prev_ts = None
    for i, row in df.iterrows():
        if row["Source_IP"] != prev_ip or (row["Timestamp"] - prev_ts) > gap:
            counter += 1
        session_id[i] = counter
        prev_ip = row["Source_IP"]
        prev_ts = row["Timestamp"]
    df = df.copy()
    df["Session_ID"] = session_id
    return df


def _shannon_entropy(counts) -> float:
    counts = np.asarray(counts, dtype=float)
    probs = counts / counts.sum()
    return float(-(probs * np.log2(probs)).sum())


def extract_session_features(g: pd.DataFrame) -> pd.Series:
    g = g.sort_values("Timestamp")
    n_events = len(g)
    n_failed = int((g["Event"] == "Failed password").sum())
    n_success = int((g["Event"] == "Accepted password").sum())

    user_counts = g["Username"].value_counts()
    duration = (g["Timestamp"].max() - g["Timestamp"].min()).total_seconds()

    if n_events > 1:
        ia = g["Timestamp"].diff().dt.total_seconds().dropna()
        mean_ia, median_ia = ia.mean(), ia.median()
        std_ia, min_ia = ia.std(ddof=0), ia.min()
    else:
        mean_ia = median_ia = std_ia = min_ia = 0.0

    attempts_per_min = n_events / ((duration / 60) + 1e-6)

    return pd.Series({
        "n_events": n_events,
        "n_failed": n_failed,
        "n_success": n_success,
        "fail_ratio": n_failed / n_events,
        "n_unique_usernames": int(g["Username"].nunique()),
        "username_entropy": _shannon_entropy(user_counts.values),
        "targets_default_username": int(bool(set(g["Username"]) & DEFAULT_USERNAMES)),
        "n_unique_ports": int(g["Source_Port"].nunique()),
        "duration_seconds": duration,
        "mean_inter_arrival_s": mean_ia,
        "median_inter_arrival_s": median_ia,
        "std_inter_arrival_s": std_ia,
        "min_inter_arrival_s": min_ia,
        "attempts_per_minute": attempts_per_min,
    })


def build_session_results(df: pd.DataFrame, model) -> list[dict]:
    """df must already have Session_ID (from segment_sessions). Returns one
    dict per session with features, model probability, and the raw rows
    (for the frontend's expandable evidence view)."""
    results = []
    for session_id, g in df.groupby("Session_ID"):
        g = g.sort_values("Timestamp")
        feats = extract_session_features(g)
        x = feats[FEATURE_COLUMNS].values.reshape(1, -1)
        proba = float(model.predict_proba(x)[0, 1])
        results.append({
            "session_id": int(session_id),
            "ip": g["Source_IP"].iloc[0],
            "start": g["Timestamp"].iloc[0].isoformat(),
            "proba": proba,
            "features": {k: (float(v) if isinstance(v, (np.floating, float)) else int(v))
                         for k, v in feats.items()},
            "rows": [
                {
                    "ts": row["Timestamp"].isoformat(),
                    "event": row["Event"],
                    "username": row["Username"],
                    "port": int(row["Source_Port"]),
                }
                for _, row in g.iterrows()
            ],
        })
    results.sort(key=lambda r: r["proba"], reverse=True)
    return results
