"""
pipeline.py (v3) -- shared log-parsing / session-segmentation /
feature-extraction logic for the backend API. This is the Python twin of
web/js/features.js; keep the two in sync if either changes.

v3 adds two feature families on top of the v2 session-level set:
  - IP-level features, aggregated across a Source_IP's entire history in
    the uploaded file (persistent/low-and-slow campaigns).
  - A cross-IP time-window feature (coordinated/botnet campaigns).
Both are computed from whatever is in the uploaded file -- for a
self-contained demo log (one IP's full multi-day campaign, or several
IPs hitting the same account within minutes of each other) that's enough
to exercise them; a real deployment scoring a rolling window of traffic
would need this history to come from a persistent store instead.

See ../v3/extract_features_v3.py (training-time reference implementation)
for the derivation and evidence behind each feature.
"""

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = ["Timestamp", "Event", "Username", "Source_IP", "Source_Port"]

DEFAULT_USERNAMES = {
    "root", "admin", "test", "guest", "pi", "oracle",
    "ubuntu", "mysql", "postgres", "ftpuser",
}

MIN_DURATION_FOR_RATE = 5.0  # seconds -- floor for attempts_per_minute
BOTNET_WINDOW_MINUTES = 15

FEATURE_COLUMNS = [
    "fail_ratio", "n_failed", "n_success", "invalid_ratio", "publickey_ratio",
    "n_unique_usernames", "targets_default_username", "ends_after_success",
    "duration_seconds", "std_inter_arrival_s", "attempts_per_minute",
    "ip_session_count", "ip_active_span_days", "ip_sessions_per_day", "ip_total_events",
    "distinct_ips_same_target_15min",
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
    """Session-level features only. Mirrors extract_session_features() in
    v3/extract_features_v3.py exactly (event vocabulary, ratios, the fixed
    attempts_per_minute rate floor, ends_after_success)."""
    g = g.sort_values("Timestamp")
    n_events = len(g)
    n_failed = int((g["Event"] == "Failed password").sum())
    n_invalid = int((g["Event"] == "Invalid user").sum())
    n_accepted_pw = int((g["Event"] == "Accepted password").sum())
    n_accepted_key = int((g["Event"] == "Accepted publickey").sum())
    n_success = n_accepted_pw + n_accepted_key

    fail_ratio = n_failed / n_events
    invalid_ratio = n_invalid / n_events
    publickey_ratio = n_accepted_key / n_events

    user_counts = g["Username"].value_counts()
    duration = (g["Timestamp"].max() - g["Timestamp"].min()).total_seconds()

    if n_events > 1:
        ia = g["Timestamp"].diff().dt.total_seconds().dropna()
        std_ia = float(ia.std(ddof=0))
    else:
        std_ia = 0.0

    rate_duration = max(duration, MIN_DURATION_FOR_RATE)
    attempts_per_minute = n_events / (rate_duration / 60)

    last_event = g["Event"].iloc[-1]
    ends_after_success = int(last_event in ("Accepted password", "Accepted publickey"))

    return pd.Series({
        "Source_IP": g["Source_IP"].iloc[0],
        "session_start": g["Timestamp"].min(),
        "session_end": g["Timestamp"].max(),
        "primary_username": user_counts.index[0],
        "n_events": n_events,
        "n_failed": n_failed,
        "n_success": n_success,
        "fail_ratio": fail_ratio,
        "invalid_ratio": invalid_ratio,
        "publickey_ratio": publickey_ratio,
        "n_unique_usernames": int(g["Username"].nunique()),
        "targets_default_username": int(bool(set(g["Username"]) & DEFAULT_USERNAMES)),
        "duration_seconds": duration,
        "std_inter_arrival_s": std_ia,
        "attempts_per_minute": attempts_per_minute,
        "ends_after_success": ends_after_success,
    })


def _build_ip_features(df: pd.DataFrame, sessions: pd.DataFrame) -> pd.DataFrame:
    """Aggregated across a Source_IP's entire history in this file."""
    ip_grp = df.groupby("Source_IP")
    ip_stats = ip_grp.agg(
        ip_total_events=("Timestamp", "count"),
        ip_first_seen=("Timestamp", "min"),
        ip_last_seen=("Timestamp", "max"),
    ).reset_index()

    sess_per_ip = sessions.groupby("Source_IP")["Session_ID"].nunique()
    ip_stats = ip_stats.merge(sess_per_ip.rename("ip_session_count"), on="Source_IP", how="left")

    ip_stats["ip_active_span_days"] = (
        (ip_stats["ip_last_seen"] - ip_stats["ip_first_seen"]).dt.total_seconds() / 86400.0
    )
    span_floor = np.maximum(ip_stats["ip_active_span_days"], 1.0 / 24)
    ip_stats["ip_sessions_per_day"] = ip_stats["ip_session_count"] / span_floor

    return ip_stats[["Source_IP", "ip_session_count", "ip_active_span_days",
                      "ip_sessions_per_day", "ip_total_events"]]


def _build_botnet_window_feature(sessions: pd.DataFrame, window_minutes=BOTNET_WINDOW_MINUTES) -> pd.Series:
    """For each session, count distinct OTHER Source_IPs that had a session
    targeting the same primary_username within +/- window_minutes."""
    result = pd.Series(0, index=sessions.index, dtype=int)
    window = pd.Timedelta(minutes=window_minutes)

    for user, grp in sessions.groupby("primary_username"):
        grp = grp.sort_values("session_start")
        times = grp["session_start"].values
        ips = grp["Source_IP"].values
        idx = grp.index.values
        n = len(grp)
        left = 0
        for i in range(n):
            t = times[i]
            while times[left] < t - window:
                left += 1
            right = i
            while right + 1 < n and times[right + 1] <= t + window:
                right += 1
            window_ips = set(ips[left:right + 1])
            window_ips.discard(ips[i])
            result.loc[idx[i]] = len(window_ips)
    return result


def build_session_results(df: pd.DataFrame, model) -> list[dict]:
    """df must already have Session_ID (from segment_sessions). Computes
    session-level + IP-level + cross-IP time-window features together (the
    latter two need every session in the file, not just one group), scores
    each session, and returns one dict per session for the frontend's
    table + expandable evidence view."""
    sessions = df.groupby("Session_ID").apply(extract_session_features).reset_index()

    ip_feats = _build_ip_features(df, df[["Source_IP", "Session_ID"]].drop_duplicates())
    sessions = sessions.merge(ip_feats, on="Source_IP", how="left")
    sessions["distinct_ips_same_target_15min"] = _build_botnet_window_feature(sessions)

    X = sessions[FEATURE_COLUMNS].values
    probas = model.predict_proba(X)[:, 1]

    results = []
    raw_by_session = {sid: g.sort_values("Timestamp") for sid, g in df.groupby("Session_ID")}
    for row, proba in zip(sessions.itertuples(index=False), probas):
        g = raw_by_session[row.Session_ID]
        feats = {col: getattr(row, col) for col in FEATURE_COLUMNS}
        feats["n_events"] = int(row.n_events)
        results.append({
            "session_id": int(row.Session_ID),
            "ip": row.Source_IP,
            "start": row.session_start.isoformat(),
            "proba": float(proba),
            "features": {k: (float(v) if isinstance(v, (np.floating, float)) else int(v))
                         for k, v in feats.items()},
            "rows": [
                {
                    "ts": r["Timestamp"].isoformat(),
                    "event": r["Event"],
                    "username": r["Username"],
                    "port": int(r["Source_Port"]),
                }
                for _, r in g.iterrows()
            ],
        })
    results.sort(key=lambda r: r["proba"], reverse=True)
    return results
