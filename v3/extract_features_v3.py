"""
extract_features_v3.py

Three layers of features, computed from a raw SSH event-level CSV
(Log_ID, Timestamp, Event, Username, Source_IP, Source_Port, Password,
Session_ID, Attack_Type, Label):

  1. SESSION-level features  -- same idea as v1/v2, but with v2's known
     bugs fixed on sight (see notes inline) instead of discovered later:
       - n_success dropped: with 4 Event categories now (Failed password,
         Invalid user, Accepted password, Accepted publickey) it is no
         longer *deterministically* implied by n_events/n_failed alone,
         BUT fail_ratio + invalid_ratio + success_ratio == 1.0 exactly by
         construction, so only 2 of those 3 ratios are kept (fail_ratio,
         invalid_ratio) -- the 3rd is fully determined and adds nothing.
       - attempts_per_minute: v2 divided by (duration_seconds/60 + 1e-6),
         which sent 32.5% of sessions (all single-event ones) to exactly
         1,000,000. Fixed by flooring the duration used for the rate at
         MIN_DURATION_FOR_RATE seconds instead of ~0.
     Every other v2 feature is kept as a CANDIDATE (not pre-judged) --
     redundancy among them (e.g. the 4 inter-arrival stats, or
     n_unique_usernames vs username_entropy) is for the verification
     step to catch with evidence (correlation/VIF), not for this script
     to assume away.

  2. IP-level features -- aggregated across a Source_IP's ENTIRE history
     in the log, not just one session. This is what can catch
     persistent_multiday_attacker and (partially) low_and_slow, where
     each individual session looks tiny/innocuous by design.

  3. Time-window features -- for coordinated_botnet_spike: how many
     DISTINCT other source IPs hit the same target username within a
     trailing window. No single-IP view (session or IP-level) can see
     this; it requires looking across IPs.

Usage:
    python3 extract_features_v3.py ssh_dataset_v3.csv ssh_features_v3.csv
"""

import sys

import numpy as np
import pandas as pd

DEFAULT_USERNAMES = {
    "root", "admin", "test", "guest", "pi", "oracle",
    "ubuntu", "mysql", "postgres", "ftpuser",
}
MIN_DURATION_FOR_RATE = 5.0  # seconds -- floor used only for the rate calc,
                             # so a 1-event session gets a bounded, sane
                             # attempts_per_minute instead of exploding.
BOTNET_WINDOW_MINUTES = 15


def shannon_entropy(counts):
    counts = np.asarray(counts, dtype=float)
    probs = counts / counts.sum()
    return float(-(probs * np.log2(probs)).sum())


# --------------------------------------------------------- session-level --
def extract_session_features(g: pd.DataFrame) -> pd.Series:
    g = g.sort_values("Timestamp")
    n_events = len(g)
    n_failed = int((g["Event"] == "Failed password").sum())
    n_invalid = int((g["Event"] == "Invalid user").sum())
    n_accepted_pw = int((g["Event"] == "Accepted password").sum())
    n_accepted_key = int((g["Event"] == "Accepted publickey").sum())
    n_success = n_accepted_pw + n_accepted_key

    fail_ratio = n_failed / n_events
    invalid_ratio = n_invalid / n_events
    # success_ratio deliberately NOT stored: = 1 - fail_ratio - invalid_ratio

    publickey_ratio = n_accepted_key / n_events

    user_counts = g["Username"].value_counts()
    duration = (g["Timestamp"].max() - g["Timestamp"].min()).total_seconds()

    if n_events > 1:
        inter_arrival = g["Timestamp"].diff().dt.total_seconds().dropna()
        mean_ia, median_ia = float(inter_arrival.mean()), float(inter_arrival.median())
        std_ia, min_ia = float(inter_arrival.std(ddof=0)), float(inter_arrival.min())
    else:
        mean_ia = median_ia = std_ia = min_ia = 0.0

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
        "n_invalid_user": n_invalid,
        "n_success": n_success,
        "fail_ratio": fail_ratio,
        "invalid_ratio": invalid_ratio,
        "publickey_ratio": publickey_ratio,
        "n_unique_usernames": g["Username"].nunique(),
        "username_entropy": shannon_entropy(user_counts.values),
        "targets_default_username": int(bool(set(g["Username"]) & DEFAULT_USERNAMES)),
        "n_unique_ports": g["Source_Port"].nunique(),
        "duration_seconds": duration,
        "mean_inter_arrival_s": mean_ia,
        "median_inter_arrival_s": median_ia,
        "std_inter_arrival_s": std_ia,
        "min_inter_arrival_s": min_ia,
        "attempts_per_minute": attempts_per_minute,
        "ends_after_success": ends_after_success,
        "Label": g["Label"].iloc[0],
        "Attack_Type": g["Attack_Type"].iloc[0],
    })


# ------------------------------------------------------------- IP-level --
def build_ip_features(df: pd.DataFrame, sessions: pd.DataFrame) -> pd.DataFrame:
    ip_grp = df.groupby("Source_IP")
    ip_stats = ip_grp.agg(
        ip_total_events=("Log_ID", "count"),
        ip_first_seen=("Timestamp", "min"),
        ip_last_seen=("Timestamp", "max"),
        ip_unique_usernames_targeted=("Username", pd.Series.nunique),
    ).reset_index()

    sess_per_ip = sessions.groupby("Source_IP")["Session_ID"].nunique() \
        if "Session_ID" in sessions.columns else sessions.groupby("Source_IP").size()
    ip_stats = ip_stats.merge(
        sess_per_ip.rename("ip_session_count"), on="Source_IP", how="left"
    )

    ip_stats["ip_active_span_days"] = (
        (ip_stats["ip_last_seen"] - ip_stats["ip_first_seen"]).dt.total_seconds() / 86400.0
    )
    # floor so a brand-new IP with one session doesn't produce inf/huge ratios
    span_floor = np.maximum(ip_stats["ip_active_span_days"], 1.0 / 24)
    ip_stats["ip_sessions_per_day"] = ip_stats["ip_session_count"] / span_floor

    return ip_stats[[
        "Source_IP", "ip_session_count", "ip_active_span_days",
        "ip_sessions_per_day", "ip_total_events", "ip_unique_usernames_targeted",
    ]]


# --------------------------------------------------------- time-window --
def build_botnet_window_feature(sessions: pd.DataFrame, window_minutes=BOTNET_WINDOW_MINUTES) -> pd.Series:
    """For each session, count distinct OTHER Source_IPs that had a session
    targeting the same primary_username with a start time within
    +/- window_minutes of this session's start. Implemented per-username
    group with a sorted-array two-pointer sweep (O(n log n) overall)."""
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


def main(in_path, out_path):
    df = pd.read_csv(in_path, parse_dates=["Timestamp"])
    print(f"Loaded {len(df)} events, {df['Session_ID'].nunique()} sessions")

    sessions = df.groupby("Session_ID").apply(extract_session_features).reset_index()

    ip_feats = build_ip_features(df, df[["Source_IP", "Session_ID"]].drop_duplicates())
    sessions = sessions.merge(ip_feats, on="Source_IP", how="left")

    print("Computing cross-IP time-window feature (botnet signal)...")
    sessions["distinct_ips_same_target_15min"] = build_botnet_window_feature(sessions)

    sessions.to_csv(out_path, index=False)
    print(f"Wrote {out_path}: {sessions.shape}")
    print("\nColumns:", list(sessions.columns))


if __name__ == "__main__":
    in_path = sys.argv[1] if len(sys.argv) > 1 else "ssh_dataset_v3.csv"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "ssh_features_v3.csv"
    main(in_path, out_path)
