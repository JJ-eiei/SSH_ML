import sys
sys.path.insert(0, "/home/claude/v3/deploy")
import joblib
import pandas as pd
from pipeline import load_log_dataframe, segment_sessions, build_session_results

obj = joblib.load("/home/claude/v3/deploy/ssh_bruteforce_model_v3.joblib")
model = obj["model"]

files = [
    ("01_legit_baseline.csv", "SAFE"),
    ("02_legit_typo_noisy_user.csv", "SAFE"),
    ("03_legit_multi_ip_roaming.csv", "SAFE"),
    ("04_shared_ip_office.csv", "SAFE"),
    ("05_burst_bruteforce_obvious.csv", "ATTACK"),
    ("06_focused_bruteforce_single_account.csv", "ATTACK"),
    ("07_password_spray_multi_account.csv", "ATTACK"),
    ("08_credential_stuffing_leaked_creds.csv", "ATTACK"),
    ("09_persistent_multiday_stealth.csv", "ATTACK"),
    ("10_coordinated_botnet_spike.csv", "ATTACK"),
]

threshold = 0.55
for fname, expected in files:
    with open(f"test_logs/{fname}", "rb") as f:
        raw = f.read()
    df = load_log_dataframe(raw)
    df = segment_sessions(df, gap_minutes=30)
    results = build_session_results(df, model)
    n_sessions = len(results)
    n_flagged = sum(1 for r in results if r["proba"] >= threshold)
    max_p = max(r["proba"] for r in results)
    min_p = min(r["proba"] for r in results)
    verdict = "ATTACK" if n_flagged > 0 else "SAFE"
    status = "OK" if verdict == expected else "*** MISMATCH ***"
    print(f"{fname:45s} sessions={n_sessions:3d} flagged={n_flagged:3d} proba[min={min_p:.3f} max={max_p:.3f}] expected={expected:6s} got={verdict:6s} {status}")
