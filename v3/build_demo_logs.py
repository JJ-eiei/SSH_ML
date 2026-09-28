"""
build_demo_logs.py -- builds the 10 self-contained demo log CSVs for the
web test-suite panel, using the exact same generator functions as
generate_v3_dataset.py (so these are drawn from the same distribution the
model was trained/verified on -- not hand-crafted toy examples).

Each file is written in the raw-upload format the model expects:
    Log_ID, Timestamp, Event, Username, Source_IP, Source_Port, Password
(Session_ID / Attack_Type / Label are ground truth -- stripped, since a
real uploaded log would never have them.)

Design notes (why these 10, not the full 14-pattern set):
  - 4 SAFE files: one plain baseline + three "hard negative" patterns that
    exist specifically to catch models that over-flag (typo-prone user,
    roaming user across IPs, shared/NAT office IP).
  - 6 ATTACK files: 3 classic patterns v2 could already catch (burst,
    focused, password spray) + 3 patterns that only exist because of v3's
    new feature families (credential stuffing needs the new event
    vocabulary; persistent multi-day needs IP-level aggregation; botnet
    spike needs the cross-IP time-window feature) -- these three are the
    direct, demonstrable answer to "what changed since v2".
  - persistent_multiday and coordinated_botnet_spike are each written as
    ONE full self-contained campaign so the file alone carries all the
    history those features need (no external/persistent state required
    for the demo).
"""

import importlib.util
import sys
from datetime import datetime, timedelta

import pandas as pd

spec = importlib.util.spec_from_file_location("gen_v3", "/home/claude/v3/generate_v3_dataset.py")
gen_v3 = importlib.util.module_from_spec(spec)
sys.modules["gen_v3"] = gen_v3
spec.loader.exec_module(gen_v3)

OUT_COLUMNS = ["Log_ID", "Timestamp", "Event", "Username", "Source_IP", "Source_Port", "Password"]


def write_demo(rows, filename, out_dir="/home/claude/v3/deploy/test_logs"):
    df = pd.DataFrame(rows).sort_values("Timestamp").reset_index(drop=True)
    df["Log_ID"] = [f"LOG_{i+1:05d}" for i in range(len(df))]
    df = df[OUT_COLUMNS]
    path = f"{out_dir}/{filename}"
    df.to_csv(path, index=False)
    print(f"{filename}: {len(df)} rows, {df['Source_IP'].nunique()} unique IP(s), "
          f"{(df['Timestamp'].max() - df['Timestamp'].min())} span")
    return df


def main():
    import os
    os.makedirs("/home/claude/v3/deploy/test_logs", exist_ok=True)

    r, npr = gen_v3.make_rng(101)
    used_ips = set()
    start = datetime(2026, 9, 20, 0, 0, 0)
    end = start + timedelta(days=2)

    # 1. Baseline: plain successful logins, several different real users, no attack at all.
    r, npr = gen_v3.make_rng(1)
    rows = gen_v3.gen_legit_success(8, r, npr, start, end, used_ips, None)
    write_demo(rows, "01_legit_baseline.csv")

    # 2. Hard negative: legit user typing their password wrong a few times before succeeding.
    r, npr = gen_v3.make_rng(2)
    rows = gen_v3.gen_legit_typo(4, r, npr, start, end, used_ips, None)
    write_demo(rows, "02_legit_typo_noisy_user.csv")

    # 3. Hard negative (NEW v3 pattern): one legit user, several different IPs
    # within a short window (roaming / remote worker) -- must NOT be flagged
    # just because "many IPs".
    r, npr = gen_v3.make_rng(3)
    rows = gen_v3.gen_legit_multi_ip_roaming(1, r, npr, start, end, used_ips, None)
    write_demo(rows, "03_legit_multi_ip_roaming.csv")

    # 4. Hard negative: shared office/NAT IP, several different legit users, no fails.
    r, npr = gen_v3.make_rng(4)
    rows = gen_v3.gen_shared_ip_legit(1, r, npr, start, end, used_ips, None)
    write_demo(rows, "04_shared_ip_office.csv")

    # 5. Obvious attack: single IP hammering one account with fails.
    r, npr = gen_v3.make_rng(5)
    rows = gen_v3.gen_burst_bruteforce(1, r, npr, start, end, used_ips, None)
    write_demo(rows, "05_burst_bruteforce_obvious.csv")

    # 6. Focused brute force: single account targeted, timing/fail-count
    # deliberately overlaps a "legit user having a bad day" (see the
    # generator's own docstring) -- shows the model isn't just thresholding fail count.
    r, npr = gen_v3.make_rng(2)
    rows = gen_v3.gen_focused_bruteforce(1, r, npr, start, end, used_ips, None)
    write_demo(rows, "06_focused_bruteforce_single_account.csv")

    # 7. Password spraying: few common passwords, many accounts, low-and-slow per account.
    r, npr = gen_v3.make_rng(4)
    rows = gen_v3.gen_password_spray(1, r, npr, start, end, used_ips, None)
    write_demo(rows, "07_password_spray_multi_account.csv")

    # 8. Credential stuffing (NEW v3 pattern): realistic leaked user:pass
    # pairs -- low fails per account, mixed-in successes, needs the new
    # Invalid user / publickey-aware feature set to separate from legit traffic.
    r, npr = gen_v3.make_rng(8)
    rows = gen_v3.gen_credential_stuffing(1, r, npr, start, end, used_ips, None)
    write_demo(rows, "08_credential_stuffing_leaked_creds.csv")

    # 9. Persistent multi-day attacker (NEW v3 pattern): same IP returns across
    # 15-50 SMALL, individually-innocuous-looking sessions spread over 1-4
    # weeks. Only IP-level aggregation (ip_session_count, ip_active_span_days,
    # ip_sessions_per_day) reveals this -- session-level features alone
    # understate it by design. File is self-contained: it carries the IP's
    # full history so no external state is needed to score it.
    r, npr = gen_v3.make_rng(9)
    p_start = datetime(2026, 8, 25)
    p_end = p_start + timedelta(days=1)
    rows = gen_v3.gen_persistent_multiday_attacker(1, r, npr, p_start, p_end, used_ips, None)
    write_demo(rows, "09_persistent_multiday_stealth.csv")

    # 10. Coordinated botnet spike (NEW v3 pattern): 10-40 DIFFERENT IPs, each
    # a small isolated-looking burst, all within a ~3-15 minute window,
    # targeting the SAME account. Only the cross-IP time-window feature
    # (distinct_ips_same_target_15min) reveals the coordination -- no
    # single IP's session looks unusual on its own.
    r, npr = gen_v3.make_rng(10)
    b_start = datetime(2026, 9, 24, 13, 0, 0)
    b_end = b_start + timedelta(hours=1)
    rows = gen_v3.gen_coordinated_botnet_spike(1, r, npr, b_start, b_end, used_ips, None)
    write_demo(rows, "10_coordinated_botnet_spike.csv")


if __name__ == "__main__":
    main()
