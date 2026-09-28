"""
generate_v3_dataset.py

SSH auth-log mock generator, v3.

What changed from v2 (see ../v2 review notes):
  - Event vocabulary expanded from {Failed password, Accepted password} to
    also include "Invalid user" (attempt against a username that does not
    exist on the box -- real sshd logs this as a SEPARATE line before the
    Failed-password line) and "Accepted publickey" (key-based auth, so not
    every legit login is a password event). This lets us compute
    invalid_user_ratio and publickey_ratio, which v2 could not.
  - 5 new behavior patterns grounded in real SSH brute-force research
    (NSDI'24 "Brute-Force SSH Attacks In The Wild", NDSS billion-scale SSH
    study): large-dictionary scanner, credential stuffing, persistent
    multi-day attacker, coordinated botnet spike, legit multi-IP roaming.
  - Overlap between hard classes is now engineered on fail_ratio /
    attempts_per_minute / duration TOGETHER (v2's mistake: overlap was
    only added on secondary params like raw duration/count ranges, while
    the dominant model feature, fail_ratio, stayed cleanly separated).
  - Every row still only uses fields a real sshd log would have
    (Timestamp, Event, Username, Source_IP, Source_Port). Password is
    label-only bookkeeping (never a model feature), same rule as v1/v2.

Two levels of ground truth are produced:
  - Session_ID: a single continuous burst of activity from one IP
    (this is what v1/v2 called a "session" -- session-level features).
  - Source_IP persistence across MANY sessions/days, and coordinated
    timing across MANY different IPs, are both real signals that no
    single session can see -- that's what the IP-level and time-window
    aggregation features (built in extract_features_v3.py) are for.

Usage:
    python3 generate_v3_dataset.py
Produces:
    ssh_dataset_v3.csv       (main train/eval set)
    ssh_dataset_v3_ood.csv   (different seed + shifted ranges, held out)
"""

import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

# ---------------------------------------------------------------- config --
DEFAULT_USERNAMES = [
    "root", "admin", "test", "guest", "pi", "oracle",
    "ubuntu", "mysql", "postgres", "ftpuser",
]
REAL_USERNAMES = [
    "jsmith", "k.wong", "a.patel", "m.garcia", "t.nguyen", "s.johnson",
    "r.kim", "l.chen", "d.brown", "n.suarez", "c.taylor", "p.singh",
    "e.martin", "y.tanaka", "b.davis", "f.rossi", "h.mueller", "v.ivanov",
    "j.lee2", "o.dubois",
]
COMMON_WEAK_PASSWORDS = [
    "admin123", "111111", "admin", "system", "qwerty",
    "123456", "root", "password", "letmein", "welcome1", "123123",
]
# simulated "leaked" username:password pairs for credential stuffing --
# the point is these are CORRECT for a subset of REAL_USERNAMES, so a
# stuffing attacker occasionally succeeds on the FIRST try for an account,
# unlike brute force (many fails before any success).
LEAKED_CREDS = {u: f"leaked_{u}_{i}" for i, u in enumerate(REAL_USERNAMES)}


def make_rng(seed):
    r = random.Random(seed)
    np_r = np.random.RandomState(seed)
    return r, np_r


def random_ephemeral_port(r):
    return r.randint(49152, 65535)


def random_public_ip(r, used):
    while True:
        ip = ".".join(str(r.randint(1, 254)) for _ in range(4))
        if ip not in used:
            used.add(ip)
            return ip


def random_large_dict_username(r, n=6):
    """Looks like a scraped username-list entry: short lowercase token,
    sometimes with digits, mimicking real large-dictionary attacker lists."""
    letters = "abcdefghijklmnopqrstuvwxyz"
    base = "".join(r.choice(letters) for _ in range(r.randint(3, 8)))
    if r.random() < 0.3:
        base += str(r.randint(1, 99))
    return base


# ============================================================ patterns ====
# Each generator returns a list of event dicts:
#   Timestamp, Event, Username, Source_IP, Source_Port, Password,
#   Session_ID, Attack_Type, Label
# Session_ID is assigned by the caller (main()) after concatenation, based
# on (Source_IP, contiguous time block) -- see assign_sessions().

def gen_legit_success(n, r, npr, start, end, used_ips, sid_pool):
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        user = r.choice(REAL_USERNAMES)
        t = start + timedelta(seconds=r.randint(0, span))
        event = "Accepted publickey" if r.random() < 0.35 else "Accepted password"
        pw = "***HIDDEN***"
        rows.append(dict(Timestamp=t, Event=event, Username=user, Source_IP=ip,
                          Source_Port=random_ephemeral_port(r), Password=pw,
                          Attack_Type="legit_success", Label=0))
    return rows


def gen_legit_typo(n, r, npr, start, end, used_ips, sid_pool):
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        user = r.choice(REAL_USERNAMES)
        n_fail = r.randint(1, 9)
        gives_up = r.random() < 0.12
        t = start + timedelta(seconds=r.randint(0, span))
        for i in range(n_fail):
            rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password="typo_pass", Attack_Type="legit_typo", Label=0))
            t += timedelta(seconds=r.uniform(2, 25))
        if not gives_up:
            rows.append(dict(Timestamp=t, Event="Accepted password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password="***HIDDEN***", Attack_Type="legit_typo", Label=0))
    return rows


def gen_shared_ip_legit(n, r, npr, start, end, used_ips, sid_pool):
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)  # office / NAT IP
        n_users = r.randint(3, 7)
        users = r.sample(REAL_USERNAMES, min(n_users, len(REAL_USERNAMES)))
        campaign_start = start + timedelta(seconds=r.randint(0, span))
        t = campaign_start
        for user in users:
            if r.random() < 0.15:
                rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                                  Source_IP=ip, Source_Port=random_ephemeral_port(r),
                                  Password="typo_pass", Attack_Type="shared_ip_legit", Label=0))
                t += timedelta(seconds=r.uniform(2, 15))
            event = "Accepted publickey" if r.random() < 0.3 else "Accepted password"
            rows.append(dict(Timestamp=t, Event=event, Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password="***HIDDEN***", Attack_Type="shared_ip_legit", Label=0))
            t += timedelta(seconds=r.uniform(30, 900))
    return rows


def gen_legit_multi_ip_roaming(n, r, npr, start, end, used_ips, sid_pool):
    """NEW. One legit user, successful logins from 2-4 different IPs within
    a short window (mobile / remote worker roaming). Each individual
    session is a single Accepted event -- indistinguishable from
    legit_success at the session level. Only a USER-level cross-IP view
    (not IP-level) can see the roaming. Deliberate hard negative for any
    'many IPs = suspicious' heuristic."""
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        user = r.choice(REAL_USERNAMES)
        n_ips = r.randint(2, 4)
        window_hours = r.uniform(1, 10)
        campaign_start = start + timedelta(seconds=r.randint(0, span))
        for _ in range(n_ips):
            ip = random_public_ip(r, used_ips)
            t = campaign_start + timedelta(seconds=r.uniform(0, window_hours * 3600))
            event = "Accepted publickey" if r.random() < 0.4 else "Accepted password"
            rows.append(dict(Timestamp=t, Event=event, Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password="***HIDDEN***",
                              Attack_Type="legit_multi_ip_roaming", Label=0))
    return rows


def gen_ambiguous_legit(n, r, npr, start, end, used_ips, sid_pool):
    """Legit user having a genuinely bad day: high fail count (overlaps
    focused_bruteforce's fail_ratio range on purpose), still succeeds."""
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        user = r.choice(REAL_USERNAMES)
        n_fail = r.randint(6, 14)  # overlaps focused_bruteforce's low end
        t = start + timedelta(seconds=r.randint(0, span))
        for _ in range(n_fail):
            rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password="typo_pass", Attack_Type="ambiguous_legit", Label=0))
            t += timedelta(seconds=r.uniform(3, 40))  # overlaps attack timing
        if r.random() < 0.85:
            rows.append(dict(Timestamp=t, Event="Accepted password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password="***HIDDEN***", Attack_Type="ambiguous_legit", Label=0))
    return rows


def gen_burst_bruteforce(n, r, npr, start, end, used_ips, sid_pool):
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        user = r.choice(DEFAULT_USERNAMES + REAL_USERNAMES)
        n_fail = r.randint(15, 45)
        t = start + timedelta(seconds=r.randint(0, span))
        for _ in range(n_fail):
            rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password=f"pass{r.randint(1000,99999)}",
                              Attack_Type="burst_bruteforce", Label=1))
            t += timedelta(seconds=r.uniform(0.3, 3))
        if r.random() < 0.05:
            rows.append(dict(Timestamp=t, Event="Accepted password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password="***HIDDEN***", Attack_Type="burst_bruteforce", Label=1))
    return rows


def gen_focused_bruteforce(n, r, npr, start, end, used_ips, sid_pool):
    """Hard positive: single account, fail_ratio/timing deliberately
    overlapping ambiguous_legit's range (both ~6-20 fails, seconds-scale
    gaps) so fail_ratio alone can't cleanly separate them -- the model has
    to use a combination, not just targets_default_username (60/40 mix
    with REAL_USERNAMES so that flag alone isn't a free shortcut)."""
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        user = r.choice(DEFAULT_USERNAMES) if r.random() < 0.6 else r.choice(REAL_USERNAMES)
        n_fail = r.randint(6, 40)  # overlaps ambiguous_legit at the low end
        t = start + timedelta(seconds=r.randint(0, span))
        for _ in range(n_fail):
            rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password=f"pass{r.randint(1000,99999)}",
                              Attack_Type="focused_bruteforce", Label=1))
            t += timedelta(seconds=r.uniform(2, 35))  # overlaps ambiguous_legit gaps
        if r.random() < 0.04:
            rows.append(dict(Timestamp=t, Event="Accepted password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password="***HIDDEN***", Attack_Type="focused_bruteforce", Label=1))
    return rows


def gen_low_and_slow(n, r, npr, start, end, used_ips, sid_pool):
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        n_targets = r.choices([1, 2, 3], weights=[0.7, 0.2, 0.1])[0]
        pool = DEFAULT_USERNAMES if r.random() < 0.55 else REAL_USERNAMES
        targets = r.sample(pool, min(n_targets, len(pool)))
        n_attempts = r.randint(8, 30)
        duration_hours = r.uniform(4, 36)
        min_gap = 180
        campaign_start = start + timedelta(seconds=r.randint(0, max(span - 3600, 0)))
        raw_gaps = npr.exponential(scale=1.0, size=n_attempts - 1) if n_attempts > 1 else np.array([])
        if len(raw_gaps):
            raw_gaps = raw_gaps / raw_gaps.sum() * (duration_hours * 3600 - min_gap * (n_attempts - 1))
        gaps = np.clip(raw_gaps, 0, None) + min_gap
        t = campaign_start
        succeeds = r.random() < 0.08
        for i in range(n_attempts):
            user = r.choice(targets)
            is_last = i == n_attempts - 1
            if is_last and succeeds:
                event, pw = "Accepted password", "***HIDDEN***"
            else:
                event, pw = "Failed password", f"pass{r.randint(1000,99999)}"
            rows.append(dict(Timestamp=t, Event=event, Username=user, Source_IP=ip,
                              Source_Port=random_ephemeral_port(r), Password=pw,
                              Attack_Type="low_and_slow", Label=1))
            if i < n_attempts - 1:
                t += timedelta(seconds=float(gaps[i]))
    return rows


def gen_password_spray(n, r, npr, start, end, used_ips, sid_pool):
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        multi_ip = r.random() < 0.3
        ip_pool = ([random_public_ip(r, used_ips) for _ in range(r.randint(2, 4))]
                   if multi_ip else [random_public_ip(r, used_ips)])
        spray_passwords = r.sample(COMMON_WEAK_PASSWORDS, r.randint(1, 3))
        targets = r.sample(REAL_USERNAMES, r.randint(6, len(REAL_USERNAMES)))
        campaign_start = start + timedelta(seconds=r.randint(0, span))
        t = campaign_start
        succeed_user = r.choice(targets) if r.random() < 0.15 else None
        for pw in spray_passwords:
            for user in targets:
                ip = r.choice(ip_pool)
                if user == succeed_user and pw == spray_passwords[-1]:
                    event, out_pw = "Accepted password", "***HIDDEN***"
                else:
                    event, out_pw = "Failed password", pw
                rows.append(dict(Timestamp=t, Event=event, Username=user, Source_IP=ip,
                                  Source_Port=random_ephemeral_port(r), Password=out_pw,
                                  Attack_Type="password_spray", Label=1))
                t += timedelta(seconds=r.uniform(20, 300))
    return rows


def gen_ambiguous_attack(n, r, npr, start, end, used_ips, sid_pool):
    """Attack that looks legit: succeeds within a handful of fails, mimicking
    legit_typo's profile (overlaps legit_typo's fail count and timing)."""
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        user = r.choice(REAL_USERNAMES)  # targets a real-looking account, not a default one
        n_fail = r.randint(1, 8)  # overlaps legit_typo (1-9)
        t = start + timedelta(seconds=r.randint(0, span))
        for _ in range(n_fail):
            rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                              Source_IP=ip, Source_Port=random_ephemeral_port(r),
                              Password=f"pass{r.randint(1000,99999)}",
                              Attack_Type="ambiguous_attack", Label=1))
            t += timedelta(seconds=r.uniform(2, 25))  # overlaps legit_typo gaps
        rows.append(dict(Timestamp=t, Event="Accepted password", Username=user,
                          Source_IP=ip, Source_Port=random_ephemeral_port(r),
                          Password="***HIDDEN***", Attack_Type="ambiguous_attack", Label=1))
    return rows


def gen_large_dictionary_scanner(n, r, npr, start, end, used_ips, sid_pool):
    """NEW. Grounded in NSDI'24 finding: some attackers use dictionaries of
    thousands of usernames from one IP, mostly against accounts that don't
    exist (-> Invalid user events), 1 attempt each, essentially never
    succeeds. Opposite signature to focused_bruteforce: high username
    diversity instead of low."""
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        n_attempts = r.randint(150, 600)
        t = start + timedelta(seconds=r.randint(0, span))
        for _ in range(n_attempts):
            user = random_large_dict_username(r)
            exists = user in REAL_USERNAMES  # ~never, by construction
            event = "Failed password" if exists else "Invalid user"
            rows.append(dict(Timestamp=t, Event=event, Username=user, Source_IP=ip,
                              Source_Port=random_ephemeral_port(r),
                              Password=f"pass{r.randint(1000,99999)}",
                              Attack_Type="large_dictionary_scanner", Label=1))
            t += timedelta(seconds=r.uniform(0.1, 2))
    return rows


def gen_credential_stuffing(n, r, npr, start, end, used_ips, sid_pool):
    """NEW. Uses realistic (leaked) username:password PAIRS instead of
    blind guessing. Distinctive signature: LOW fails-per-username (usually
    0-1, since the attacker already "knows" the password) but HIGH
    username diversity, with successes mixed among the fails rather than
    only at the very end -- unlike password_spray (blind common passwords,
    success is rare/incidental) or focused_bruteforce (many fails, one
    target)."""
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        n_targets = r.randint(8, 20)
        targets = r.sample(REAL_USERNAMES, min(n_targets, len(REAL_USERNAMES)))
        hit_rate = r.uniform(0.2, 0.5)  # fraction of pairs that are genuinely correct
        t = start + timedelta(seconds=r.randint(0, span))
        for user in targets:
            is_hit = r.random() < hit_rate
            if is_hit:
                # occasionally one stale/wrong guess first, then the real leaked pw
                if r.random() < 0.3:
                    rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                                      Source_IP=ip, Source_Port=random_ephemeral_port(r),
                                      Password="old_pw_guess",
                                      Attack_Type="credential_stuffing", Label=1))
                    t += timedelta(seconds=r.uniform(1, 10))
                rows.append(dict(Timestamp=t, Event="Accepted password", Username=user,
                                  Source_IP=ip, Source_Port=random_ephemeral_port(r),
                                  Password="***HIDDEN***",
                                  Attack_Type="credential_stuffing", Label=1))
            else:
                rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                                  Source_IP=ip, Source_Port=random_ephemeral_port(r),
                                  Password=LEAKED_CREDS.get(user, "wrong_leak"),
                                  Attack_Type="credential_stuffing", Label=1))
            t += timedelta(seconds=r.uniform(5, 60))
    return rows


def gen_persistent_multiday_attacker(n, r, npr, start, end, used_ips, sid_pool):
    """NEW. Same IP returns across MANY sessions spread over many days.
    Each individual session is deliberately small/innocuous (3-10 fails,
    short duration) so SESSION-level features alone understate this --
    only IP-level aggregation (total sessions, active-day span) reveals
    it. Grounded in NSDI'24: persistence spans from <1 day to months for
    a subset of attackers."""
    rows = []
    for _ in range(n):
        ip = random_public_ip(r, used_ips)
        user = r.choice(DEFAULT_USERNAMES) if r.random() < 0.5 else r.choice(REAL_USERNAMES)
        n_sessions = r.randint(15, 50)
        active_days = r.uniform(5, 25)
        campaign_start = start
        for _ in range(n_sessions):
            offset_days = r.uniform(0, active_days)
            t = campaign_start + timedelta(days=offset_days, seconds=r.randint(0, 86400))
            n_fail = r.randint(3, 10)  # small, innocuous-looking per session
            for _ in range(n_fail):
                rows.append(dict(Timestamp=t, Event="Failed password", Username=user,
                                  Source_IP=ip, Source_Port=random_ephemeral_port(r),
                                  Password=f"pass{r.randint(1000,99999)}",
                                  Attack_Type="persistent_multiday_attacker", Label=1))
                t += timedelta(seconds=r.uniform(1, 20))
    return rows


def gen_coordinated_botnet_spike(n_campaigns, r, npr, start, end, used_ips, sid_pool):
    """NEW. MANY different IPs, each a short/small burst, all within a
    narrow time window, targeting the SAME account(s). Each IP's own
    session again looks small/isolated -- only a cross-IP TIME-WINDOW view
    (many distinct IPs hitting the same target within minutes) reveals
    the coordination. Grounded in NDSS/NSDI findings on correlated botnet
    spikes."""
    rows = []
    span = int((end - start).total_seconds())
    for _ in range(n_campaigns):
        # real botnets mostly target default/common accounts (routers, IoT),
        # but keep a minority on real-looking usernames so
        # targets_default_username isn't a free shortcut for this class
        target = r.choice(DEFAULT_USERNAMES) if r.random() < 0.75 else r.choice(REAL_USERNAMES)
        n_bots = r.randint(10, 40)
        window_minutes = r.uniform(3, 15)
        spike_start = start + timedelta(seconds=r.randint(0, span))
        for _ in range(n_bots):
            ip = random_public_ip(r, used_ips)
            t = spike_start + timedelta(seconds=r.uniform(0, window_minutes * 60))
            n_fail = r.randint(2, 6)
            for _ in range(n_fail):
                rows.append(dict(Timestamp=t, Event="Failed password", Username=target,
                                  Source_IP=ip, Source_Port=random_ephemeral_port(r),
                                  Password=f"pass{r.randint(1000,99999)}",
                                  Attack_Type="coordinated_botnet_spike", Label=1))
                t += timedelta(seconds=r.uniform(0.5, 5))
    return rows


# ================================================================ main ====
PATTERN_COUNTS = {
    # legit
    "legit_success": 620,
    "legit_typo": 480,
    "shared_ip_legit": 45,
    "legit_multi_ip_roaming": 55,      # NEW
    "ambiguous_legit": 70,
    # attack
    "burst_bruteforce": 440,
    "focused_bruteforce": 70,
    "low_and_slow": 65,
    "password_spray": 50,
    "ambiguous_attack": 65,
    "large_dictionary_scanner": 30,    # NEW
    "credential_stuffing": 45,         # NEW
    "persistent_multiday_attacker": 12,# NEW (each is many sessions -> many rows)
    "coordinated_botnet_spike": 10,    # NEW (each is many sessions -> many rows)
}

GENERATORS = {
    "legit_success": gen_legit_success,
    "legit_typo": gen_legit_typo,
    "shared_ip_legit": gen_shared_ip_legit,
    "legit_multi_ip_roaming": gen_legit_multi_ip_roaming,
    "ambiguous_legit": gen_ambiguous_legit,
    "burst_bruteforce": gen_burst_bruteforce,
    "focused_bruteforce": gen_focused_bruteforce,
    "low_and_slow": gen_low_and_slow,
    "password_spray": gen_password_spray,
    "ambiguous_attack": gen_ambiguous_attack,
    "large_dictionary_scanner": gen_large_dictionary_scanner,
    "credential_stuffing": gen_credential_stuffing,
    "persistent_multiday_attacker": gen_persistent_multiday_attacker,
    "coordinated_botnet_spike": gen_coordinated_botnet_spike,
}


def build_dataset(seed, count_scale=1.0, day_span=30):
    r, npr = make_rng(seed)
    start = datetime(2024, 8, 1)
    end = start + timedelta(days=day_span)
    used_ips = set()
    sid_pool = None

    all_rows = []
    for pattern, base_n in PATTERN_COUNTS.items():
        n = max(1, int(round(base_n * count_scale)))
        rows = GENERATORS[pattern](n, r, npr, start, end, used_ips, sid_pool)
        all_rows.extend(rows)

    df = pd.DataFrame(all_rows)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    df["Log_ID"] = [f"LOG_{i+1:06d}" for i in range(len(df))]
    return df


def assign_sessions(df):
    """A Session_ID groups one continuous burst of activity from one
    Source_IP: events from the same IP more than SESSION_GAP_SECONDS apart
    start a new session. This mirrors the real-world session-segmentation
    rule (time-gap per Source_IP) noted as future work in v2."""
    SESSION_GAP_SECONDS = 600  # 10 min
    df = df.sort_values(["Source_IP", "Timestamp"]).reset_index(drop=True)
    gap = df.groupby("Source_IP")["Timestamp"].diff().dt.total_seconds()
    new_session = (gap.isna()) | (gap > SESSION_GAP_SECONDS)
    df["_sess_local"] = new_session.groupby(df["Source_IP"]).cumsum()
    df["Session_ID"] = df["Source_IP"] + "_S" + df["_sess_local"].astype(str)
    df = df.drop(columns=["_sess_local"])
    return df.sort_values("Timestamp").reset_index(drop=True)


def main():
    print("Building main dataset (seed=42)...")
    df_main = build_dataset(seed=42, count_scale=1.0, day_span=30)
    df_main = assign_sessions(df_main)
    df_main = df_main[["Log_ID", "Timestamp", "Event", "Username", "Source_IP",
                        "Source_Port", "Password", "Session_ID", "Attack_Type", "Label"]]
    df_main.to_csv("ssh_dataset_v3.csv", index=False)
    print(f"Main: {df_main.shape}, sessions: {df_main['Session_ID'].nunique()}")
    print(df_main.drop_duplicates('Session_ID')['Attack_Type'].value_counts())

    print("\nBuilding OOD dataset (seed=777, shifted scale + different day span)...")
    df_ood = build_dataset(seed=777, count_scale=0.85, day_span=45)
    df_ood = assign_sessions(df_ood)
    df_ood = df_ood[["Log_ID", "Timestamp", "Event", "Username", "Source_IP",
                      "Source_Port", "Password", "Session_ID", "Attack_Type", "Label"]]
    df_ood.to_csv("ssh_dataset_v3_ood.csv", index=False)
    print(f"OOD: {df_ood.shape}, sessions: {df_ood['Session_ID'].nunique()}")
    print(df_ood.drop_duplicates('Session_ID')['Attack_Type'].value_counts())


if __name__ == "__main__":
    main()
