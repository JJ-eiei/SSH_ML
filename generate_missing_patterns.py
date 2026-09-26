"""
generate_missing_patterns.py

Augments ssh_dataset_features.csv with two attack patterns the original
dataset does NOT contain:

  1. Low-and-slow brute force
     - Same attacker IP, usually 1 (sometimes 2-3) target username(s)
     - Few dozen attempts spread over hours (min gap enforced), instead of
       sub-second bursts like the original "random_guess" sessions.
     - Deliberately gives LOW username diversity (n_user often == 1),
       which breaks a naive "high username diversity = attack" rule.

  2. Password spraying
     - Same attacker IP (or a small rotating pool, see MULTI_IP_SPRAY),
       1-3 passwords tried, HIGH username diversity, but only 1 (rarely 2)
       attempt per username per password -- the opposite signature of a
       classic per-account brute force burst.

Both patterns reuse the same Password-field encoding as the original file
(pass##### = random_guess, literal weak words = common_weak_pw,
***HIDDEN*** = success) so the existing label-derivation heuristic
(dominant password category -> brute force / not) still works on the
combined file. Only Event, Username, Source_IP, Source_Port, Timestamp,
Password are ever fed to a model -- Password stays label-only, never a
feature, exactly as flagged before.

Usage:
    python3 generate_missing_patterns.py
Produces:
    ssh_dataset_features_augmented.csv
"""

import random
from datetime import timedelta

import numpy as np
import pandas as pd

# ---------------------------------------------------------------- config --
RANDOM_SEED = 42
INPUT_CSV = "ssh_dataset_features.csv"
OUTPUT_CSV = "ssh_dataset_features_augmented.csv"

N_LOW_AND_SLOW_CAMPAIGNS = 25
N_SPRAY_CAMPAIGNS = 15
MULTI_IP_SPRAY_FRACTION = 0.3  # fraction of spray campaigns run from a small
                                # rotating pool of IPs instead of a single IP
                                # (distributed / coordinated spraying)

COMMON_WEAK_PASSWORDS = [
    "admin123", "111111", "admin", "system", "qwerty",
    "123456", "root", "password", "letmein", "welcome1", "123123",
]

random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)


# --------------------------------------------------------------- helpers --
def random_guess_password() -> str:
    return f"pass{random.randint(1000, 99999)}"


def random_ephemeral_port() -> int:
    return random.randint(49152, 65535)


def random_public_ip(existing: set) -> str:
    """Random-looking public IPv4, avoiding collisions with IPs already used."""
    while True:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        if ip not in existing:
            existing.add(ip)
            return ip


# ------------------------------------------------------- pattern: L&S -----
def generate_low_and_slow(n_campaigns, usernames, start, end, used_ips):
    """Sparse, long-duration brute force against 1 (rarely 2-3) usernames."""
    rows = []
    span_seconds = int((end - start).total_seconds())

    for _ in range(n_campaigns):
        ip = random_public_ip(used_ips)
        n_targets = random.choices([1, 2, 3], weights=[0.7, 0.2, 0.1])[0]
        targets = random.sample(usernames, n_targets)

        n_attempts = random.randint(8, 30)
        duration_hours = random.uniform(4, 36)
        duration_seconds = duration_hours * 3600
        min_gap = 180  # 3 min floor -- this is what makes it "slow"

        # campaign start: anywhere in the original window, but leave room
        # for the full duration (wrap by extending past `end` if needed)
        campaign_start = start + timedelta(
            seconds=random.randint(0, max(span_seconds - 3600, 0))
        )

        # gaps that sum to duration_seconds, each >= min_gap
        raw_gaps = np.random.exponential(scale=1.0, size=n_attempts - 1)
        raw_gaps = raw_gaps / raw_gaps.sum() * (duration_seconds - min_gap * (n_attempts - 1))
        gaps = np.clip(raw_gaps, 0, None) + min_gap

        succeeds = random.random() < 0.08  # low-and-slow rarely lands a hit
        t = campaign_start
        for i in range(n_attempts):
            user = random.choice(targets)
            is_last = i == n_attempts - 1
            port = random_ephemeral_port()  # new connection each time (long gaps)

            if is_last and succeeds:
                event, pw = "Accepted password", "***HIDDEN***"
            else:
                event = "Failed password"
                pw = (
                    random.choice(COMMON_WEAK_PASSWORDS)
                    if random.random() < 0.2
                    else random_guess_password()
                )

            rows.append(
                dict(Timestamp=t, Event=event, Username=user,
                     Source_IP=ip, Source_Port=port, Password=pw)
            )
            if i < n_attempts - 1:
                t = t + timedelta(seconds=float(gaps[i]))
    return rows


# ------------------------------------------------------- pattern: spray ---
def generate_password_spray(n_campaigns, usernames, start, end, used_ips):
    """Few passwords, many usernames, ~1 attempt per (user, password) pair."""
    rows = []
    span_seconds = int((end - start).total_seconds())

    for _ in range(n_campaigns):
        multi_ip = random.random() < MULTI_IP_SPRAY_FRACTION
        ip_pool = (
            [random_public_ip(used_ips) for _ in range(random.randint(2, 4))]
            if multi_ip
            else [random_public_ip(used_ips)]
        )

        n_passwords = random.randint(1, 3)
        spray_passwords = random.sample(COMMON_WEAK_PASSWORDS, n_passwords)
        n_targets = random.randint(6, len(usernames))
        targets = random.sample(usernames, n_targets)

        campaign_start = start + timedelta(
            seconds=random.randint(0, max(span_seconds - 3600, 0))
        )
        # deliberate spacing between attempts to stay under lockout thresholds
        t = campaign_start
        succeed_user = (
            random.choice(targets) if random.random() < 0.15 else None
        )

        for pw in spray_passwords:
            for user in targets:
                ip = random.choice(ip_pool)
                port = random_ephemeral_port()  # separate connection per target
                if user == succeed_user and pw == spray_passwords[-1]:
                    event, out_pw = "Accepted password", "***HIDDEN***"
                else:
                    event, out_pw = "Failed password", pw
                rows.append(
                    dict(Timestamp=t, Event=event, Username=user,
                         Source_IP=ip, Source_Port=port, Password=out_pw)
                )
                t = t + timedelta(seconds=random.uniform(20, 300))
    return rows


# -------------------------------------------------------------- main ------
def main():
    df = pd.read_csv(INPUT_CSV, parse_dates=["Timestamp"])
    used_ips = set(df["Source_IP"].unique())
    usernames = sorted(df["Username"].unique())
    start, end = df["Timestamp"].min(), df["Timestamp"].max()

    new_rows = []
    new_rows += generate_low_and_slow(
        N_LOW_AND_SLOW_CAMPAIGNS, usernames, start, end, used_ips
    )
    new_rows += generate_password_spray(
        N_SPRAY_CAMPAIGNS, usernames, start, end, used_ips
    )

    new_df = pd.DataFrame(new_rows)
    combined = pd.concat([df, new_df], ignore_index=True)
    combined = combined.sort_values("Timestamp").reset_index(drop=True)
    combined["Log_ID"] = [f"LOG_{i+1:06d}" for i in range(len(combined))]
    combined = combined[
        ["Log_ID", "Timestamp", "Event", "Username", "Source_IP", "Source_Port", "Password"]
    ]
    combined.to_csv(OUTPUT_CSV, index=False)

    # ---- quick sanity check: prove these patterns break a naive rule ----
    def pw_cat(p):
        if p == "***HIDDEN***":
            return "success"
        if p in ("fast_typo", "typo_pass"):
            return "typo"
        if p.startswith("pass") and p[4:].isdigit():
            return "random_guess"
        return "common_weak_pw"

    new_df["pw_cat"] = new_df["Password"].apply(pw_cat)
    print(f"Added {len(new_df)} rows "
          f"({N_LOW_AND_SLOW_CAMPAIGNS} low-and-slow + {N_SPRAY_CAMPAIGNS} spray campaigns)")
    print(f"Combined dataset: {len(combined)} rows -> {OUTPUT_CSV}")
    print("\nNew rows by password category:")
    print(new_df["pw_cat"].value_counts())


if __name__ == "__main__":
    main()
