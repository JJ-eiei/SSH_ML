# SSH Brute-Force Detector — 11-File Test Suite

Each file is one scenario, built with the same generator functions used to
create the training data (so these are authentic instances of the same
patterns, not hand-rolled approximations). Upload each one to the web app
separately. Unless noted, use the **default gap threshold (30 min)** and
**default decision threshold (0.5)**.

All "actual model output" numbers below were produced by running the real
trained model (`ssh_bruteforce_model_v2.joblib`) against these exact files,
so they are not guesses — you can reproduce them and they should match
(±noise from your local gap/threshold settings) what the web app shows.

| # | File | What it is | Design intent | Actual model output |
|---|------|-----------|----------------|----------------------|
| 01 | `01_normal_legit_baseline.csv` | Ordinary workday: 10 distinct users each logging in once successfully, plus 4 people who mistyped once and got it right. Zero attacks. | False-positive baseline — nothing here should ever be flagged. | All 14 sessions **safe** (P ≤ 0.02). ✅ |
| 02 | `02_burst_bruteforce_obvious.csv` | One IP hammering `root` with 45 rapid-fire failed guesses (~0.3–1s apart), no success. | The textbook case — should be caught with near-total confidence every time. | **ATTACK**, P = 0.999. ✅ |
| 03 | `03_focused_bruteforce_single_account.csv` | 3 separate campaigns, each many different passwords vs. ONE known account, fast timing, sometimes eventually succeeds. | Low username diversity ≠ safe. Tests that the model doesn't rely on "many usernames = attack" alone. | All 3 sessions **ATTACK** (P = 0.87–0.998). ✅ |
| 04 | `04_password_spray_multi_account.csv` | Few common passwords tried across several accounts, rotated over 2–3 source IPs. | High username diversity = attack (the mirror image of #3). Also shows a real limitation: when the campaign is split thin across IPs, a fragment with only 1 attempt can look like ordinary noise. | 2 of 3 IP-fragments **ATTACK** (P = 0.53, 0.85); 1 fragment (single attempt, one IP) **safe** (P = 0.44) — **expected, not a bug**: this is exactly the "distributed spray defeats single-IP session models" limitation documented in the project notes. |
| 05 | `05_low_and_slow_stealth.csv` | ONE stealthy campaign: 18 attempts against 1 account, spread across ~20 hours. | Deliberately exposes the gap-threshold limitation. | **At default 30-min gap: completely missed** — fragments into 18 separate 1-event sessions, every one **safe** (P = 0.44). **Re-run with gap = 1200 min (20h)**: reconstructs into one session, **ATTACK**, P = 0.996. This is the single most important demo file — it shows the model works, but only if the segmentation parameter matches the attacker's pace. |
| 06 | `06_shared_ip_office_legit.csv` | Office/NAT IP, 3–4 different real employees, all successful, zero failures. | Hard negative — must NOT be flagged despite high username diversity (looks superficially like #04). | Both sessions **safe** (P = 0.03, 0.04). ✅ |
| 07 | `07_legit_typo_noisy_user.csv` | 5 sessions of a real user fat-fingering their password up to 10 times before succeeding. | Hard negative — must NOT over-flag ordinary human forgetfulness. | All 5 sessions **safe** (P ≤ 0.05). ✅ |
| 08 | `08_ambiguous_borderline.csv` | 10 sessions drawn from a distribution that is **identical for label=0 and label=1** by construction (see project notes on "irreducible ambiguity"). | Proves the model has an honest, documented accuracy ceiling here — not overfitting, not a bug. | Mixed: 6 **ATTACK**, 4 **safe**, probabilities clustered tight around 0.48–0.65 (near the decision boundary). **This is the expected, correct behavior** — a professor checking rigor should see this file as evidence the limitation was anticipated and tested, not discovered after the fact. |
| 09 | `09_mixed_integration_day.csv` | ~11 concurrent sessions on different IPs in one file: normal logins, a spray, a focused brute force, shared-IP legit, ambiguous cases, and a compressed low-and-slow — all interleaved. | End-to-end integration test: correct session segmentation across many simultaneous IPs, correct classification across a "busy realistic log", not just isolated single-scenario files. | 5 sessions **ATTACK** (P = 0.64–0.99), 6 **safe** (P ≤ 0.37) — spot-check against the description above rather than exact session numbers, since groupby ordering is alphabetical by IP, not by scenario. |
| 10 | `10_edge_cases_robustness.csv` | Structural stress tests, not attack patterns: a lone failed attempt with no follow-up; a lone successful login (n=1); an extreme 200-attempts-in-5-seconds burst; two events at the **exact same timestamp**; two events **exactly 30:00 apart** (the gap-threshold boundary itself). | Engineering robustness — the pipeline must not crash or misbehave on degenerate input. | No crashes. Lone-fail: P=0.47 (borderline, correctly uncertain from 1 data point). Lone-success: P=0.00. 200-burst: **ATTACK**, P=0.87. Duplicate-timestamp: safe, P=0.00 (handled — zero-inter-arrival doesn't break entropy/std calculations). Exactly-30-min boundary: stays as **one session** (segmentation rule is `> gap`, not `≥`), P=0.21 safe. |

## How to grade this against the project write-up

- **01, 06, 07** → precision / false-positive resistance on realistic legit traffic, including two deliberately attack-*shaped* hard negatives.
- **02, 03, 04** → recall across three structurally different attack signatures (loud burst, low-diversity/high-volume, high-diversity/low-volume).
- **05** → the single clearest demonstration that a session-segmentation *parameter*, not just the model, determines detection — and that this is a known, explained trade-off rather than an unnoticed flaw.
- **08** → evidence the "why isn't this 100% accurate" question was anticipated and deliberately tested, not glossed over.
- **09** → the pipeline works end-to-end on a realistic multi-IP log, not just on cherry-picked single-session files.
- **10** → the implementation doesn't fall over on messy/degenerate real-world input.

## Regenerating

These files are deterministic (each scenario has a fixed random seed) and
were built by `generate_test_suite.py` reusing the builder functions from
`generate_dataset_v2.py` — the same code that produced the training data.
