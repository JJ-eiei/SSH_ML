# SSH Brute-Force Detector — web app (v4)

Plain HTML/CSS/JS, no build step. One multiclass Random Forest tells, for
every SSH session in a log, **whether it is an attack and which behaviour it
is**:

| Group | Class | Shown as | MITRE ATT&CK |
|---|---|---|---|
| Legit | `legit_login` | Login ปกติ | – |
| Legit | `legit_typo` | ผู้ใช้พิมพ์รหัสผิด | – |
| Legit | `shared_ip_legit` | หลายคนใช้ IP ร่วม | – |
| Attack | `burst_bruteforce` | Burst brute force | T1110.001 |
| Attack | `focused_bruteforce` | Focused brute force | T1110.001 |
| Attack | `large_dictionary_scanner` | Dictionary scanner | T1110.001 |
| Attack | `low_and_slow` | Low-and-slow | T1110.001 |
| Attack | `persistent_multiday_attacker` | Persistent multi-day | T1110.001 |
| Attack | `coordinated_botnet_spike` | Botnet spike | T1110 |
| Attack | `password_spray` | Password spraying | T1110.003 |
| Attack | `credential_stuffing` | Credential stuffing | T1110.004 |

**Decision rule** (identical in `js/model.js`, `../backend/pipeline.py` and
`../v3/train_multiclass_model.py`): risk = sum of the 8 attack-class
probabilities; `risk >= threshold` → Attack, labelled with the most likely
attack class; otherwise Legit, labelled with the most likely legit class.
Label confidence below 0.6 is shown as "ไม่แน่ใจ (ใกล้เคียง …)". Default
threshold 0.57 (chosen by 5-fold CV on the training set), session gap 10
minutes (the gap the training sessions were built with).

Model results (see `../v3/ssh_multiclass_pipeline.ipynb`): Attack/Legit F1
0.984 test / 0.985 OOD, 0 false positives on both, class macro-F1 0.991 /
0.992. Synthetic data only — not validated on real traffic.

## Run it

Serve over `http://` (Chrome/Edge block `fetch()` from `file://`):
double-click `run.bat`, or `python -m http.server 8000` here and open
`http://localhost:8000`.

`config.js` decides where the model runs: `API_BASE_URL` set → the CSV is
sent to the FastAPI backend; empty → everything runs in the browser
(`js/model.js` + `model/forest.json`). Both give the same results (checked
session by session: 2,905 sessions, 0 label mismatches, max risk difference
3e-8). The Live Console and the log generator always run in the browser.

## What the page does

1. **Upload a log** — CSV in the training format, or a **raw OpenSSH
   auth.log / journalctl export** (converted to CSV in the browser by
   `js/auth-log.js`). The expected formats are explained on the page under
   "รูปแบบไฟล์ที่รองรับ".
2. **Generate a new test log** (`js/log-generator.js`, `js/generator-ui.js`)
   — pick any of the 11 behaviours and how many; IPs, times, ports and counts
   are drawn fresh from a seeded RNG, never reusing IPs from the 10 demo
   logs. The CSV given to the model has no labels; the answer key stays in
   memory and the page grades the result per class ("ตรวจคำตอบเทียบเฉลย").
   Both the CSV and the answer key can be downloaded.
3. **10 demo test logs** (`test_logs/`) — 4 legit, 6 attacks.
4. **Live Attack Console** (`js/live-console.js`) — type password guesses
   or play a preset (Burst / Focused / Password Spray / Credential Stuffing)
   and watch the risk score and behaviour label update after every attempt.

### Log generator: how it was checked

The generator is a line-by-line port of `../v3/generate_v3_dataset.py`
(ranges, probabilities, username pools; class mix weights 620:55 for
legit_success:roaming and 480:70 for legit_typo:ambiguous_legit, as in the
training data). `ambiguous_attack` (an attack generated to look exactly like a
user mistyping) is not offered — it is not one of the model's classes.

- Per-campaign statistics of JS vs Python generators over thousands of
  campaigns: KS distance ≤ 0.03 for nearly all statistics.
- Feature extraction in the browser reproduces the training features on the
  raw OOD log for all 3,316 sessions (differences ≤ 1 ms of timestamp
  precision).
- Over 300 random "ผสมทุกแบบ" runs the page scores 99.7% on average; about
  two thirds of runs are exactly 100%, the rest miss 1–2 sessions (mostly a
  short focused brute force or a small spray session that looks like a
  mistyping user). That is the model's real accuracy, not a generator bug.

### Live Console presets

Each preset logs the same attempt counts, timing and success rates as the
training generator (lines still appear 90 ms apart on screen; only the logged
timestamps follow the real pattern). Over 2,000 simulated runs each, all four
presets are flagged and labelled correctly 100% of the time. Focused starts
at 15 failed attempts: below ~13 failures on a real-looking account it
overlaps a mistyping user by design (typing a few wrong passwords by hand
shows that: the label is "ผู้ใช้พิมพ์รหัสผิด"). The console simulates one
IP in one session, so Persistent multi-day and Botnet can only be shown with
test logs 09/10 or the generator.

## Files

- `index.html`, `style.css` — the page
- `js/features.js` — CSV parsing (strict ISO timestamps, trimmed fields),
  session segmentation, the 16 features. Mirrors `../backend/pipeline.py`.
- `js/model.js` — `SSHModel` (multiclass forest walker, float32 split
  comparison like sklearn) + `decideClass` (the decision rule)
- `js/class-info.js` — names, Thai descriptions, MITRE IDs, "signal" text
- `js/app.js` — upload → pipeline → table / summary / answer check
- `js/auth-log.js` — raw sshd log → CSV (syslog and ISO timestamps,
  `message repeated N times`, invalid-user probe de-duplication,
  keyboard-interactive/pam, IPv6, BOM/CRLF)
- `js/log-generator.js`, `js/generator-ui.js` — the generator panel
- `js/live-console.js` — the simulated terminal
- `model/forest.json` — exported model (written by
  `../v3/train_multiclass_model.py`, max difference vs sklearn ~2e-8)

## Known limitations

- Trained on synthetic data; not validated on real attack traffic.
- Blind spots: an attack shaped exactly like a mistyping user
  (`ambiguous_attack`, 0% in v3 as well), focused brute force with few
  attempts against a real-looking account, and attacks with perfectly
  regular timing.
- IP-level and time-window features only see what is in the uploaded file;
  short files carry less history. A production system would need a
  persistent store keyed by IP/username.
- Roaming users (one user, several IPs) are labelled "Login ปกติ" — a
  user-level feature would be needed to name them separately.
