# SSH Brute-Force Detector — model test page (v3)

Plain HTML/CSS/JS, no build step, no backend required by default. All
parsing, feature extraction, and model inference run in the browser.

## Run it

Double-clicking `index.html` will **not** work — Chrome/Edge block `fetch()`
for local `file://` resources, and this page uses `fetch()` to load
`model/forest.json` and the test logs. Serve it over `http://` instead:

- **Easiest**: double-click `run.bat`. It starts `python -m http.server 8000`
  in this folder and opens `http://localhost:8000` in your browser.
- **Manual**: open a terminal here and run `python -m http.server 8000`,
  then open `http://localhost:8000`.

## Live Attack Console

A third way to test the model, alongside uploading a file and loading a
canned demo: a fake SSH terminal (`js/live-console.js`) where you type
password guesses yourself, or click a preset (Burst / Focused / Password
Spray / Credential Stuffing) to watch it play out automatically. Every
attempt is scored live through the exact same `SSHFeatures`/`SSHModel`
pipeline as everything else on this page — always client-side, regardless
of `config.js`. Nothing is a real server or real auth; it only builds an
in-memory log in the same schema the model expects and re-scores it after
every line.

Two things worth trying:
- Type slowly by hand vs. run a preset — the risk score usually rises much
  faster for the preset, because `attempts_per_minute` reflects real
  automation speed vs. human typing speed. That gap *is* the signal.
- After ~8 failed guesses a hint reveals the password. Log in successfully
  and watch the score often *drop* even though most of the session was
  fails — `ends_after_success` is one of the model's higher-weight
  features, so "many fails then a clean success" reads closer to a
  legit-typo user than a still-failing attacker. Worth pointing out when
  demoing: it's a real, inspectable model behavior, not a bug.

Scope note: this only simulates a single attacking IP (manual or preset).
It intentionally does not simulate a coordinated multi-IP botnet spike or a
persistent multi-day campaign live in the terminal — those two behaviors
are still fully demonstrated via the `09`/`10` canned test logs, which
already carry the multi-session/multi-IP history those features need.

## What's new in v3

- **Event vocabulary expanded**: `Invalid user` and `Accepted publickey`,
  on top of v2's `Failed password` / `Accepted password`.
- **IP-level features**: aggregated across a Source_IP's entire history in
  the uploaded file (`ip_session_count`, `ip_active_span_days`,
  `ip_sessions_per_day`, `ip_total_events`) — catches persistent, low-volume
  campaigns that look innocuous session-by-session.
- **Cross-IP time-window feature**: `distinct_ips_same_target_15min` —
  catches coordinated/botnet spikes where many different IPs hit the same
  account within a short window; no single IP's session shows this alone.
- Both new feature families are computed **from whatever is in the
  uploaded file** — a self-contained demo log (one IP's full multi-day
  campaign, or many IPs' bursts against one account) needs no external or
  persistent state to score correctly. A production deployment scoring a
  rolling window of live traffic would need this history to come from a
  persistent store instead — see the notebook's closing section.
- Deployed model switched from XGBoost (best by a 0.0003 PR-AUC margin) to
  **RandomForest**, to keep the pure-JS tree-traversal engine (`js/model.js`,
  unchanged from v2) — same verified-against-sklearn approach as before.

## What's in here

- `index.html` / `style.css` — the page
- `js/features.js` — CSV parsing, session segmentation (time-gap per
  Source_IP), and the full v3 feature set (session + IP-level +
  time-window). Mirrors `../backend/pipeline.py` exactly — keep both in
  sync if either changes.
- `js/model.js` — pure-JS traversal of the trained Random Forest (unchanged
  from v2; it's generic over whatever `feature_columns` the forest.json
  says). Verified against the real sklearn model: max probability
  difference ~1.6e-8 (floating-point rounding only).
- `js/app.js` — wires upload → pipeline → results table
- `model/forest.json` — the exported v3 model (400 trees, depth 8, ~960 KB)
- `sample-log.csv` — a small demo log covering a few patterns
- `test_logs/` — 10 self-contained demo logs for the test-suite panel (see
  their in-page descriptions); `01`–`04` are safe/hard-negative, `05`–`10`
  are attacks, with `08`–`10` specifically showcasing v3's new feature
  families (credential stuffing needs the new event vocabulary; persistent
  multi-day needs IP-level aggregation; botnet spike needs the time-window
  feature) — each verified against the model before publishing (see
  `verify_demo_logs.py` in the `v3/` working folder).
- `export_model_v3.py` — the export script (Python, sklearn) that produced
  `model/forest.json` from `ssh_bruteforce_model_v3.joblib`

## Using the page

1. Load a log CSV (must have `Timestamp, Event, Username, Source_IP,
   Source_Port` columns — `Log_ID`/`Password` are ignored if present,
   `Password` is never used as a feature) or click "ใช้ไฟล์ตัวอย่าง" for the
   bundled sample, or load one of the 10 test-suite cards.
2. Adjust **session gap threshold** (minutes) if needed.
3. Adjust the **decision threshold** slider to see the precision/recall
   trade-off live.
4. Click a row to expand the raw log lines behind that session's score.

## Known limitations (carried over from the model itself)

- Trained entirely on synthetic data — see `../v3/ssh_bruteforce_pipeline_v3_executed.ipynb`
  for the full evidence trail (feature verification, permutation
  importance, group ablation, OOD generalization check). Not validated
  against real attack traffic.
- `ambiguous_attack`-style cases (deliberately built to look statistically
  identical to a legit typo-prone user) are effectively undetectable from
  log-derived features alone — this is a property of the feature space,
  not a bug, and is documented in the notebook. None of the 10 demo files
  use this pattern (it would not "show off" detection, since it's a known,
  by-design blind spot) — ask if you'd like an 11th file added specifically
  to demonstrate it.
- IP-level and time-window features only see what's in the uploaded file;
  a real deployment scoring a live rolling window of traffic needs a
  persistent store keyed by Source_IP/username, not just this page.
