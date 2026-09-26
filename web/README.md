# SSH Brute-Force Detector — model test page

Plain HTML/CSS/JS, no build step, no backend. All parsing, feature
extraction, and model inference run in the browser.

## Run it

Double-clicking `index.html` will **not** work — Chrome/Edge block `fetch()`
for local `file://` resources, and this page uses `fetch()` to load
`model/forest.json` and `sample-log.csv`. Serve it over `http://` instead:

- **Easiest**: double-click `run.bat`. It starts `python -m http.server 8000`
  in this folder and opens `http://localhost:8000` in your browser.
- **Manual**: open a terminal here and run `python -m http.server 8000`,
  then open `http://localhost:8000`.
- Any other static server works too (VS Code's "Live Server" extension, `npx serve`, etc.).

## What's in here

- `index.html` / `style.css` — the page
- `js/features.js` — CSV parsing, **session segmentation** (time-gap per
  Source_IP — adjustable in the UI, since this is a judgment call, not
  ground truth), and feature extraction (mirrors `extract_session_features`
  from the training notebook exactly: same 14 columns, same formulas)
- `js/model.js` — pure-JS traversal of the trained Random Forest, exported
  from `ssh_bruteforce_model_v2.joblib` via `export_model.py` (300 trees,
  depth 6) as `model/forest.json`. Verified against the real sklearn model
  on held-out sessions: max probability difference ~3.5e-8 (floating-point
  rounding only) — this is the trained model, not an approximation.
- `js/app.js` — wires upload → pipeline → results table
- `model/forest.json` — the exported model (~586 KB)
- `sample-log.csv` — a small demo log covering every pattern the model was
  trained on (burst brute force, low-and-slow, password spraying, focused
  brute force, shared-IP legit, ambiguous cases, plain legit logins)
- `export_model.py` — the export script (Python, sklearn) that produced
  `model/forest.json` from the `.joblib` file, kept here for re-export if
  the model is retrained

## Using the page

1. Load a log CSV (must have `Timestamp, Event, Username, Source_IP,
   Source_Port` columns — `Log_ID`/`Password` are ignored if present,
   `Password` is never used as a feature) or click "ใช้ไฟล์ตัวอย่าง" for the
   bundled sample.
2. Adjust **session gap threshold** (minutes) if needed — this determines
   how raw log lines from the same IP get grouped into "sessions" before
   scoring. There is no universally correct value; too short fragments a
   slow campaign, too long merges unrelated logins from a shared/NAT IP.
3. Adjust the **decision threshold** slider to see the precision/recall
   trade-off live — this only re-labels already-computed probabilities, no
   re-scoring needed.
4. Click a row to expand the raw log lines behind that session's score.

## Known limitations (carried over from the model itself)

- Trained entirely on synthetic data — see `../claude/dataset-v2-notes.md`
  (or the Project doc) for the full history of why an earlier version
  scored a suspicious 1.0 on every metric, and what changed. Not validated
  against real attack traffic.
- Session segmentation here is a simple time-gap heuristic; a coordinated
  multi-IP campaign (e.g. distributed password spraying) will not be
  recognized as one event.
