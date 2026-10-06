# Deploy to Render (free tier)

This repo has a `render.yaml` Blueprint that defines **both** services:
- `sshml-backend` — the FastAPI model API (`backend/`)
- `sshml-frontend` — the static HTML/CSS/JS page (`web/`)

## 1. Push to GitHub

```bash
git add .
git commit -m "Add backend API and Render blueprint"
git push
```

(This repo is already connected to `https://github.com/JJ-eiei/SSH_ML.git`.)

## 2. Deploy the Blueprint on Render

1. Go to https://dashboard.render.com → **New** → **Blueprint**
2. Connect the `JJ-eiei/SSH_ML` GitHub repo
3. Render reads `render.yaml` automatically and shows both services —
   confirm and click **Apply**
4. Wait for both to finish building (first backend build installs
   scikit-learn etc., takes a few minutes)

## 3. Point the frontend at the backend

Once `sshml-backend` is live, copy its URL from the Render dashboard
(something like `https://sshml-backend.onrender.com`) and put it in
`web/config.js`:

```js
window.SSHML_CONFIG = { API_BASE_URL: "https://sshml-backend.onrender.com" };
```

Commit and push that one-line change — Render auto-deploys on push
(`autoDeploy: true` in `render.yaml`), so the live frontend picks it up
without doing anything else.

Leaving `API_BASE_URL` empty keeps the page running the **client-side**
models (`js/model.js` + `model/forest.json` for Attack/Legit,
`model/forest_type.json` for the attack type) instead — both modes work from
the same codebase, so you always have a working fallback even if the
backend is asleep (see below).

## 4. Known Render free-tier behavior

- **Backend spins down after 15 minutes idle.** The first request after
  that takes ~1 minute while it wakes up — the page will just look like
  it's hanging; there's no separate loading state for this in `app.js` yet.
- **750 free instance-hours/month** shared across your account. A single
  low-traffic demo service won't come close to this.
- **Static frontend has no spin-down or hour limit.**
- CORS is limited to `https://sshml-frontend.onrender.com` and
  `http://localhost:8000` (`ALLOWED_ORIGINS` in `backend/main.py`). Add an
  origin there if the frontend moves.
- The backend loads two models: `ssh_bruteforce_model_v3.joblib` (stage 1,
  required) and `ssh_attack_type_model_v3.joblib` (stage 2, optional). If
  the second file is missing it still serves Attack/Legit, and
  `GET /health` reports `"type_model_loaded": false`.

## 5. Test before + after deploying

Local backend test (already verified working):
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
# then POST a CSV to http://127.0.0.1:8000/predict?gap_minutes=30
```

Local frontend test: `web/run.bat`, or `cd web && python -m http.server 8000`.
