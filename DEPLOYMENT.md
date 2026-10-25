# Deploying Node Sentinel to Render (with Gemini)

This puts the Streamlit dashboard on the internet as a Render web service. The AI
investigator uses the **Google Gemini API** instead of a local Ollama model.
Everything Render needs is already in the repository:

| File | Purpose |
|---|---|
| `render.yaml` | Render Blueprint: build/start commands, health check, env vars |
| `requirements.txt` | Python dependencies (installed by Render at build time) |
| `.python-version` / `PYTHON_VERSION` | Python 3.12 (pandas 3 needs ≥ 3.11) |
| `Procfile` | Same start command, for hosts that read a Procfile |
| `.streamlit/config.toml` | Dark theme + headless server |
| `.env.example` | Every setting the app reads, with defaults |

How the app picks the AI: if `GEMINI_API_KEY` is set (or `LLM_PROVIDER=gemini`), it uses
Gemini; otherwise it uses local Ollama as before. With no working AI at all it still runs
and shows the deterministic fallback report.

---

## 1. Get a Gemini API key (2 min)

1. Open <https://aistudio.google.com/apikey> and sign in with a Google account.
2. Click **Create API key** → copy it. Keep it secret; never commit it to git.

## 2. Push the code to GitHub

Render deploys from a Git repository. From the project folder:

```bash
git add .
git commit -m "Deploy to Render with Gemini"
git push origin main
```

Check that `.env` and `*.db` are **not** pushed (they are in `.gitignore`).

## 3. Create the service on Render — Option A: Blueprint (recommended, one go)

1. Sign in at <https://dashboard.render.com> (sign in with GitHub is easiest).
2. Click **New +** → **Blueprint**.
3. Connect your GitHub account if asked, then pick the `Network-Anomaly-Detector` repository.
4. Render reads `render.yaml` and shows one service, **node-sentinel**. It asks for the
   value of `GEMINI_API_KEY` → paste your key.
5. Click **Apply**. The first build takes ~3–5 minutes.
6. When the status turns **Live**, open the URL shown at the top
   (e.g. `https://node-sentinel.onrender.com`).

## 3. (alternative) Option B: create the web service by hand

1. **New +** → **Web Service** → pick the repository.
2. Fill in:

   | Field | Value |
   |---|---|
   | Language / Runtime | Python 3 |
   | Branch | `main` |
   | Root Directory | *(empty; or `Network-Anomaly-Detector` if the repo contains a parent folder)* |
   | Build Command | `pip install --upgrade pip && pip install -r requirements.txt` |
   | Start Command | `streamlit run frontend/app.py --server.port $PORT --server.address 0.0.0.0 --server.headless true` |
   | Instance Type | Free |

3. **Environment** → **Add Environment Variable**:

   | Key | Value |
   |---|---|
   | `GEMINI_API_KEY` | your key |
   | `LLM_PROVIDER` | `gemini` |
   | `GEMINI_MODEL` | `gemini-3.8-flash` |
   | `PYTHON_VERSION` | `3.12.10` |

4. **Advanced** → Health Check Path: `/_stcore/health`.
5. **Create Web Service** and wait for **Live**.

## 4. Check the deployment

1. Open the Render URL. The header badge should read **☁️ gemini-3.8-flash · Gemini API**.
   If it says *GEMINI_API_KEY not set*, the variable is missing; add it under
   **Environment** and Render redeploys automatically.
2. Pick `sample_data/portscan_sample.csv` → **Run detection** → 2 alerts.
3. **Investigate** tab → **Investigate with Gemini**. Tool calls appear live, then the report.
4. If you see *Fallback report · not AI*, the reason is printed in the yellow box
   (e.g. `Gemini API error 400/403/429`). See troubleshooting below.

## 5. Optional settings (Render → Environment)

| Variable | Default | Notes |
|---|---|---|
| `GEMINI_MODEL` | `gemini-3.8-flash` | Also offered in the UI: `gemini-3.6-flash`, `gemini-3.5-flash-lite` |
| `GEMINI_REASONING_EFFORT` | `low` | `low` / `medium` / `high`. Gemini 3 cannot turn thinking off |
| `GEMINI_MAX_TOKENS` | `8192` | Output cap per request (includes thinking tokens) |
| `GEMINI_TIMEOUT_SECONDS` | `120` | Per request |
| `NODE_SENTINEL_BURST_THRESHOLD` | `3000` | Rule 1 threshold |
| `NODE_SENTINEL_PORT_SPREAD_THRESHOLD` | `50` | Rule 2 threshold |

Every push to `main` redeploys automatically (`autoDeploy: true`).

## 6. Run the same setup on your laptop (optional)

```powershell
pip install -r requirements.txt
$env:GEMINI_API_KEY = "your-key"
streamlit run frontend/app.py
```

Unset `GEMINI_API_KEY` (or set `LLM_PROVIDER=ollama`) to go back to the offline Ollama mode.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Build fails on `pandas`/`streamlit` | Make sure `PYTHON_VERSION=3.12.10` is set |
| Page loads forever / "Please wait…" | Render must support WebSockets (it does); make sure the start command has `--server.address 0.0.0.0 --server.port $PORT` |
| `Gemini API error 400` / `403` | Key wrong or not enabled → create a new key in AI Studio, update `GEMINI_API_KEY` |
| `Gemini API error 404` | Model name retired → set `GEMINI_MODEL` to a current one from <https://ai.google.dev/gemini-api/docs/models> |
| `Gemini API error 429` | Free-tier rate limit → wait a minute or enable billing |
| First visit takes ~1 minute | Free Render services sleep after 15 min idle; the first request wakes them up |
| Alerts/investigations disappear | Free Render disks are temporary: the SQLite DB resets on every deploy/restart. Just press **Run detection** again. For persistence, use a paid instance with a Disk mounted at e.g. `/var/data` and set `NODE_SENTINEL_DB_PATH=/var/data/node_sentinel.db` |

## Notes on privacy and limits

- In Gemini mode, the alert facts produced by the read-only tools (IPs, ports, counts)
  are sent to Google's API. Raw CSV files and the dataset's ground-truth labels are not.
- The deployed app is public and has no login. Everyone shares one database, so one
  visitor's detection run replaces another's for the same file.
- Only the sample CSVs in `data/sample_data/` are available online; the full CICIDS2017
  files are too large for the repository.
