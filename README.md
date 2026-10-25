# Node Sentinel

A local-first network alert investigator: transparent rules detect unusual traffic,
and a small open-weight model running on your own laptop explains each alert using
read-only analysis tools. No cloud AI, no data leaves the machine.

**Track:** Narrow Agentic Tools | **Team:** _[Node Sentinel: Gaurvanshi Jain, Lakshmi Upadhyay, Shreyan Dhar, Varun Rastogi]_ | **Event:** Hack Day Jaipur 2026

---

## Problem statement & target user

Students, small IT teams and junior SOC analysts get raw network logs or threshold
alerts like *"172.16.0.1: 154 > 50"*, which say **that** something is unusual but not
**what it might mean** or **what to check next**. Reading thousands of flow records
by hand is slow, and pasting private network logs into a cloud chatbot is often not allowed.

**Node Sentinel does one job:** take a selected alert, gather the facts with fixed
analysis tools, and produce a cautious, evidence-based explanation, entirely offline.

## Approach, architecture & demo

```
CICIDS2017 flow CSV
      │
      ▼
backend/data_loader.py ── validate, fix timestamps, drop bad rows
      │
      ▼
backend/detector.py ───── 60 s windows per source → 2 rules → merged alerts   (deterministic)
      │
      ▼
backend/storage.py ────── SQLite: flows, alerts, investigation history
      │
      ▼  user clicks "Investigate"
agent/investigator.py ─── local model (Ollama) ⇄ agent/tools.py (read-only, alert-scoped)
      │                    ├─ get_alert_details
      │                    ├─ count_distinct_ports
      │                    └─ summarize_time_window
      ▼
validate report ───────── schema check · over-confidence filter · number-grounding check
      │                    └─ on failure: one retry, then deterministic fallback report
      ▼
frontend/app.py (Streamlit) ─ overview · alert cards · live agent steps · AI report · accuracy
```

### Project structure

```
frontend/      app.py — Streamlit dashboard (dark theme in .streamlit/config.toml)
backend/       config.py (all thresholds) · models.py · data_loader.py · detector.py
               storage.py (SQLite) · evaluation.py (scores rules against labels)
agent/         investigator.py (local-model agent + guardrails) · tools.py (read-only tools)
data/          sample_data/ — demo CSV excerpts from CICIDS2017
scripts/       make_sample.py (builds the samples) · repeat_runs.py (3-run reliability log)
tests/         pytest suite, incl. an end-to-end UI test
results/       repeat-run logs (port scan, DDoS)
graphify-out/  Graphify codebase graph
```

**Core principle:** the *rules* decide that an alert exists; the *AI* explains the
evidence. The model never sees the dataset's ground-truth labels.

### Detection rules

| Rule | Fires when (per source, per 60 s window) | Why this threshold |
|---|---|---|
| `connection_burst` | more than **3,000 flows** | Benign hosts in CICIDS2017 peaked at ~2,100 flows/min |
| `port_spread` | more than **50 distinct destination ports below 1024** | Benign hosts peaked at 10; counting *all* ports caused false alarms from server reply traffic (up to 1,894 high ports/min) |

Consecutive triggering windows from the same source are merged into one alert.
Thresholds are demo settings chosen from benign traffic in this dataset, not universal rules.

### The agent (narrow, visible, guarded)

1. The model receives only the alert ID and is told to gather facts with tools.
2. It requests `get_alert_details`, `count_distinct_ports`, `summarize_time_window`.
   The **app** executes them, and only for the selected alert. The dashboard shows
   every call, its arguments and its output, and says whether the model or the app requested it.
3. The model writes a JSON report (summary, observed evidence, possible explanations,
   confidence, uncertainty, safe checks, missing information).
4. Guardrails: required fields; wording like "confirmed"/"definitely" is rejected;
   automatic blocking is rejected; numbers quoted as evidence are checked against the
   tool outputs; repeated tool calls are not re-run; output length is capped.
5. If the model is offline or fails validation twice, a **deterministic fallback
   report** built from the same tool outputs is shown, clearly labelled.

### Demo

1. `data/sample_data/portscan_sample.csv` → **Run detection** → 2 alerts from `172.16.0.1`.
2. *Overview* tab: red bands mark the alert minutes. *Investigate* tab: the port-spread alert is selected first; its gauge shows 154 service ports vs 50 allowed.
3. **Investigate with local AI** → each tool call appears live as the agent runs it → read the hedged report.
4. Stop Ollama and investigate again → fallback report appears; the app keeps working.
5. *Accuracy* tab → precision/recall against the dataset's labels.
6. `benign_sample.csv` → 0 alerts.

_[https://drive.google.com/drive/folders/1YmuTX2CVNmCOSwaZUO3qrkxYQlFv_dPC?usp=sharing]_

## Model details

| | |
|---|---|
| Model | **Qwen3 1.7B** (`qwen3:1.7b`, default) · optional **Qwen3 4B** (`qwen3:4b`) |
| Parameters | 1.7 B (Ollama reports 2.0 B incl. embeddings); optional 4.0 B |
| Licence | Apache-2.0 |
| Runtime | Ollama 0.40.10, `localhost:11434`, `/api/chat` with tool calling + JSON-schema output |
| Quantization | Q4_K_M (Ollama default tags; 1.4 GB / 2.5 GB download) |
| Settings | temperature 0, seed 42, context 8,192, thinking disabled |
| Hardware tested | Intel Core Ultra 7 155H, 23.5 GB RAM, integrated GPU (inference on **CPU only**), Windows 11 |
| External APIs | **None.** All inference is local; works with Wi-Fi off |

Why 1.7B by default: on this CPU it runs at ~20 tokens/s and finishes an investigation in
~50 s. The `qwen3:4b` tag (262K context, i.e. the newer 2507 build) gives slightly
richer text but always reasons before each tool call (~400 extra tokens per call,
~3x slower), so it is offered as an option.

## Setup instructions

> **Online deployment:** the app can run on Render with the Google Gemini API instead of
> local Ollama. See [`DEPLOYMENT.md`](DEPLOYMENT.md).

1. **Prerequisites:** Python 3.10+ (tested on 3.12), [Ollama](https://ollama.com).
2. **Install dependencies**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
3. **Download the model** (once, needs internet)
   ```powershell
   ollama pull qwen3:1.7b
   ollama pull qwen3:4b   # optional
   ```
4. **Start the app**
   ```powershell
   streamlit run frontend/app.py
   ```
5. **Try the example input:** choose `sample_data/portscan_sample.csv`, press
   **Run detection**, open the *Investigate* tab (the port-spread alert is selected
   first) and press **Investigate with local AI**. The dark theme comes from `.streamlit/config.toml`, so start the app from the repository root.

Optional settings (model, thresholds, path to the full dataset) are listed in
`.env.example` and are read from environment variables.

Run the tests: `pytest` · Re-create the repeat-run log: `python scripts/repeat_runs.py`

### Input data

`data/sample_data/` holds a few minutes of real, unmodified flows (13 of the 85 columns)
from the **CICIDS2017** dataset (Canadian Institute for Cybersecurity, UNB):

| File | Flows | Content |
|---|---|---|
| `portscan_sample.csv` | 24,167 | Fri 7 Jul 2017 15:05–15:15, benign + PortScan |
| `ddos_sample.csv` | 35,417 | Fri 7 Jul 2017 15:53–15:59, benign + DDoS |
| `benign_sample.csv` | 5,875 | Mon 3 Jul 2017 09:00–09:09, benign only |

`scripts/make_sample.py` regenerates them from the full CSV files. If the full files
are placed in `../Input_csv` (or `NODE_SENTINEL_INPUT_DIR`), the app lists them too.

Data quirks handled by the loader: column names with leading spaces; Windows-1252
encoding; timestamps with minute resolution on a 12-hour clock **without AM/PM**
(times before 08:00 are read as PM, since capture ran 08:00–18:00); blank rows.

## Results

### Detection quality (against CICIDS2017 labels, never shown to the AI)

| Data | Attack flows | Flows inside alerts | Precision | Recall |
|---|---|---|---|---|
| `portscan_sample.csv` | 11,038 | 11,036 | 100% | 99.98% |
| `ddos_sample.csv` | 23,865 | 21,427 | 100% | 89.8% |
| `benign_sample.csv` | 0 | 0 | – (0 false alerts) | – |

The samples are hand-picked, so the rules were also run on **all 8 full CICIDS2017
files (~2.8 M flows)**:

| Day / file | Alerts | Attack flows | Attack flows inside alerts | Benign flows inside alerts |
|---|---|---|---|---|
| Monday (benign only, 529,918 flows) | 0 | 0 | – | **0** |
| Tuesday (FTP/SSH-Patator) | 0 | 13,835 | 0 | 0 |
| Wednesday (DoS) | 1 | 252,672 | 230,726 (DoS Hulk 99.85%; slowloris, Slowhttptest, GoldenEye, Heartbleed 0%) | 70 |
| Thursday AM (web attacks) | 0 | 2,180 | 0 | 0 |
| Thursday PM (infiltration) | 9 | 36 | 16 | 69,882 ⚠️ |
| Friday AM (botnet) | 0 | 1,966 | 0 | 0 |
| Friday PM PortScan | 6 | 158,930 | 158,553 (99.8%) | 1 |
| Friday PM DDoS | 1 | 128,027 | 124,238 (97.0%) | 0 |
| **All files** | **17** | **557,646** | **513,533 (recall 92.1%)** | **69,953 (precision 88.0%)** |

⚠️ The Thursday-afternoon alerts are false positives *by the labels*: host
`192.168.10.8` contacted many service ports. The dataset's authors describe the
infiltrated victim scanning the internal network in this period, so these flows may
be mislabelled scans, but we count them as false alarms. This is exactly the kind of
alert the AI investigator is meant to help a human triage.

Volume/port rules catch high-rate attacks (port scans, DDoS, DoS Hulk) and miss
low-rate ones (slowloris, brute force, web attacks, bots). See *Known limitations*.

### AI investigation: 3 repeated runs

`scripts/repeat_runs.py` runs the whole workflow (load → detect → store → investigate)
three times per scenario with `qwen3:1.7b` on the laptop above (CPU only):

| Scenario | Runs completed by the model (no fallback) | Tool calls requested by the model | Time per investigation | Generation speed |
|---|---|---|---|---|
| Port scan (`port_spread`, 154 vs 50) | **3 / 3** | 3 / 3 tools every run | 44–51 s | 17.0–18.5 tokens/s |
| DDoS (`connection_burst`, 8,244 vs 3,000) | **3 / 3** | 3 / 3 tools every run | 41–52 s | 18.5–20.1 tokens/s |

Detection results were identical in every run (deterministic). The AI reports
differed in wording but kept the same structure, "medium" confidence, hedged
language and correct key figures (peak value, threshold, flow count). Observed
weaknesses of the 1.7 B model: it sometimes misdescribes the time span ("within
60 seconds" for a 3-minute alert), and in the DDoS case it lists a vulnerability
scan next to a DoS flood as a possible cause.

Full logs: [`results/repeat_runs.md`](results/repeat_runs.md) (port scan) and
[`results/ddos/repeat_runs.md`](results/ddos/repeat_runs.md) (DDoS).

### Known limitations

- Rules only cover volume and port-spread patterns. Slow/stealthy scans, brute force
  (FTP/SSH-Patator), web attacks, infiltration and botnet traffic in CICIDS2017 are
  **not** detected.
- Thresholds are tuned on this dataset; another network needs its own baseline.
- Timestamps have 1-minute resolution, so 60 s is the smallest usable window.
- A 1.7 B model can still misread numbers or give generic advice; the grounding
  check flags unknown numbers but cannot catch every misstatement.
- Flow records only; no payloads, so intent can never be established.
- No live capture and no automatic blocking (by design for this prototype).

## Graphify integration

Graph: Shared in Discord: _[yes]_

```powershell
graphify extract . --code-only
graphify cluster-only . --no-label
graphify export html
```

## Future scope

Live capture from an authorised interface, per-network baselines, more rules
(brute-force, beaconing), exportable reports, and a follow-up Q&A limited to the
selected alert.

## Licence

MIT, see [`LICENSE`](LICENSE). Third-party and model licences and the dataset
citation are in [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).
