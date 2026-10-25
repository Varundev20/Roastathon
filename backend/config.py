"""Central configuration for Node Sentinel.

All thresholds live here so they are easy to find, explain and change.
Values can be overridden with environment variables (see .env.example).
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # repository root

# --- Data -----------------------------------------------------------------
SAMPLE_DIR = ROOT / "data" / "sample_data"
# Optional folder with the full CICIDS2017 CSV files (not committed to git).
INPUT_DIR = Path(os.getenv("NODE_SENTINEL_INPUT_DIR", ROOT.parent / "Input_csv"))
DB_PATH = Path(os.getenv("NODE_SENTINEL_DB_PATH", ROOT / "node_sentinel.db"))

# --- Detection ------------------------------------------------------------
# The dataset only records timestamps to the minute, so 60 s is the
# smallest window that is meaningful.
WINDOW_SECONDS = 60

# Rule 1: connection burst. Flows started by one source in one window.
# Profiling the benign traffic in CICIDS2017 (Mon/Tue/Wed/Fri) showed a
# maximum of ~2,100 flows per source per minute, so 3,000 leaves headroom.
CONNECTION_BURST_THRESHOLD = int(os.getenv("NODE_SENTINEL_BURST_THRESHOLD", 3000))

# Rule 2: port spread. Distinct destination *service* ports (< 1024)
# contacted by one source in one window. Benign hosts peaked at 10.
# Ports >= 1024 are ignored because server reply traffic goes to many
# random high (ephemeral) ports and would cause false alarms.
PORT_SPREAD_THRESHOLD = int(os.getenv("NODE_SENTINEL_PORT_SPREAD_THRESHOLD", 50))
SERVICE_PORT_LIMIT = 1024

# Windows of the same rule and source that are at most this many windows
# apart are merged into one alert.
MERGE_GAP_WINDOWS = 1

RULE_DESCRIPTIONS = {
    "connection_burst": (
        f"More than {CONNECTION_BURST_THRESHOLD} network flows started by one "
        f"source within {WINDOW_SECONDS} seconds."
    ),
    "port_spread": (
        f"More than {PORT_SPREAD_THRESHOLD} different destination service ports "
        f"(below {SERVICE_PORT_LIMIT}) contacted by one source within "
        f"{WINDOW_SECONDS} seconds."
    ),
}

# --- Local AI (Ollama) ----------------------------------------------------
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
# qwen3:1.7b is the default: on the test laptop (CPU only) it runs at ~20
# tokens/s and can skip its "thinking" step. qwen3:4b writes better text but
# always reasons before each tool call, which makes an investigation ~3x slower.
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:1.7b")
FALLBACK_MODELS = ["qwen3:1.7b", "qwen3:4b"]
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", 300))
# Temperature 0 and a fixed seed make repeated runs as consistent as
# the runtime allows.
MODEL_OPTIONS = {"temperature": 0, "seed": 42, "num_ctx": 8192}
# Output caps stop a small model from rambling (or looping) on a slow CPU.
# (qwen3:4b needs ~400 tokens of reasoning before it emits a tool call.)
MAX_TOKENS_TOOL_ROUND = 700
MAX_TOKENS_REPORT = 900
MAX_TOOL_ROUNDS = 4

# --- Hosted AI (Google Gemini) -----------------------------------------------
# Used for the internet deployment (Render), where no local Ollama exists.
# The key is only ever read from the environment; never commit it.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY", "")
GEMINI_URL = os.getenv("GEMINI_URL", "https://generativelanguage.googleapis.com/v1beta/openai")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
GEMINI_MODELS = list(dict.fromkeys([GEMINI_MODEL, "gemini-3.8-flash", "gemini-3.6-flash",
                                    "gemini-3.5-flash-lite"]))
# Gemini 3 models always "think" and thinking tokens count against the output
# cap, so the caps are higher than for the small local model.
GEMINI_REASONING_EFFORT = os.getenv("GEMINI_REASONING_EFFORT", "low")
GEMINI_MAX_TOKENS = int(os.getenv("GEMINI_MAX_TOKENS", 8192))
GEMINI_TIMEOUT_SECONDS = int(os.getenv("GEMINI_TIMEOUT_SECONDS", 120))

# "gemini" when a key is present, otherwise the local Ollama runtime.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini" if GEMINI_API_KEY else "ollama").strip().lower()


def default_model() -> str:
    return GEMINI_MODEL if LLM_PROVIDER == "gemini" else OLLAMA_MODEL
