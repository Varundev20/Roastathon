import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import storage  # noqa: E402
from backend.detector import detect  # noqa: E402


def make_flows(rows):
    """rows: list of (timestamp, src_ip, dst_ip, dst_port[, label])."""
    df = pd.DataFrame([r if len(r) == 5 else (*r, "BENIGN") for r in rows],
                      columns=["timestamp", "src_ip", "dst_ip", "dst_port", "label"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    for col, value in [("src_port", 50000), ("protocol", 6), ("duration_us", 100.0),
                       ("fwd_packets", 1.0), ("bwd_packets", 1.0), ("fwd_bytes", 0.0),
                       ("bwd_bytes", 0.0), ("syn_flags", 0.0)]:
        df[col] = value
    return df


def burst(src, minute, count, port=80, label="DDoS"):
    return [(f"2017-07-07 15:{minute:02d}:00", src, "192.168.10.50", port, label)] * count


@pytest.fixture
def db(tmp_path):
    return tmp_path / "test.db"


@pytest.fixture
def stored_alert(db):
    """A dataset with one port-scan alert saved to a temporary database."""
    rows = [("2017-07-07 15:00:00", "172.16.0.1", "192.168.10.50", p, "PortScan") for p in range(1, 80)]
    rows += [("2017-07-07 15:00:00", "192.168.10.5", "8.8.8.8", 53)] * 5
    flows = make_flows(rows)
    alerts = detect(flows, burst_threshold=1000, port_spread_threshold=50)
    storage.save_analysis("test.csv", flows, alerts, db_path=db)
    return alerts[0]


@pytest.fixture(autouse=True)
def local_provider(monkeypatch):
    """Tests use the Ollama code path unless a test switches to Gemini,
    even when GEMINI_API_KEY happens to be set in the shell."""
    from backend import config
    monkeypatch.setattr(config, "LLM_PROVIDER", "ollama")
