"""Every shipped sample loads and gives the documented number of alerts."""
import pytest

from backend import config
from backend.data_loader import load_flows
from backend.detector import detect

# file -> (flows kept, alerts, attack label present)
EXPECTED = {
    "portscan_sample.csv": (24167, 2, "PortScan"),
    "ddos_sample.csv": (35417, 1, "DDoS"),
    "benign_sample.csv": (5875, 0, None),
    "dos_hulk_sample.csv": (54548, 1, "DoS Hulk"),
    "infiltration_sample.csv": (23159, 3, "Infiltration"),
    "slow_dos_sample.csv": (12016, 0, "DoS Slowhttptest"),
    "ftp_patator_sample.csv": (12630, 0, "FTP-Patator"),
    "web_attack_sample.csv": (12502, 0, "Web Attack - Brute Force"),
    "bot_sample.csv": (4819, 0, "Bot"),
}


def test_every_sample_is_listed():
    assert {p.name for p in config.SAMPLE_DIR.glob("*.csv")} == set(EXPECTED)


@pytest.mark.parametrize("name", EXPECTED)
def test_sample_loads_and_detects(name):
    flows, report = load_flows(config.SAMPLE_DIR / name)
    rows, alerts, label = EXPECTED[name]
    assert report.rows_kept == rows
    assert len(detect(flows)) == alerts
    if label:
        assert label in set(flows["label"])
