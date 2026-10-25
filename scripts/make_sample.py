"""Cut small demo samples out of the full CICIDS2017 CSV files.

The full files are 75-285 MB each, too large for GitHub, so the repository
ships a few minutes of real traffic from each scenario instead. Rows are
copied unchanged (only a subset of columns is kept), so the app loads the
samples exactly like the original files.

Usage:
    python scripts/make_sample.py --input-dir ../Input_csv
"""
import argparse
from pathlib import Path

import pandas as pd

COLUMNS = [
    "Source IP", "Source Port", "Destination IP", "Destination Port",
    "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "SYN Flag Count", "Label",
]

# (output file, source file, first minute, last minute) - times exactly as
# written in the CSV (12-hour clock without AM/PM).
SAMPLES = [
    ("portscan_sample.csv", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
     "7/7/2017 3:05", "7/7/2017 3:15"),
    ("ddos_sample.csv", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
     "7/7/2017 3:53", "7/7/2017 3:59"),
    ("benign_sample.csv", "Monday-WorkingHours.pcap_ISCX.csv",
     "03/07/2017 09:00", "03/07/2017 09:09"),
    # Detected: DoS Hulk flood (connection burst).
    ("dos_hulk_sample.csv", "Wednesday-workingHours.pcap_ISCX.csv",
     "5/7/2017 10:41", "5/7/2017 10:45"),
    # Detected, but labelled BENIGN: 192.168.10.8 sweeping many ports while
    # the infiltration attack runs (false positives by the labels).
    ("infiltration_sample.csv", "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
     "6/7/2017 3:08", "6/7/2017 3:16"),
    # Missed by design (low-rate attacks): known limitations of the rules.
    ("slow_dos_sample.csv", "Wednesday-workingHours.pcap_ISCX.csv",
     "5/7/2017 10:18", "5/7/2017 10:26"),
    ("ftp_patator_sample.csv", "Tuesday-WorkingHours.pcap_ISCX.csv",
     "4/7/2017 9:20", "4/7/2017 9:28"),
    ("web_attack_sample.csv", "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
     "6/7/2017 9:36", "6/7/2017 9:44"),
    ("bot_sample.csv", "Friday-WorkingHours-Morning.pcap_ISCX.csv",
     "7/7/2017 10:40", "7/7/2017 10:49"),
]


def minute_key(ts: str) -> str:
    """Reduce '7/7/2017 3:05' or '03/07/2017 09:00:12' to a comparable key."""
    date, time = ts.strip().split(" ")
    d, m, y = (int(p) for p in date.split("/"))
    h, mi = (int(p) for p in time.split(":")[:2])
    return f"{y:04d}{m:02d}{d:02d}{h:02d}{mi:02d}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default=Path(__file__).resolve().parents[2] / "Input_csv")
    parser.add_argument("--out-dir", default=Path(__file__).resolve().parents[1] / "data" / "sample_data")
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(exist_ok=True)

    for out_name, src_name, first, last in SAMPLES:
        df = pd.read_csv(Path(args.input_dir) / src_name, encoding="cp1252",
                         skipinitialspace=True, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df = df.dropna(subset=["Timestamp"])
        keys = df["Timestamp"].map(minute_key)
        part = df.loc[(keys >= minute_key(first)) & (keys <= minute_key(last)), COLUMNS]
        # cp1252 like the originals: the web-attack labels contain an en dash.
        part.to_csv(out_dir / out_name, index=False, encoding="cp1252")
        size_mb = (out_dir / out_name).stat().st_size / 1e6
        print(f"{out_name}: {len(part):,} rows, {size_mb:.1f} MB, "
              f"labels={part['Label'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()
