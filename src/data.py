"""Dataset helpers.

Training data = UCI SMS Spam Collection (downloaded on demand) plus a small
handwritten set of modern, India-focused scam and genuine messages
(data/extra_messages.csv) because the UCI set is mostly older UK/US SMS.
"""

from __future__ import annotations

import io
import urllib.request
import zipfile
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
SMS_CSV = DATA_DIR / "sms_spam.csv"
EXTRA_CSV = DATA_DIR / "extra_messages.csv"

SMS_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
_MAX_DOWNLOAD_BYTES = 5_000_000


def download_sms_dataset(dest: Path = SMS_CSV) -> int:
    """Download the UCI SMS Spam Collection and save it as label,text CSV.

    The archive is read in memory (only one named file is extracted), so
    nothing from the zip is ever written to disk except our own CSV.
    """
    with urllib.request.urlopen(SMS_URL, timeout=60) as resp:
        payload = resp.read(_MAX_DOWNLOAD_BYTES)
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        raw = zf.read("SMSSpamCollection").decode("utf-8")

    rows = [line.split("\t", 1) for line in raw.splitlines() if "\t" in line]
    df = pd.DataFrame(rows, columns=["label", "text"])
    df = df[df["label"].isin(["ham", "spam"])]
    dest.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(dest, index=False)
    return len(df)


def load_training_data() -> pd.DataFrame:
    """Return a de-duplicated DataFrame with columns text, is_scam (0/1), source."""
    if not SMS_CSV.exists():
        raise FileNotFoundError(f"{SMS_CSV} not found. Run: python -m src.data")
    sms = pd.read_csv(SMS_CSV).assign(source="uci_sms")
    frames = [sms]
    if EXTRA_CSV.exists():
        frames.append(pd.read_csv(EXTRA_CSV).assign(source="extra"))

    df = pd.concat(frames, ignore_index=True).dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df["text"] != ""].drop_duplicates(subset="text")
    df["is_scam"] = (df["label"] == "spam").astype(int)
    return df[["text", "is_scam", "source"]].reset_index(drop=True)


if __name__ == "__main__":
    n = download_sms_dataset()
    print(f"Saved {n} messages to {SMS_CSV}")
