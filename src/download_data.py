"""
Dataset Acquisition Script.

Downloads the verified academic benchmark phishing & benign URL dataset
from HuggingFace (Mitake/PhishingURLsANDBenignURLs) under CC-BY-SA-4.0 license.
Validates file integrity and ensures clean CSV formatting.
"""

import os
import sys
import urllib.request
from pathlib import Path
import pandas as pd

DATASET_URL = "https://huggingface.co/datasets/Mitake/PhishingURLsANDBenignURLs/resolve/main/PhishBenignDataset.csv"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data"
OUTPUT_FILE = OUTPUT_DIR / "dataset.csv"

def download_dataset(force: bool = False, max_records: int = None) -> Path:
    """
    Downloads the dataset to data/dataset.csv if not already present.
    
    Args:
        force: If True, redownload even if file exists.
        max_records: If specified, truncates to this number of valid rows.
        
    Returns:
        Path: Path to the validated dataset.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    if OUTPUT_FILE.exists() and not force:
        print(f"[+] Dataset already exists at {OUTPUT_FILE} ({OUTPUT_FILE.stat().st_size / (1024*1024):.2f} MB)")
        return OUTPUT_FILE

    print(f"[*] Downloading academic benchmark dataset from:\n    {DATASET_URL}")
    print(f"[*] Destination: {OUTPUT_FILE}")
    
    req = urllib.request.Request(
        DATASET_URL,
        headers={"User-Agent": "AI-Phishing-Detector/1.0 (Academic Research; Python urllib)"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response, open(OUTPUT_FILE, "wb") as out_f:
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            block_size = 64 * 1024
            while True:
                buffer = response.read(block_size)
                if not buffer:
                    break
                downloaded += len(buffer)
                out_f.write(buffer)
                if total_size > 0:
                    pct = (downloaded / total_size) * 100
                    sys.stdout.write(f"\rDownloading: {downloaded / (1024*1024):.2f} MB / {total_size / (1024*1024):.2f} MB [{pct:.1f}%]")
                    sys.stdout.flush()
        print("\n[+] Download completed successfully.")
    except Exception as exc:
        if OUTPUT_FILE.exists():
            OUTPUT_FILE.unlink(missing_ok=True)
        print(f"\n[-] Error downloading dataset: {exc}")
        raise

    # Validation
    print("[*] Validating downloaded dataset structure...")
    df = pd.read_csv(OUTPUT_FILE, on_bad_lines="skip")
    print(f"[+] Initial row count: {len(df):,}")
    
    # Standardize column names
    df.columns = [c.strip().lower() for c in df.columns]
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(f"Expected 'url' and 'label' columns, got: {list(df.columns)}")
    
    # Drop invalid or empty rows
    df = df.dropna(subset=["url", "label"])
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    
    # Keep binary 0 and 1
    df = df[df["label"].isin([0, 1])]
    
    # Remove duplicates
    df = df.drop_duplicates(subset=["url"])
    print(f"[+] Cleaned row count: {len(df):,} (Benign: {(df['label'] == 0).sum():,}, Phishing: {(df['label'] == 1).sum():,})")
    
    if max_records and len(df) > max_records:
        print(f"[*] Subsampling to balanced {max_records:,} records for rapid development...")
        half = max_records // 2
        df_0 = df[df["label"] == 0].sample(n=min(half, (df["label"] == 0).sum()), random_state=42)
        df_1 = df[df["label"] == 1].sample(n=min(half, (df["label"] == 1).sum()), random_state=42)
        df = pd.concat([df_0, df_1]).sample(frac=1.0, random_state=42).reset_index(drop=True)
        print(f"[+] Subsampled to {len(df):,} records.")
    
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"[+] Final dataset saved at {OUTPUT_FILE}")
    return OUTPUT_FILE

if __name__ == "__main__":
    download_dataset()
