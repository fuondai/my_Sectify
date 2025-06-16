"""Detect which user watermark is present in a leaked audio file.

Usage:
    py -3.10 test_watermark_extract.py leaked.mp3 user1 user2 ...

This demo script focuses on our simple high-freq noise watermark.
It uses ffmpeg to band-pass 17-19 kHz and numpy correlation.
"""
from __future__ import annotations

import subprocess  # nosec B404
import sys
import hashlib
import os
from pathlib import Path
from typing import List
import numpy as np  # type: ignore

SAMPLE_RATE = 44100
DURATION = 0  # 0 => full audio
BANDPASS = "highpass=f=17000,lowpass=f=19000"


def pcm_from_audio(path: str, duration: int = DURATION) -> np.ndarray:  # noqa: D401
    """Extract mono PCM float32 from *path* using ffmpeg & band-pass filter.
    If *duration* is 0, extract entire file.
    """
    cmd = [
        "ffmpeg",
        "-v",
        "error",
        "-i",
        path,
        "-af",
        BANDPASS,
        "-ac",
        "1",
        "-ar",
        str(SAMPLE_RATE),
        *(["-t", str(duration)] if duration else []),
        "-f",
        "s16le",
        "-",
    ]
    proc = subprocess.run(cmd, capture_output=True, check=True)  # nosec B603
    pcm_int16 = np.frombuffer(proc.stdout, dtype=np.int16)
    return pcm_int16.astype(np.float32) / 32768.0


def generate_noise(seed: int, duration: int | None = None) -> np.ndarray:  # noqa: D401
    if not duration:
        duration = 60  # arbitrary long noise; will be truncated later
    """Generate the deterministic noise track for *seed* using ffmpeg anoisesrc."""
    cmd = [
        "ffmpeg",
        "-v",
        "error",
        "-f",
        "lavfi",
        "-i",
        f"anoisesrc=color=white:seed={seed}:duration={duration}:amplitude=1",
        "-af",
        BANDPASS,
        "-ac",
        "1",
        "-ar",
        str(SAMPLE_RATE),
        "-f",
        "s16le",
        "-",
    ]
    proc = subprocess.run(cmd, capture_output=True, check=True)  # nosec B603
    pcm_int16 = np.frombuffer(proc.stdout, dtype=np.int16)
    return pcm_int16.astype(np.float32) / 32768.0


def correlation(a: np.ndarray, b: np.ndarray) -> float:
    """Return Pearson correlation between arrays (truncate to same length)."""
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    a = a[:n]
    b = b[:n]
    if a.std() == 0 or b.std() == 0:
        return 0.0
    # cross-correlation (normalized)
    c = np.correlate(a - a.mean(), b - b.mean(), mode="valid")[0]
    norm = len(a) * a.std() * b.std()
    return float(c / norm) if norm else 0.0


def detect(leaked_path: str, candidate_ids: List[str]) -> None:
    print(f"🔎 Analysing {leaked_path} …")
    leaked_pcm = pcm_from_audio(leaked_path)
    print(f"   Extracted {len(leaked_pcm)/SAMPLE_RATE:.1f} s of band-passed PCM")

    best_id = None
    best_corr = -1.0

    for cid in candidate_ids:
        seed_hex = hashlib.sha256(cid.encode()).hexdigest()[:8]
        seed = int(seed_hex, 16)
        noise = generate_noise(seed)
        corr_val = correlation(leaked_pcm, noise)
        print(f"   Candidate {cid:15}: corr = {corr_val:.4f}")
        if corr_val > best_corr:
            best_corr = corr_val
            best_id = cid

    print("—— Summary ——")
    print(f"Highest correlation: {best_corr:.4f} → {best_id}")
    if best_corr < 0.02:
        print("⚠️  No strong watermark detected (corr < 0.05)")
    else:
        print(f"✅ Leaked file likely originated from viewer: {best_id}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: py -3.10 test_watermark_extract.py leaked.mp3 viewer1 viewer2 …")
        sys.exit(1)
    leak_file = sys.argv[1]
    ids = sys.argv[2:]
    if not Path(leak_file).exists():
        print(f"File {leak_file} not found")
        sys.exit(1)
    detect(leak_file, ids)
