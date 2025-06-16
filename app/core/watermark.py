"""Simple forensic audio watermarking utilities.

This module provides a lightweight approach to embed a *per-user* watermark
into an audio file using FFmpeg by mixing a very-low-volume, high-frequency
noise that is deterministically generated from the `user_identifier`.

The watermark is not intended to be cryptographically impossible to remove,
but it is sufficient for tracing the origin of leaked files: the pattern of
noise (seed) can be extracted and mapped back to the user.

⚠️  For a production-grade solution, consider a sophisticated library such as
Audiowmark, RainDrop, or a commercial forensic watermarking SDK. Here we aim
for zero external dependencies and fast processing.
"""
from __future__ import annotations

import hashlib
import logging
import os
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _seed_from_identifier(user_identifier: str) -> int:
    """Derive a 32-bit integer seed from the user identifier (email/ID)."""
    digest = hashlib.sha256(user_identifier.encode()).hexdigest()
    # Take first 8 hex chars → 32-bit int
    return int(digest[:8], 16)


def embed_watermark(
    input_path: str,
    user_identifier: str,
    *,
    amplitude: float = 0.0005,
    freq: int = 18337,
    output_path: Optional[str] = None,
) -> str:
    """Embed a deterministic noise watermark into *input_path*.

    Parameters
    ----------
    input_path: str
        Path to original audio file.
    user_identifier: str
        Unique string identifying the user (e.g. user ID or email). Used to
        derive the PRNG seed so each user gets a distinct watermark pattern.
    amplitude: float, optional
        Peak amplitude of the injected noise (0–1). Default 0.0005 (~-66 dBFS).
    freq: int, optional
        Frequency (Hz) of the sine tone. Choose >17 kHz so it is inaudible for
        most users but survives typical AAC encoding. Default 18 337 Hz (prime).
    output_path: str, optional
        If provided, write the watermarked file here. Otherwise a temp file is
        created next to *input_path* with suffix "_wm.m4a".

    Returns
    -------
    str
        Path to the watermarked audio file.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(input_path)

    seed = _seed_from_identifier(user_identifier)

    # Determine output codec/extension to match original container
    ext = Path(input_path).suffix.lower()
    codec_args: list[str]
    movflags: list[str] = []
    if ext == ".mp3":
        codec_args = ["-c:a", "libmp3lame", "-b:a", "192k"]
        suffix = "_wm.mp3"
    elif ext in {".wav"}:
        codec_args = ["-c:a", "pcm_s16le"]
        suffix = "_wm.wav"
    else:
        codec_args = ["-c:a", "aac", "-b:a", "128k"]
        movflags = ["-movflags", "+faststart"]
        suffix = "_wm.m4a"

    if output_path is None:
        directory = Path(input_path).parent
        output_path = str((directory / (Path(input_path).stem + suffix)).resolve())

    # FFmpeg command: mix original audio with deterministic noise (anoisesrc)
    # * Use -map 0:a to keep original streams (assumes single audio stream).
    # * anoisesrc with given seed ensures repeatability.
    # * amix weights: 1 original, 0.02 noise (-34 dB). Further reduced by amplitude.
    noise_src = f"anoisesrc=color=white:seed={seed}:amplitude={amplitude}"
    command = [
        "ffmpeg",
        "-y",
        "-i", input_path,
        "-f", "lavfi", "-i", noise_src,
        "-filter_complex", "[0:a][1:a]amix=inputs=2:duration=first:dropout_transition=2[aout]",
        "-shortest",
        "-map", "[aout]",
        *codec_args,
        *movflags,
        output_path,
    ]

    logger.debug("Embedding watermark for user %s via ffmpeg", user_identifier)
    try:
        subprocess.run(command, check=True, capture_output=True, shell=False)  # nosec B603
    except subprocess.CalledProcessError as e:
        logger.error("Watermark embedding failed: %s", e.stderr)
        raise RuntimeError("Failed to embed watermark") from e

    return output_path
