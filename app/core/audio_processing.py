# app/core/audio_processing.py
import subprocess  # nosec B404
import os
import base64
import re
import logging

logger = logging.getLogger(__name__)

HLS_DIRECTORY = "hls"
KEY_DIRECTORY = os.path.join(HLS_DIRECTORY, "keys")

os.makedirs(HLS_DIRECTORY, exist_ok=True)
os.makedirs(KEY_DIRECTORY, exist_ok=True)

def process_audio_to_hls(
    input_path: str,
    track_id: str,
    *,
    delete_input: bool = True,
    watermark_user: str | None = None,
    watermark_amplitude: float | None = None,
):
    """
    Converts an audio file to encrypted HLS format using ffmpeg.

    Args:
        input_path (str): Path to the input audio file.
        track_id (str): Unique ID of the track to name the output files.

    Returns:
        tuple[str, str] | tuple[None, None]: A tuple containing the path to the HLS playlist
                                and the base64 encoded encryption key, or (None, None) on failure.
    """
    # Validate inputs to mitigate path traversal or injection attacks
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

    # track_id chỉ cho phép [A-Za-z0-9_-]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", track_id):
        raise ValueError("Invalid track_id; allowed characters are A–Z, a–z, 0–9, '_' and '-'.")

    # 0. Optionally embed per-user watermark
    if watermark_user:
        from app.core.watermark import embed_watermark
        input_path = embed_watermark(input_path, watermark_user, amplitude=(watermark_amplitude or 0.002))

    # 1. Define output paths
    output_playlist_dir = os.path.join(HLS_DIRECTORY, track_id)
    os.makedirs(output_playlist_dir, exist_ok=True)
    output_playlist_path = os.path.join(output_playlist_dir, "playlist.m3u8")

    # 2. Create encryption key
    key = os.urandom(16)
    key_b64 = base64.b64encode(key).decode('utf-8')
    key_filename = f"{track_id}.key"
    key_filepath = os.path.join(KEY_DIRECTORY, key_filename)
    with open(key_filepath, "wb") as key_file:
        key_file.write(key)

    # 3. Create key info file for ffmpeg
    key_info_filename = f"{track_id}.keyinfo"
    key_info_filepath = os.path.join(KEY_DIRECTORY, key_info_filename)
    # The key URI for the HLS player. This is the absolute path to our API endpoint.
    key_uri_for_player = "key.key"  # A placeholder URI
    
    with open(key_info_filepath, "w") as key_info_file:
        # The first line is the URI for the player
        key_info_file.write(f"{key_uri_for_player}\n")
        # The second line is the path to the key file on the server's filesystem
        key_info_file.write(key_filepath)

    # 4. Build and run the ffmpeg command to create encrypted HLS
    # Chrome (MSE) thường từ chối phát HLS chỉ có audio. Chúng ta chèn một track video đen 16x16 rất nhỏ.
    input_abs = os.path.abspath(input_path)
    command = [
        "ffmpeg",
        # Audio input
        "-i", input_abs,
        # Dummy black video input
        "-f", "lavfi", "-i", "color=color=black:s=16x16:r=1",
        # Make output length follow audio (shortest)
        "-shortest",
        # Video encoding (extremely low bitrate, intra-only)
        "-c:v", "libx264", "-preset", "ultrafast", "-tune", "stillimage", "-pix_fmt", "yuv420p",
        "-r", "1",
        # Audio encoding (AAC)
        "-c:a", "aac", "-profile:a", "aac_low", "-b:a", "128k",
        # Map audio & video streams explicitly
        "-map", "0:a", "-map", "1:v",
        # HLS parameters
        "-hls_time", "6",
        "-hls_segment_type", "mpegts",
        "-hls_flags", "independent_segments",
        "-pat_period", "1",
        "-hls_list_size", "4",  # sliding window for anti-scraping
        "-hls_segment_filename", os.path.join(output_playlist_dir, "segment%03d.ts"),
        "-hls_key_info_file", key_info_filepath,
        output_playlist_path
    ]

    try:
        # Use subprocess.run to wait for completion
        # Run the command without text=True to get stdout/stderr as bytes
        logger.debug("Running FFmpeg command: %s", " ".join(command))
        result = subprocess.run(command, check=True, capture_output=True, shell=False)  # nosec B603
        logger.debug("FFmpeg stdout: %s", result.stdout)
        logger.debug("FFmpeg stderr: %s", result.stderr)
        return output_playlist_path, key_b64
    except subprocess.CalledProcessError as e:
        logger.error("Error processing audio with ffmpeg for track %s.", track_id)
        logger.error("FFmpeg stdout: %s", e.stdout)
        # Safely decode stdout/stderr, replacing invalid characters
        stdout_safe = e.stdout.decode('utf-8', errors='replace')
        stderr_safe = e.stderr.decode('utf-8', errors='replace')
        error_details = f"FFmpeg stdout: {stdout_safe}\nFFmpeg stderr: {stderr_safe}"
        logger.error("%s", error_details)
        return None, error_details
    finally:
        # Clean up the original uploaded file after processing (optional). Useful for key rotation when we want to keep the master copy.
        if delete_input and os.path.exists(input_path):
            os.remove(input_path)
