"""Quick manual test for per-viewer watermark & HLS pipeline.

Run with:
    py -3.10 test_watermark_pipeline.py

Yêu cầu: đặt tệp mp3 gốc tên `j97.mp3` ở thư mục gốc project (cùng cấp script này).
Script sẽ:
1. Gọi embed_watermark() sinh file nhúng watermark cho viewer giả lập.
2. Gọi process_audio_to_hls() 2 lần:
   - Tạo bản HLS gốc (không watermark) để kiểm tra encode ok.
   - Tạo bản HLS dành cho viewer (có watermark).
3. In thông tin file và 10 dòng đầu playlist viewer.
"""
from __future__ import annotations

import os
import subprocess  # nosec B404
import uuid
from pathlib import Path

from app.core.watermark import embed_watermark
from app.core.audio_processing import process_audio_to_hls


def main() -> None:  # noqa: D401
    project_root = Path(__file__).resolve().parent
    mp3_path = project_root / "j97.mp3"

    if not mp3_path.exists():
        print("❌ File j97.mp3 not found. Copy it to project root before running this test.")
        return

    viewer_id = "viewer_test"
    print("👉 Embedding watermark …")
    wm_output = embed_watermark(str(mp3_path), viewer_id)
    print(f"✅ Watermarked file: {wm_output} (size={os.path.getsize(wm_output)} bytes)")

    base_track_id = f"testtrack_{uuid.uuid4().hex[:8]}"
    print("👉 Encoding base HLS …")
    playlist_base, key_b64 = process_audio_to_hls(str(mp3_path), base_track_id, delete_input=False)
    if playlist_base:
        print(f"✅ Base HLS playlist: {playlist_base} (key len={len(key_b64)})")
    else:
        print("❌ Base HLS generation failed")
        return

    viewer_track_id = f"{base_track_id}_{viewer_id[:8]}"
    print("👉 Encoding viewer-specific HLS …")
    playlist_viewer, _ = process_audio_to_hls(
        str(mp3_path),
        viewer_track_id,
        delete_input=False,
        watermark_user=viewer_id,
    )
    if not playlist_viewer:
        print("❌ Viewer HLS generation failed")
        return
    print(f"✅ Viewer playlist: {playlist_viewer}")

    # Print first 10 lines of viewer playlist
    print("—— Playlist head ——")
    with open(playlist_viewer, "r", encoding="utf-8") as fp:
        for _ in range(10):
            line = fp.readline()
            if not line:
                break
            print(line.rstrip())
    print("———————————")

    # Optional: verify duration with ffprobe (if installed)
    try:
        print("👉 ffprobe duration check …")
        result = subprocess.run(
            [
                "ffprobe",
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                wm_output,
            ],
            capture_output=True,
            text=True,
            check=True,
        )  # nosec B603
        print(f"Duration: {result.stdout.strip()} sec")
    except FileNotFoundError:
        print("⚠️  ffprobe not available; skipping duration check")


if __name__ == "__main__":
    main()
