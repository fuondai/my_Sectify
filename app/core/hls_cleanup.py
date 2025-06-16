"""HLS segment cleanup utility.

Tác vụ nền này sẽ tự động xóa các file `.ts` cũ nhằm giảm dung lượng lưu trữ.
Được thiết kế an toàn:
- Chỉ xóa các segment lớn hơn `age_seconds` (mặc định 10 phút).
- Giữ lại playlist `.m3u8`, khoá `.key` và những file metadata khác.
- Xóa các thư mục rỗng sau khi xoá segment.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from typing import Final

logger = logging.getLogger(__name__)

# Thư mục gốc chứa HLS
HLS_DIRECTORY: Final[str] = "hls"

# Phần mở rộng segment
_SEGMENT_EXT: Final[str] = ".ts"

async def cleanup_loop(interval_seconds: int = 120, age_seconds: int = 600) -> None:
    """Vòng lặp bất đồng bộ xoá segment cũ.

    Args:
        interval_seconds: Chu kỳ lặp lại kiểm tra, mặc định 2 phút.
        age_seconds: File cũ hơn giá trị này sẽ bị xoá, mặc định 10 phút.
    """
    logger.info("Starting HLS cleanup task: every %ss, delete segments older than %ss", interval_seconds, age_seconds)
    try:
        while True:
            # Chạy _cleanup_once trong thread để không block event loop
            await asyncio.to_thread(_cleanup_once, age_seconds)
            await asyncio.sleep(interval_seconds)
    except asyncio.CancelledError:
        logger.info("HLS cleanup task cancelled")
        raise


def _cleanup_once(age_seconds: int) -> None:
    """Xoá một lần các segment đã quá hạn."""
    now = time.time()
    for root, dirs, files in os.walk(HLS_DIRECTORY, topdown=False):
        # Xoá file .ts quá cũ
        for file in files:
            if not file.endswith(_SEGMENT_EXT):
                continue
            path = os.path.join(root, file)
            try:
                if now - os.path.getmtime(path) > age_seconds:
                    os.remove(path)
                    logger.debug("Removed old segment %s", path)
            except FileNotFoundError:
                # Có thể file đã bị xoá bởi tiến trình khác
                continue
            except Exception as exc:
                logger.error("Failed to remove segment %s: %s", path, exc)

        # Sau khi xử lý file, xoá thư mục rỗng (trừ thư mục gốc HLS)
        if root == HLS_DIRECTORY:
            continue
        try:
            if not os.listdir(root):
                shutil.rmtree(root, ignore_errors=True)
                logger.debug("Removed empty HLS directory %s", root)
        except FileNotFoundError:
            continue
        except Exception as exc:
            logger.error("Failed to remove directory %s: %s", root, exc)
