"""Utility functions for generating and verifying short-lived signed URLs (JWT) for HLS resources.

Mục tiêu: cho phép truy cập công khai để "nghe" nhưng tránh việc tải, chia sẻ link bừa bãi.
Các token ngắn hạn (5 phút) ràng buộc track_id (và tuỳ chọn IP).
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from jose import jwt

from app.core.config import SECRET_KEY, ALGORITHM

TOKEN_EXPIRE_MINUTES_DEFAULT = 2  # reduced TTL to strengthen anti-scraping


def create_track_token(track_id: str, ip: Optional[str] = None, expires_minutes: int = TOKEN_EXPIRE_MINUTES_DEFAULT) -> str:
    """Tạo JWT cho một bản nhạc HLS.

    Args:
        track_id: Mã track.
        ip: Địa chỉ IP client (ràng buộc tuỳ chọn).
        expires_minutes: TTL.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "track_id": track_id,
        "exp": now + timedelta(minutes=expires_minutes),
    }
    if ip:
        payload["ip"] = ip
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_track_token(token: str, track_id: str, ip: Optional[str] = None) -> None:
    """Xác minh JWT, ném HTTPException 403/401 khi không hợp lệ."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from None

    if payload.get("track_id") != track_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token track mismatch")

    if ip and payload.get("ip") and payload["ip"] != ip:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="IP mismatch")

    # Hết hạn được jose kiểm tra tự động.
