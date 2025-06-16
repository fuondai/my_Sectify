"""
Endpoint to securely serve HLS playlists, keys, and segments.
It uses a signed URL pattern with short-lived JWTs for authorization.
"""
import os
import logging
import re
import time
import hmac
from datetime import datetime, timezone, timedelta
import hashlib

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import FileResponse, Response
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.mongodb_utils import get_database
from app.crud.audio import get_track_by_id
from app.core.audio_processing import KEY_DIRECTORY
from app.core.token_utils import create_track_token, verify_track_token
from app.core.jit_key_alias import create_key_alias, resolve_key_alias
from app.core.config import SECRET_KEY
from app.api.v1.dependencies import try_get_current_user
from app.schemas.user import UserInDB
from app.core.limiter import limiter
from app.core.embed_protection import check_embed_source

logger = logging.getLogger(__name__)
router = APIRouter()

PLAYLIST_MEDIA_TYPE = "application/vnd.apple.mpegurl"
SEGMENT_MEDIA_TYPE = "video/mp2t"


@router.get("/playlist/{track_id}", response_class=Response, tags=["stream"])
async def get_signed_playlist(
    track_id: str,
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: Optional[UserInDB] = Depends(try_get_current_user),
    _: None = Depends(check_embed_source)
):
    """
    Returns a rewritten .m3u8 playlist with signed URIs for keys and segments.
    - Public tracks: Accessible by anyone.
    - Private tracks: Accessible only by the owner.
    """
    track = await get_track_by_id(db, track_id)
    if not track:
        raise HTTPException(status_code=404, detail="Track not found")

    # Authorization Check
    is_public = track.get("is_public", False)
    if not is_public:
        if not current_user:
            raise HTTPException(
                status_code=401,
                detail="Authentication required for private tracks",
            )
        if track.get("owner_id") != current_user.id:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to access this track",
            )

    # ---------- Automatic key rotation for original HLS ----------
    try:
        ROTATION_INTERVAL_MINUTES = 30
        last_rotated = track.get("last_key_rotation")
        # Ensure timezone-aware comparison
        if last_rotated and last_rotated.tzinfo is None:
            last_rotated = last_rotated.replace(tzinfo=timezone.utc)
        if last_rotated:
            
            if datetime.now(timezone.utc) - last_rotated > timedelta(minutes=ROTATION_INTERVAL_MINUTES):
                logger.info("Rotating key for track %s", track_id)
                original_path = track.get("original_file_path")
                if original_path and os.path.exists(original_path):
                    import shutil
                    hls_dir = os.path.dirname(track["hls_playlist_path"])
                    if os.path.isdir(hls_dir):
                        shutil.rmtree(hls_dir, ignore_errors=True)
                    from app.core.audio_processing import process_audio_to_hls
                    new_playlist_path, new_key_b64 = process_audio_to_hls(original_path, track_id, delete_input=False)
                    if new_playlist_path:
                        await db["tracks"].update_one({"track_id": track_id}, {"$set": {
                            "hls_playlist_path": new_playlist_path,
                            "encryption_key": new_key_b64,
                            "last_key_rotation": datetime.now(timezone.utc)
                        }})
                        track["hls_playlist_path"] = new_playlist_path
    except Exception as rot_err:
        logger.error("Key rotation failed for %s: %s", track_id, rot_err)
    
    # ---------- Per-viewer watermark ----------
    viewer_id = current_user.id if current_user else request.client.host
    viewer_hash = hashlib.sha256(viewer_id.encode()).hexdigest()[:8]
    wm_track_id = f"{track_id}_{viewer_hash}"

    client_ip = request.client.host
    # Expected playlist path for viewer-specific stream
    playlist_path = os.path.join("hls", wm_track_id, "playlist.m3u8")

    if not os.path.exists(playlist_path):
        original_path = track.get("original_file_path")
        if not original_path or not os.path.exists(original_path):
            raise HTTPException(status_code=500, detail="Original file missing for watermark generation")
        from app.core.audio_processing import process_audio_to_hls
        new_playlist_path, _ = process_audio_to_hls(
            original_path,
            wm_track_id,
            delete_input=False,
            watermark_user=viewer_id,
            watermark_amplitude=0.002,
        )
        if not new_playlist_path:
            raise HTTPException(status_code=500, detail="Failed to generate watermarked stream")
        playlist_path = new_playlist_path

    # Short-lived token tied to viewer-specific track
    token = create_track_token(wm_track_id, ip=client_ip)
    alias_value = create_key_alias(wm_track_id, os.path.join(KEY_DIRECTORY, f"{wm_track_id}.key"))

    # Read the original playlist and rewrite URIs to point to our secure endpoints
    new_lines: list[str] = []
    try:
        f_handle = open(playlist_path, "r", encoding="utf-8")
    except FileNotFoundError:
        # Fallback to original playlist if viewer-specific not yet generated
        playlist_path = track["hls_playlist_path"]
        f_handle = open(playlist_path, "r", encoding="utf-8")
    with f_handle as f:
        for line in f.readlines():
            stripped = line.strip()
            if stripped.startswith("#EXT-X-KEY"):
                # Rewrite the key URI attribute with our secure, signed URL while preserving other attributes
                new_line = re.sub(
                    r'URI="[^"]+"',
                    f'URI="/api/v1/stream/key/{wm_track_id}?token={token}&alias={alias_value}"',
                    stripped
                ) + "\n"
                new_lines.append(new_line)
            elif stripped and not stripped.startswith("#"):
                # Rewrite the segment URI with per-segment nonce signature
                seg_name = stripped
                ts = int(time.time())
                sig = hmac.new(SECRET_KEY.encode(), f"{wm_track_id}:{seg_name}:{ts}".encode(), hashlib.sha256).hexdigest()[:20]
                new_lines.append(f"/api/v1/stream/segment/{wm_track_id}/{seg_name}?ts={ts}&sig={sig}\n")
            else:
                new_lines.append(line)

    content = "".join(new_lines)
    return Response(content, media_type=PLAYLIST_MEDIA_TYPE)


@router.get("/key/{track_id}", tags=["stream"])
@limiter.limit("10/minute")
async def get_key(
    track_id: str,
    request: Request,
    token: str = Query(...),
    alias: str = Query(...),
    _ : None = Depends(check_embed_source),
):
    """Serves the encryption key after validating the track token."""
    client_ip = request.client.host
    verify_track_token(token, track_id, ip=client_ip, range_header=request.headers.get("range"))

    key_path = resolve_key_alias(alias, track_id)
    if not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Key file not found")
    return FileResponse(key_path, media_type="application/octet-stream")


@router.get("/segment/{track_id}/{segment_name}", tags=["stream"])
@limiter.limit("60/minute")
async def get_segment(
    track_id: str,
    segment_name: str,
    ts: int = Query(...),
    sig: str = Query(...),
    current_user: Optional[UserInDB] = Depends(try_get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
    request: Request = None,
    _ : None = Depends(check_embed_source)
):
    """
    Serves an HLS media segment (.ts file) after validating the JWT token.
    This endpoint is protected and requires a valid token from the playlist.
    """
    # Validate signature freshness (≤10 s)
    if abs(time.time() - ts) > 10:
        raise HTTPException(status_code=400, detail="Signature expired.")

    expected_sig = hmac.new(SECRET_KEY.encode(), f"{track_id}:{segment_name}:{ts}".encode(), hashlib.sha256).hexdigest()[:20]
    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=400, detail="Invalid signature.")

    # Validate segment name to prevent path traversal for .ts files
    if not segment_name.startswith("segment") or not segment_name.endswith(".ts"):
        raise HTTPException(status_code=400, detail="Invalid segment name format.")

    segment_path = os.path.join("hls", track_id, segment_name)
    if not os.path.exists(segment_path):
        # Fallback to original track dir if viewer-specific not generated
        orig_id = track_id.split("_")[0]
        segment_path = os.path.join("hls", orig_id, segment_name)

    # Security: Ensure the resolved path exists
    if not os.path.exists(segment_path):
        raise HTTPException(status_code=404, detail="Segment not found.")

    # Basic anomaly log: log each segment request; tools scraping will flood logs
    logger.debug("Serve segment %s to IP %s", segment_name, request.client.host)

    return FileResponse(segment_path, media_type="video/mp2t")  # Use video/mp2t for .ts segments
