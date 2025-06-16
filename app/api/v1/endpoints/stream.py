"""
Endpoint to securely serve HLS playlists, keys, and segments.
It uses a signed URL pattern with short-lived JWTs for authorization.
Enhanced with security validations and path traversal protection.
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
from app.core.validation import validate_uuid, validate_path_safety, ValidationError

logger = logging.getLogger(__name__)
router = APIRouter()

PLAYLIST_MEDIA_TYPE = "application/vnd.apple.mpegurl"
SEGMENT_MEDIA_TYPE = "video/mp2t"


async def check_track_access(track_id: str, current_user: Optional[UserInDB], db: AsyncIOMotorDatabase) -> dict:
    """
    Check if user can access the track
    
    Returns:
        track dict if access allowed
        
    Raises:
        HTTPException: If access denied or track not found
    """
    track = await get_track_by_id(db, track_id)
    if not track:
        logger.warning(f"Track not found: {track_id}")
        raise HTTPException(status_code=404, detail="Track not found")

    # Authorization Check
    is_public = track.get("is_public", False)
    if not is_public:
        if not current_user:
            logger.warning(f"Unauthenticated access attempt to private track: {track_id}")
            raise HTTPException(
                status_code=401,
                detail="Authentication required for private tracks",
            )
        if track.get("owner_id") != current_user.id:
            logger.warning(f"Unauthorized access attempt to track {track_id} by user {current_user.id}")
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to access this track",
            )
    
    return track


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
    Enhanced with security validation and proper access controls.
    """
    # Validate track ID format
    validated_track_id = validate_uuid(track_id, "track_id")
    
    # Check access permissions
    track = await check_track_access(validated_track_id, current_user, db)

    # ---------- Automatic key rotation for original HLS ----------
    try:
        ROTATION_INTERVAL_MINUTES = 30
        last_rotated = track.get("last_key_rotation")
        # Ensure timezone-aware comparison
        if last_rotated and last_rotated.tzinfo is None:
            last_rotated = last_rotated.replace(tzinfo=timezone.utc)
        if last_rotated:
            
            if datetime.now(timezone.utc) - last_rotated > timedelta(minutes=ROTATION_INTERVAL_MINUTES):
                logger.info("Rotating key for track %s", validated_track_id)
                original_path = track.get("original_file_path") or track.get("file_path")
                if original_path and os.path.exists(original_path):
                    # Validate path safety before processing
                    try:
                        validate_path_safety(original_path, "uploads_originals")
                    except ValidationError as e:
                        logger.error(f"Path validation failed for key rotation: {e}")
                        raise HTTPException(status_code=500, detail="Key rotation failed")
                    
                    import shutil
                    hls_dir = os.path.dirname(track["hls_playlist_path"])
                    if os.path.isdir(hls_dir):
                        shutil.rmtree(hls_dir, ignore_errors=True)
                    from app.core.audio_processing import process_audio_to_hls
                    new_playlist_path, new_key_b64 = process_audio_to_hls(original_path, validated_track_id, delete_input=False)
                    if new_playlist_path:
                        await db["tracks"].update_one({"track_id": validated_track_id}, {"$set": {
                            "hls_playlist_path": new_playlist_path,
                            "encryption_key": new_key_b64,
                            "last_key_rotation": datetime.now(timezone.utc)
                        }})
                        track["hls_playlist_path"] = new_playlist_path
    except Exception as rot_err:
        logger.error("Key rotation failed for %s: %s", validated_track_id, rot_err)
    
    # ---------- Per-viewer watermark with enhanced security ----------
    try:
        viewer_id = current_user.id if current_user else request.client.host
        viewer_hash = hashlib.sha256(f"{viewer_id}{SECRET_KEY}".encode()).hexdigest()[:8]  # Add SECRET_KEY for security
        wm_track_id = f"{validated_track_id}_{viewer_hash}"

        client_ip = request.client.host
        # Expected playlist path for viewer-specific stream
        playlist_path = os.path.join("hls", wm_track_id, "playlist.m3u8")
        logger.info(f"Looking for viewer-specific playlist: {playlist_path}")

        # Validate playlist path safety
        try:
            validate_path_safety(playlist_path, "hls")
        except ValidationError as e:
            logger.error(f"Playlist path validation failed: {e}")
            raise HTTPException(status_code=500, detail="Playlist generation failed")

        if not os.path.exists(playlist_path):
            logger.info(f"Viewer-specific playlist not found, generating watermarked stream...")
            original_path = track.get("original_file_path") or track.get("file_path")
            if not original_path or not os.path.exists(original_path):
                logger.error(f"Original file missing: {original_path}")
                raise HTTPException(status_code=500, detail="Original file missing for watermark generation")
            
            # Validate original file path
            try:
                validate_path_safety(original_path, "uploads_originals")
            except ValidationError as e:
                logger.error(f"Original file path validation failed: {e}")
                raise HTTPException(status_code=500, detail="File access denied")
            
            from app.core.audio_processing import process_audio_to_hls
            new_playlist_path, _ = process_audio_to_hls(
                original_path,
                wm_track_id,
                delete_input=False,
                watermark_user=viewer_id,
                watermark_amplitude=0.002,
            )
            if not new_playlist_path:
                logger.error(f"Failed to generate watermarked stream for {wm_track_id}")
                raise HTTPException(status_code=500, detail="Failed to generate watermarked stream")
            playlist_path = new_playlist_path
            logger.info(f"Generated watermarked playlist: {playlist_path}")
    except Exception as watermark_error:
        logger.error(f"Error in watermark generation for {validated_track_id}: {watermark_error}")
        import traceback
        logger.error(f"Watermark error traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Watermark generation failed: {str(watermark_error)}")

    # Short-lived token tied to viewer-specific track
    token = create_track_token(wm_track_id, ip=client_ip)
    alias_value = create_key_alias(wm_track_id, os.path.join(KEY_DIRECTORY, f"{wm_track_id}.key"))

    # Read the original playlist and rewrite URIs to point to our secure endpoints
    new_lines: list[str] = []
    try:
        # Validate final playlist path
        validate_path_safety(playlist_path, "hls")
        f_handle = open(playlist_path, "r", encoding="utf-8")
    except ValidationError as e:
        logger.error(f"Final playlist path validation failed: {e}")
        raise HTTPException(status_code=500, detail="Playlist access failed")
    except FileNotFoundError:
        # Fallback to original playlist if viewer-specific not yet generated
        playlist_path = track["hls_playlist_path"]
        try:
            validate_path_safety(playlist_path, "hls")
            f_handle = open(playlist_path, "r", encoding="utf-8")
        except ValidationError as e:
            logger.error(f"Fallback playlist path validation failed: {e}")
            raise HTTPException(status_code=500, detail="Playlist access failed")
    
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
                
                # Validate segment name to prevent path traversal
                if '..' in seg_name or '/' in seg_name or '\\' in seg_name:
                    logger.warning(f"Suspicious segment name detected: {seg_name}")
                    continue
                
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
    """Serves the encryption key after validating the track token with enhanced security."""
    # Validate track ID format (allow watermarked track IDs)
    if not track_id or len(track_id.split('_')) < 2:
        logger.warning(f"Invalid track ID format for key request: {track_id}")
        raise HTTPException(status_code=400, detail="Invalid track ID format")
    
    # Extract base track ID and validate
    base_track_id = track_id.split('_')[0]
    try:
        validate_uuid(base_track_id, "track_id")
    except HTTPException:
        logger.warning(f"Invalid base track ID in key request: {base_track_id}")
        raise HTTPException(status_code=400, detail="Invalid track ID")
    
    client_ip = request.client.host
    try:
        verify_track_token(token, track_id, ip=client_ip, range_header=request.headers.get("range"))
    except Exception as e:
        logger.warning(f"Token verification failed for track {track_id}: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    try:
        key_path = resolve_key_alias(alias, track_id)
        
        # Validate key path safety
        validate_path_safety(key_path, KEY_DIRECTORY)
        
        if not os.path.exists(key_path):
            logger.warning(f"Key file not found: {key_path}")
            raise HTTPException(status_code=404, detail="Key file not found")
        
        return FileResponse(key_path, media_type="application/octet-stream")
        
    except ValidationError as e:
        logger.warning(f"Key path validation failed: {e}")
        raise HTTPException(status_code=403, detail="Key access denied")
    except Exception as e:
        logger.error(f"Key serving error: {e}")
        raise HTTPException(status_code=500, detail="Key serving failed")


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
    Enhanced with security validation and path traversal protection.
    """
    # Validate track ID format (allow watermarked track IDs)
    if not track_id or len(track_id.split('_')) < 2:
        logger.warning(f"Invalid track ID format for segment request: {track_id}")
        raise HTTPException(status_code=400, detail="Invalid track ID format")
    
    # Extract base track ID and validate
    base_track_id = track_id.split('_')[0]
    try:
        validate_uuid(base_track_id, "track_id")
    except HTTPException:
        logger.warning(f"Invalid base track ID in segment request: {base_track_id}")
        raise HTTPException(status_code=400, detail="Invalid track ID")
    
    # Validate segment name to prevent path traversal
    if not segment_name or '..' in segment_name or '/' in segment_name or '\\' in segment_name:
        logger.warning(f"Suspicious segment name: {segment_name}")
        raise HTTPException(status_code=400, detail="Invalid segment name")
    
    # Validate segment name format
    if not re.match(r'^[a-zA-Z0-9_\-]+\.ts$', segment_name):
        logger.warning(f"Invalid segment name format: {segment_name}")
        raise HTTPException(status_code=400, detail="Invalid segment format")
    
    # Verify signature
    try:
        expected_sig = hmac.new(SECRET_KEY.encode(), f"{track_id}:{segment_name}:{ts}".encode(), hashlib.sha256).hexdigest()[:20]
        if not hmac.compare_digest(sig, expected_sig):
            logger.warning(f"Invalid signature for segment {segment_name} on track {track_id}")
            raise HTTPException(status_code=401, detail="Invalid signature")
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        raise HTTPException(status_code=401, detail="Signature verification failed")
    
    # Check signature age (prevent replay attacks)
    current_time = int(time.time())
    if abs(current_time - ts) > 300:  # 5 minutes tolerance
        logger.warning(f"Signature too old for segment {segment_name}: {abs(current_time - ts)} seconds")
        raise HTTPException(status_code=401, detail="Signature expired")
    
    # Check track access permissions (using base track ID)
    try:
        await check_track_access(base_track_id, current_user, db)
    except HTTPException as e:
        logger.warning(f"Access denied for segment {segment_name} on track {base_track_id}")
        raise e
    
    # Construct and validate segment path
    segment_dir = os.path.join("hls", track_id)
    segment_path = os.path.join(segment_dir, segment_name)
    
    try:
        # Validate path safety
        validate_path_safety(segment_path, "hls")
        
        if not os.path.exists(segment_path):
            logger.warning(f"Segment file not found: {segment_path}")
            raise HTTPException(status_code=404, detail="Segment not found")
        
        # Additional security: verify file is actually a .ts file
        if not segment_path.endswith('.ts'):
            logger.warning(f"Non-TS file access attempt: {segment_path}")
            raise HTTPException(status_code=403, detail="Invalid file type")
        
        logger.info(f"Serving segment: {segment_path} for track {base_track_id}")
        return FileResponse(segment_path, media_type=SEGMENT_MEDIA_TYPE)
        
    except ValidationError as e:
        logger.warning(f"Segment path validation failed: {e}")
        raise HTTPException(status_code=403, detail="Segment access denied")
    except Exception as e:
        logger.error(f"Segment serving error: {e}")
        raise HTTPException(status_code=500, detail="Segment serving failed")
