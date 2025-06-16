# app/api/v1/endpoints/audio.py
import uuid
import os
import logging
import asyncio
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Security, Request, Form, BackgroundTasks
from fastapi.responses import FileResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
import shutil

from app.db.mongodb_utils import get_database
from app.api.v1.dependencies import get_current_active_user, get_any_active_user, oauth2_scheme
from app.crud.audio import create_track, get_track_by_id, get_public_tracks, get_tracks_by_owner
from app.schemas.user import User
from app.schemas.audio import (
    AudioOut, 
    AudioUploadResponse, 
    AudioUploadRequest,
    EncryptionProgress,
    EncryptionStatusResponse
)
from app.core.audio_processing import process_audio_to_hls, KEY_DIRECTORY
from app.core.chaotic_audio_protection import (
    encrypt_audio_file, 
    decrypt_audio_file,
    create_audio_protection_key,
    calculate_file_sha256,
    SUPPORTED_FORMATS,
    ChaoticAudioProtection, 
    get_progress, 
    estimate_encryption_time,
    update_progress
)
from app.core.config import SECRET_KEY, MAX_FILE_SIZE_MB
from app.core.validation import (
    validate_uuid, 
    validate_filename, 
    validate_file_extension, 
    validate_file_size,
    validate_path_safety,
    sanitize_user_input,
    ValidationError
)
from pathlib import Path

# Setup logger
logger = logging.getLogger(__name__)

router = APIRouter()

UPLOAD_DIRECTORY = "uploads_temp"
ENCRYPTED_STORAGE = "uploads_encrypted"  # Thư mục lưu file encrypted
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
os.makedirs(ENCRYPTED_STORAGE, exist_ok=True)

# Audio file extensions allowed
ALLOWED_AUDIO_EXTENSIONS = ['.mp3', '.wav', '.m4a', '.flac', '.aac', '.ogg']

async def check_track_ownership(track_id: str, user_id: str, db: AsyncIOMotorDatabase) -> dict:
    """
    Check if user owns the track or if track is public
    
    Returns:
        track dict if access allowed
        
    Raises:
        HTTPException: If access denied or track not found
    """
    track = await get_track_by_id(db, track_id)
    if not track:
        logger.warning(f"Track not found: {track_id}")
        raise HTTPException(status_code=404, detail="Track not found")
    
    is_public = track.get("is_public", False)
    owner_id = track.get("owner_id")
    
    # For private tracks, only owner can access
    if not is_public and owner_id != user_id:
        logger.warning(f"Unauthorized access attempt to track {track_id} by user {user_id}")
        raise HTTPException(
            status_code=403, 
            detail="You do not have permission to access this track"
        )
    
    return track

async def process_audio_async(
    temp_file_path: str,
    original_file_path: str, 
    encrypted_file_path: str,
    track_id: str,
    user_id: str,
    performance_mode: str,
    db: AsyncIOMotorDatabase
):
    """Background task để process audio async"""
    try:
        logger.info(f"Starting async processing for track {track_id}")
        
        # Update progress
        update_progress(track_id, 10, "Starting encryption...", performance_mode)
        
        # For fast mode, skip chaotic encryption để ultra fast
        if performance_mode == 'fast':
            logger.info(f"Fast mode: Skipping chaotic encryption for {track_id}")
            update_progress(track_id, 50, "Fast mode: Skipping encryption, starting HLS...", performance_mode)
            
            # Just copy original file để có encrypted path 
            shutil.copy2(temp_file_path, encrypted_file_path)
            encryption_result = {
                "success": True,
                "original_file_sha256": "fast_mode_skip"
            }
        else:
            # Initialize chaotic protection cho balanced/secure modes
            protection = ChaoticAudioProtection()
            
            # Encryption với progress tracking
            encryption_result = protection.encrypt_audio_file(
                input_path=temp_file_path,
                output_path=encrypted_file_path,
                user_id=user_id,
                track_id=track_id,
                performance_mode=performance_mode
            )
        
        if not encryption_result["success"]:
            update_progress(track_id, 0, f"Encryption failed: {encryption_result.get('error')}", performance_mode)
            logger.error(f"Encryption failed for {track_id}")
            return
        
        # Update progress 
        update_progress(track_id, 60, "Encryption completed, starting HLS...", performance_mode)
        
        # HLS processing
        try:
            hls_playlist_path, hls_key_b64 = process_audio_to_hls(
                original_file_path, 
                track_id, 
                delete_input=False
            )
            
            if hls_playlist_path:
                update_progress(track_id, 90, "HLS processing completed", performance_mode)
                
                # Update database với HLS info
                await db["tracks"].update_one(
                    {"track_id": track_id}, 
                    {"$set": {
                        "hls_playlist_path": hls_playlist_path,
                        "encryption_key": hls_key_b64,
                        "encryption_status": "completed"
                    }}
                )
                logger.info(f"HLS processing completed for {track_id}")
            else:
                update_progress(track_id, 80, "HLS processing failed, but track saved", performance_mode)
                logger.warning(f"HLS processing failed for {track_id}")
                
        except Exception as hls_error:
            logger.error(f"HLS processing error for {track_id}: {hls_error}")
            update_progress(track_id, 80, "HLS processing failed, but track saved", performance_mode)
        
        # Final update
        update_progress(track_id, 100, "Processing completed!", performance_mode)
        
        # Clean up temp file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            
    except Exception as e:
        logger.error(f"Async processing failed for {track_id}: {e}")
        update_progress(track_id, 0, f"Processing failed: {str(e)}", performance_mode)

@router.post("/upload", response_model=AudioUploadResponse)
async def upload_audio(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    is_public: bool = Form(False),
    performance_mode: str = Form("balanced"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Upload file âm thanh và process async với enhanced security validation.
    
    Performance Modes:
    - fast: Ultra nhanh cho testing (0.5s/MB)
    - balanced: Cân bằng tốc độ và bảo mật (6s/MB)
    - secure: Bảo mật tối đa cho production (15s/MB)
    """
    logger.info(f"Upload request received: file={file.filename}, mode={performance_mode}, user={current_user.id}")
    
    try:
        # Validate file presence
        if not file or not file.filename:
            raise HTTPException(
                status_code=400,
                detail="No file provided"
            )
        
        # Sanitize and validate filename
        try:
            clean_filename = sanitize_user_input(file.filename, 255)
            validated_filename = validate_filename(clean_filename)
            validated_filename = validate_file_extension(validated_filename, ALLOWED_AUDIO_EXTENSIONS)
        except ValidationError as e:
            logger.warning(f"File validation failed for {file.filename}: {e}")
            raise HTTPException(status_code=400, detail=str(e))
        
        # Validate performance mode
        if performance_mode not in ['fast', 'balanced', 'secure']:
            performance_mode = 'balanced'
        
        # Read file content and validate size
        file_content = await file.read()
        file_size = len(file_content)
        
        try:
            validate_file_size(file_size, MAX_FILE_SIZE_MB)
        except ValidationError as e:
            logger.warning(f"File size validation failed: {e}")
            raise HTTPException(status_code=413, detail=str(e))
        
        estimated_time = estimate_encryption_time(file_size, performance_mode)
        logger.info(f"File size: {file_size} bytes, estimated time: {estimated_time}s")
        
        # Generate secure track ID
        track_id = str(uuid.uuid4())
        logger.info(f"Generated track_id: {track_id}")
        
        # Prepare safe paths
        temp_dir = "uploads_temp"
        original_dir = "uploads_originals"
        encrypted_dir = "uploads_encrypted"
        
        for directory in [temp_dir, original_dir, encrypted_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Use UUID for safe filenames
        safe_filename = f"{track_id}_{validated_filename}"
        temp_file_path = os.path.join(temp_dir, safe_filename)
        original_file_path = os.path.join(original_dir, safe_filename)
        encrypted_file_path = os.path.join(encrypted_dir, f"{safe_filename}.encrypted")
        
        # Validate paths are safe
        try:
            validate_path_safety(temp_file_path, temp_dir)
            validate_path_safety(original_file_path, original_dir)
            validate_path_safety(encrypted_file_path, encrypted_dir)
        except ValidationError as e:
            logger.error(f"Path validation failed: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")
        
        # Save temp file
        with open(temp_file_path, "wb") as f:
            f.write(file_content)
        
        # Copy to original storage
        shutil.copy2(temp_file_path, original_file_path)
        
        # Create initial audio record in database with sanitized title
        safe_title = sanitize_user_input(file.filename, 100) or "Untitled"
        audio_data = {
            "track_id": track_id,
            "title": safe_title,
            "owner_id": str(current_user.id),
            "file_path": original_file_path,
            "original_file_path": original_file_path,
            "encrypted_file_path": encrypted_file_path,
            "is_public": bool(is_public),  # Ensure boolean
            "file_size": file_size,
            "performance_mode": performance_mode,
            "encryption_status": "processing",
            "chaotic_protection_key": create_audio_protection_key(str(current_user.id), track_id, SECRET_KEY)
        }
        
        try:
            new_track = await create_track(db, audio_data)
            logger.info(f"Track record created: {track_id}")
        except Exception as e:
            logger.error(f"Database creation failed for {track_id}: {e}")
            # Clean up files
            for path in [temp_file_path, original_file_path]:
                if os.path.exists(path):
                    os.remove(path)
            raise HTTPException(status_code=500, detail="Failed to create track record")
        
        # Start background processing
        background_tasks.add_task(
            process_audio_async,
            temp_file_path,
            original_file_path,
            encrypted_file_path,
            track_id,
            str(current_user.id),
            performance_mode,
            db
        )
        
        logger.info(f"Audio upload completed successfully for track {track_id}")
        return AudioUploadResponse(
            track_id=track_id,
            message="Upload successful, processing started",
            file_size=file_size,
            encryption_status="processing",  # Will be updated by background task
            protection_level=performance_mode,
            performance_mode=performance_mode,
            estimated_time=estimated_time,
            original_file_sha256=None  # Will be calculated during processing
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in upload_audio: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/progress/{track_id}", response_model=EncryptionProgress)
async def get_encryption_progress(
    track_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Get encryption progress with ownership validation"""
    # Validate track ID format
    validated_track_id = validate_uuid(track_id, "track_id")
    
    # Check ownership/access
    await check_track_ownership(validated_track_id, str(current_user.id), db)
    
    # Get progress
    try:
        progress = get_progress(validated_track_id)
        return progress
    except Exception as e:
        logger.error(f"Error getting progress for {validated_track_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get progress")

@router.get("/encryption-status/{track_id}", response_model=EncryptionStatusResponse)
async def get_encryption_status(
    track_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Get encryption status with ownership validation"""
    # Validate track ID format
    validated_track_id = validate_uuid(track_id, "track_id")
    
    # Check ownership/access
    track = await check_track_ownership(validated_track_id, str(current_user.id), db)
    
    encryption_status = track.get("encryption_status", "unknown")
    logger.info(f"Encryption status for {validated_track_id}: {encryption_status}")
    
    return EncryptionStatusResponse(
        track_id=validated_track_id,
        encryption_status=encryption_status,
        hls_ready=encryption_status == "completed"
    )

@router.get("/performance-info")
async def get_performance_info():
    """Get performance mode information (public endpoint)"""
    return {
        "performance_modes": {
            "fast": {
                "description": "Ultra fast processing for testing",
                "encryption": "Disabled (development only)",
                "speed": "~0.5 seconds per MB",
                "security": "Low - for testing only"
            },
            "balanced": {
                "description": "Balanced speed and security",
                "encryption": "Chaotic encryption enabled",
                "speed": "~6 seconds per MB",
                "security": "Medium - good for most users"
            },
            "secure": {
                "description": "Maximum security processing",
                "encryption": "Advanced chaotic encryption",
                "speed": "~15 seconds per MB",
                "security": "High - recommended for production"
            }
        },
        "supported_formats": ALLOWED_AUDIO_EXTENSIONS,
        "max_file_size": f"{MAX_FILE_SIZE_MB}MB",
        "features": [
            "AES-128 HLS encryption",
            "Per-user audio watermarking",
            "Chaotic cipher protection",
            "Background processing",
            "Real-time progress tracking"
        ]
    }

@router.post("/decrypt/{track_id}")
async def decrypt_audio_track(
    track_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Security(get_current_active_user, scopes=["author"]),
):
    """Decrypt audio track with proper authorization"""
    # Validate track ID format
    validated_track_id = validate_uuid(track_id, "track_id")
    
    # Check ownership (only owner can decrypt)
    track = await get_track_by_id(db, validated_track_id)
    if not track:
        raise HTTPException(status_code=404, detail="Track not found")
    
    if track.get("owner_id") != str(current_user.id):
        logger.warning(f"Unauthorized decrypt attempt for track {validated_track_id} by user {current_user.id}")
        raise HTTPException(
            status_code=403, 
            detail="Only the track owner can decrypt files"
        )
    
    try:
        encrypted_file_path = track.get("encrypted_file_path")
        if not encrypted_file_path or not os.path.exists(encrypted_file_path):
            raise HTTPException(status_code=404, detail="Encrypted file not found")
        
        # Validate path safety
        validate_path_safety(encrypted_file_path, ENCRYPTED_STORAGE)
        
        # Decrypt file
        protection = ChaoticAudioProtection()
        decrypted_data = protection.decrypt_audio_file(
            encrypted_file_path,
            str(current_user.id),
            validated_track_id
        )
        
        if not decrypted_data["success"]:
            logger.error(f"Decryption failed for {validated_track_id}: {decrypted_data.get('error')}")
            raise HTTPException(status_code=500, detail="Decryption failed")
        
        # Return decrypted file
        decrypted_path = decrypted_data["output_path"]
        if not os.path.exists(decrypted_path):
            raise HTTPException(status_code=500, detail="Decrypted file not found")
        
        logger.info(f"Successful decryption for track {validated_track_id} by user {current_user.id}")
        return FileResponse(
            decrypted_path,
            media_type="application/octet-stream",
            filename=f"decrypted_{track.get('title', 'audio')}"
        )
        
    except ValidationError as e:
        logger.warning(f"Validation error in decrypt: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Decrypt error for {validated_track_id}: {e}")
        raise HTTPException(status_code=500, detail="Decryption failed")

@router.get("/tracks/public", response_model=list[AudioOut])
async def list_public_tracks(db: AsyncIOMotorDatabase = Depends(get_database)):
    """List public tracks (no authentication required)"""
    try:
        tracks = await get_public_tracks(db)
        return tracks
    except Exception as e:
        logger.error(f"Error listing public tracks: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve tracks")

@router.get("/tracks/me", response_model=list[AudioOut])
async def list_my_tracks(
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(get_current_active_user),
):
    """List current user's tracks"""
    try:
        tracks = await get_tracks_by_owner(db, str(current_user.id))
        return tracks
    except Exception as e:
        logger.error(f"Error listing user tracks for {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve your tracks")

@router.get("/info/{track_id}", response_model=AudioOut)
async def get_track_info(
    track_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(get_any_active_user) # Require authentication
):
    """Get track information with proper access control"""
    # Validate track ID format
    validated_track_id = validate_uuid(track_id, "track_id")
    
    # Check access permissions
    track = await check_track_ownership(validated_track_id, str(current_user.id), db)
    
    try:
        # Convert to AudioOut schema
        return AudioOut(**track)
    except Exception as e:
        logger.error(f"Error converting track to AudioOut for {validated_track_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to process track information")
