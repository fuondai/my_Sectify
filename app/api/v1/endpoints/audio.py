# app/api/v1/endpoints/audio.py
import uuid
import os
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Security, Request, Form
from fastapi.responses import FileResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
import shutil
import logging

from app.db.mongodb_utils import get_database
from app.api.v1.dependencies import get_current_active_user, get_any_active_user, oauth2_scheme
from app.crud.audio import create_track, get_track_by_id, get_public_tracks, get_tracks_by_owner
from app.schemas.user import User
from app.schemas.audio import AudioCreate, AudioDB, AudioOut
from app.core.audio_processing import process_audio_to_hls, KEY_DIRECTORY


router = APIRouter()

UPLOAD_DIRECTORY = "uploads_temp"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

@router.post("/upload")
async def upload_audio_hls(
    file: UploadFile = File(...),
    is_public: bool = Form(False),
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Security(get_current_active_user, scopes=["author"]),
):
    if not current_user:
        raise HTTPException(status_code=403, detail="Not authorized")

    temp_id = str(uuid.uuid4())
    temp_path = os.path.join(UPLOAD_DIRECTORY, f"{temp_id}_{file.filename}")
    ORIGINALS_DIR = "uploads_originals"
    os.makedirs(ORIGINALS_DIR, exist_ok=True)
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        track_id = str(uuid.uuid4())
        # Permanently preserve original for future key rotation
        original_path = os.path.join(ORIGINALS_DIR, f"{track_id}_{file.filename}")
        shutil.copy(temp_path, original_path)
        playlist_path, encryption_key_b64 = process_audio_to_hls(temp_path, track_id)

        if not playlist_path:
            raise HTTPException(status_code=500, detail=f"Failed to process audio file. Error: {encryption_key_b64}")

        audio_db = AudioDB(
            title=file.filename,
            is_public=is_public,
            track_id=track_id,
            owner_id=current_user.id,
            original_filename=file.filename,
            hls_playlist_path=playlist_path,
            encryption_key=encryption_key_b64,
            original_file_path=original_path
        )
        await create_track(db, audio_db)

        return {"track_id": track_id, "filename": file.filename, "playlist_url": f"/{playlist_path}"}
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)




@router.get("/tracks/public", response_model=list[AudioOut])
async def list_public_tracks(db: AsyncIOMotorDatabase = Depends(get_database)):
    return await get_public_tracks(db)

@router.get("/tracks/me", response_model=list[AudioOut])
async def list_my_tracks(
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(get_current_active_user),
):
    return await get_tracks_by_owner(db, owner_id=current_user.id)

@router.get("/info/{track_id}", response_model=AudioOut)
async def get_track_info(
    track_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(get_any_active_user) # Require authentication
):
    """Fetches track information securely."""
    track = await get_track_by_id(db, track_id)
    if not track:
        raise HTTPException(status_code=404, detail="Track not found")

    # Authorization check
    is_public = track.get("is_public", False)
    owner_id = track.get("owner_id")

    if not is_public and (not current_user or owner_id != current_user.id):
        raise HTTPException(status_code=403, detail="You do not have permission to access this track's info")

    return track
