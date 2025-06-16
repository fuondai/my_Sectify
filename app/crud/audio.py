# app/crud/audio.py
from motor.motor_asyncio import AsyncIOMotorClient
from app.schemas.audio import AudioDB

async def create_track(db: AsyncIOMotorClient, track_data: dict):
    """Creates a new track in the database."""
    result = await db["tracks"].insert_one(track_data)
    track_data["_id"] = str(result.inserted_id)
    return track_data

async def get_tracks_by_owner(db: AsyncIOMotorClient, owner_id: str):
    """Gets all tracks for a specific user by their ID."""
    tracks = []
    cursor = db["tracks"].find({"owner_id": owner_id})
    async for track in cursor:
        tracks.append(track)
    return tracks

async def get_track_by_id(db: AsyncIOMotorClient, track_id: str):
    """Gets track information by its ID."""
    track = await db["tracks"].find_one({"track_id": track_id})
    return track

async def get_public_tracks(db: AsyncIOMotorClient):
    """Gets all public tracks and normalizes legacy field names to match the response schema."""
    tracks = []
    cursor = db["tracks"].find({"is_public": True, "title": {"$exists": True}})
    async for track in cursor:
        # Handle legacy data: rename 'id' to 'track_id' if it exists.
        if "id" in track and "track_id" not in track:
            track["track_id"] = track.pop("id")
        
        # Handle legacy data: rename 'owner_email' to 'owner_id' if it exists.
        if "owner_email" in track and "owner_id" not in track:
            track["owner_id"] = track.pop("owner_email")

        tracks.append(track)
    return tracks
