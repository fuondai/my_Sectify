# app/schemas/audio.py
from pydantic import BaseModel, Field
import uuid
from datetime import datetime, timezone
from typing import Optional

class AudioBase(BaseModel):
    title: str
    is_public: bool = False

    class Config:
        # Allow models to be created from ORM objects/attributes and ignore unknown fields (e.g. MongoDB _id)
        from_attributes = True  # Pydantic v2 equivalent to orm_mode
        extra = "ignore"

class AudioCreate(AudioBase):
    pass

class AudioDB(AudioBase):
    track_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    owner_id: str
    original_filename: str
    hls_playlist_path: Optional[str] = None
    encryption_key: Optional[str] = None  # Stored as Base64
    original_file_path: Optional[str] = None  # Saved original for future key rotation
    last_key_rotation: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    upload_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        from_attributes = True
        extra = "ignore"

# Schema for data sent back to the client (output)
class AudioOut(AudioBase):
    track_id: str
    owner_id: str
    title: str
    is_public: bool
    hls_playlist_path: Optional[str] = None

    class Config:
        from_attributes = True
        extra = "ignore"
        populate_by_name = True # Allow population by field name OR alias
