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
    
    # Chaotic Encryption Fields
    chaotic_encrypted_path: Optional[str] = None  # Path to chaotic-encrypted file
    chaotic_protection_key: Optional[str] = None  # Derived protection key
    original_file_sha256: Optional[str] = None  # SHA-256 hash for integrity
    encryption_status: Optional[str] = "unprotected"  # Status: unprotected, chaotic_protected
    protection_level: Optional[str] = "standard"  # Level: standard, high, maximum

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
    
    # Security info (limited for client)
    encryption_status: Optional[str] = None
    protection_level: Optional[str] = None
    upload_date: Optional[datetime] = None

    class Config:
        from_attributes = True
        extra = "ignore"
        populate_by_name = True # Allow population by field name OR alias

# Schema for encryption info
class EncryptionInfo(BaseModel):
    encryption_status: str
    protection_level: str
    has_chaotic_protection: bool
    original_file_sha256: Optional[str] = None
    
    class Config:
        from_attributes = True

class AudioUploadRequest(BaseModel):
    is_public: bool = False
    performance_mode: str = Field(
        default="balanced",
        description="Encryption performance mode: fast, balanced, secure",
        pattern="^(fast|balanced|secure)$"
    )

class AudioUploadResponse(BaseModel):
    track_id: str
    message: str
    file_size: int
    encryption_status: str
    protection_level: str
    performance_mode: str
    estimated_time: Optional[float] = None
    original_file_sha256: Optional[str] = None

class EncryptionProgress(BaseModel):
    track_id: str
    status: str  # "processing", "completed", "failed"
    progress_percent: float
    current_step: str
    estimated_remaining: Optional[float] = None
    performance_mode: str
    
class EncryptionStatusResponse(BaseModel):
    track_id: str
    encryption_status: str
    protection_level: str
    has_chaotic_protection: bool
    performance_mode: str
    original_file_sha256: Optional[str] = None
    encryption_time: Optional[float] = None
