# app/schemas/user.py
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
import uuid

class UserBase(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=3, max_length=50)

class User(UserBase):
    id: str
    is_active: bool = True
    is_totp_enabled: bool = False
    roles: List[str] = []

    class Config:
        from_attributes = True

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserInDB(UserBase):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    hashed_password: str
    totp_secret: Optional[str] = None
    is_totp_enabled: bool = False
    is_active: bool = True
    roles: List[str] = []

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[EmailStr] = None
