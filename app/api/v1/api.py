# app/api/v1/api.py
from fastapi import APIRouter
from app.api.v1.endpoints import auth, users, audio, totp, stream

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(audio.router, prefix="/audio", tags=["audio"])
api_router.include_router(totp.router, prefix="/totp", tags=["totp"])
api_router.include_router(stream.router, prefix="/stream", tags=["stream"])
