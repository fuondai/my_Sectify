# app/api/v1/endpoints/totp.py
import base64
import io

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Security, status
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

from app.api.v1.dependencies import get_current_user
from app.core.security import verify_password
from app.crud import user as user_crud
from app.db.mongodb_utils import get_database
from app.schemas.user import UserInDB


class TOTPDisableRequest(BaseModel):
    password: str

class TOTPVerifyRequest(BaseModel):
    code: str

router = APIRouter()

@router.post("/generate", summary="Generate TOTP secret and QR code")
async def generate_totp(
    db: AsyncIOMotorClient = Depends(get_database),
    current_user: UserInDB = Security(get_current_user),
):
    """
    Generates a TOTP secret and returns a QR code.
    This operation will store the secret in the user's profile but will not enable TOTP.
    """
    if current_user.is_totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is already enabled for your account.",
        )

    # Generate a new secret
    secret = pyotp.random_base32()

    # Create a provisioning URI for the authenticator app
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name="Sectify"
    )

    # Update the user with the new secret (but do not enable)
    await user_crud.update_user_totp_info(db, current_user.email, secret=secret, enabled=False)

    # Generate a QR code from the URI
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return {
        "detail": "QR code generated. Please scan it with your authenticator app and verify.",
        "qr_code_image": f"data:image/png;base64,{qr_base64}"
    }

@router.post("/verify", summary="Verify TOTP and enable it")
async def verify_totp(
    request_data: TOTPVerifyRequest,
    db: AsyncIOMotorClient = Depends(get_database),
    current_user: UserInDB = Security(get_current_user),
):
    """
    Verifies the TOTP code and enables it for the user.
    """
    if current_user.is_totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is already enabled.",
        )

    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP secret not found. Please generate a QR code first.",
        )

    totp = pyotp.TOTP(current_user.totp_secret)

    if not totp.verify(request_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code.",
        )

    # Enable TOTP for the user
    await user_crud.update_user_totp_info(db, current_user.email, secret=current_user.totp_secret, enabled=True)

    return {"detail": "TOTP has been successfully enabled for your account."}


@router.post("/disable", summary="Disable TOTP for the user")
async def disable_totp(
    request_data: TOTPDisableRequest,
    db: AsyncIOMotorClient = Depends(get_database),
    current_user: UserInDB = Security(get_current_user),
):
    """
    Disables TOTP for the user after verifying their password.
    """
    if not current_user.is_totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is not enabled for your account.",
        )

    # Xác minh mật khẩu của người dùng
    if not verify_password(request_data.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password.",
        )

    # Vô hiệu hóa TOTP
    await user_crud.update_user_totp_info(db, current_user.email, secret=None, enabled=False)

    return {"detail": "TOTP has been successfully disabled."}

