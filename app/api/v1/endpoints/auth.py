# app/api/v1/endpoints/auth.py
import pyotp
from fastapi import APIRouter, Depends, HTTPException, status, Security, Request, Response
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorClient

from app.schemas.user import UserCreate, Token, User, UserInDB
from app.crud import user as user_crud
from app.db.mongodb_utils import get_database
from app.core.security import verify_password, create_access_token, create_mfa_temp_token
from app.api.v1.dependencies import get_current_user_for_mfa
from app.core.limiter import limiter

router = APIRouter()

@router.post("/signup", response_model=User, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def signup(request: Request, user_in: UserCreate, db: AsyncIOMotorClient = Depends(get_database)):
    """Registers a new user."""
    db_user = await user_crud.get_user_by_email(db, email=user_in.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    new_user = await user_crud.create_user(db, user=user_in)
    return new_user

@router.post("/login")
@limiter.limit("5/minute")
async def login(
    response: Response,
    request: Request,
    db: AsyncIOMotorClient = Depends(get_database), 
    form_data: OAuth2PasswordRequestForm = Depends()):
    """Logs in and returns an access token."""
    user = await user_crud.get_user_by_email(db, email=form_data.username) # OAuth2 form uses 'username' for email
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Check if 2FA is enabled
    user_obj = UserInDB(**user)
    if user_obj.is_totp_enabled:
        # Create a temporary token for 2FA verification
        mfa_token = create_mfa_temp_token(data={"sub": user_obj.email})
        return {
            "mfa_required": True,
            "mfa_token": mfa_token,
            "token_type": "bearer"
        }

    # If 2FA is not enabled, return an access token as usual
    access_token = create_access_token(
        data={"sub": user_obj.email, "roles": user_obj.roles}
    )
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        samesite="lax",
        secure=False # Set to True in production with HTTPS
    )
    return {
        "mfa_required": False,
        "access_token": access_token,
        "token_type": "bearer"
    }


class TOTPVerifyRequest(BaseModel):
    code: str


@router.post("/login/verify-2fa", response_model=Token)
@limiter.limit("5/minute")
async def login_verify_2fa(
    response: Response,
    request: Request,
    request_data: TOTPVerifyRequest,
    current_user: UserInDB = Security(get_current_user_for_mfa),
):
    """
    Verifies the TOTP code and returns the final access token.
    """
    if not current_user.is_totp_enabled or not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not properly configured for this user.",
        )

    totp = pyotp.TOTP(current_user.totp_secret)

    if not totp.verify(request_data.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code.",
        )

    # 2FA code is valid, issue the final access token
    access_token = create_access_token(data={"sub": current_user.email, "roles": current_user.roles})
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        samesite="lax",
        secure=False # Set to True in production with HTTPS
    )
    return {"access_token": access_token, "token_type": "bearer"}
