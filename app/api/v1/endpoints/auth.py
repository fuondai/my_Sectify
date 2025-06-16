# app/api/v1/endpoints/auth.py
import pyotp
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Security, Request, Response
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorClient

from app.schemas.user import UserCreate, Token, User, UserInDB
from app.crud import user as user_crud
from app.db.mongodb_utils import get_database
from app.core.security import (
    verify_password, 
    create_access_token, 
    create_mfa_temp_token,
    validate_password_strength
)
from app.api.v1.dependencies import get_current_user_for_mfa
from app.core.limiter import limiter
from app.core.config import SECURE_COOKIES, ACCESS_TOKEN_EXPIRE_MINUTES

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter()

def get_client_ip(request: Request) -> str:
    """Extract client IP address securely"""
    # Check for proxy headers (be careful with spoofing)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP in the chain (original client)
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        client_ip = request.client.host
    
    return client_ip or "unknown"

@router.post("/signup", response_model=User, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def signup(request: Request, user_in: UserCreate, db: AsyncIOMotorClient = Depends(get_database)):
    """Registers a new user with enhanced security validation."""
    
    # Validate password strength
    is_strong, issues = validate_password_strength(user_in.password)
    if not is_strong:
        logger.warning(f"Weak password signup attempt for email: {user_in.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password requirements not met: {', '.join(issues)}",
        )
    
    # Check if user already exists
    db_user = await user_crud.get_user_by_email(db, email=user_in.email)
    if db_user:
        logger.warning(f"Duplicate email registration attempt: {user_in.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    # Create user
    try:
        new_user = await user_crud.create_user(db, user=user_in)
        logger.info(f"New user registered successfully: {user_in.email}")
        return new_user
    except Exception as e:
        logger.error(f"User creation failed for {user_in.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User registration failed"
        )

@router.post("/login")
@limiter.limit("5/minute")
async def login(
    response: Response,
    request: Request,
    db: AsyncIOMotorClient = Depends(get_database), 
    form_data: OAuth2PasswordRequestForm = Depends()):
    """Logs in and returns an access token with enhanced security."""
    
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Get user and verify credentials
    user = await user_crud.get_user_by_email(db, email=form_data.username) # OAuth2 form uses 'username' for email
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        logger.warning(f"Failed login attempt for {form_data.username} from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_obj = UserInDB(**user)
    
    # Check if user is active
    if not user_obj.is_active:
        logger.warning(f"Inactive user login attempt: {user_obj.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated"
        )
    
    # Check if 2FA is enabled
    if user_obj.is_totp_enabled:
        # Create a temporary token for 2FA verification with IP binding
        mfa_token = create_mfa_temp_token(
            data={"sub": user_obj.email}, 
            ip=client_ip
        )
        logger.info(f"MFA required for user {user_obj.email} from IP {client_ip}")
        return {
            "mfa_required": True,
            "mfa_token": mfa_token,
            "token_type": "bearer"
        }

    # If 2FA is not enabled, return an access token with IP binding
    access_token = create_access_token(
        data={"sub": user_obj.email, "roles": user_obj.roles},
        ip=client_ip
    )
    
    # Set secure cookie
    cookie_max_age = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        samesite="strict",  # Changed from "lax" for better security
        secure=SECURE_COOKIES,  # Use config value based on environment
        max_age=cookie_max_age,
        path="/",  # Restrict to application path
        domain=None  # Let browser set domain automatically
    )
    
    logger.info(f"Successful login for user {user_obj.email} from IP {client_ip}")
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
    Verifies the TOTP code and returns the final access token with enhanced security.
    """
    client_ip = get_client_ip(request)
    
    if not current_user.is_totp_enabled or not current_user.totp_secret:
        logger.warning(f"2FA verification attempt for user without proper 2FA setup: {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not properly configured for this user.",
        )

    totp = pyotp.TOTP(current_user.totp_secret)

    # Verify TOTP code with window tolerance
    if not totp.verify(request_data.code, valid_window=1):
        logger.warning(f"Invalid 2FA code for user {current_user.email} from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code.",
        )

    # 2FA code is valid, issue the final access token with IP binding
    access_token = create_access_token(
        data={"sub": current_user.email, "roles": current_user.roles},
        ip=client_ip
    )
    
    # Set secure cookie
    cookie_max_age = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        samesite="strict",  # Enhanced security
        secure=SECURE_COOKIES,  # Use config value
        max_age=cookie_max_age,
        path="/",
        domain=None
    )
    
    logger.info(f"Successful 2FA verification for user {current_user.email} from IP {client_ip}")
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
async def logout(response: Response, request: Request):
    """Logout user by clearing the authentication cookie."""
    client_ip = get_client_ip(request)
    
    # Clear the authentication cookie
    response.delete_cookie(
        key="access_token",
        path="/",
        domain=None,
        secure=SECURE_COOKIES,
        httponly=True,
        samesite="strict"
    )
    
    logger.info(f"User logout from IP {client_ip}")
    return {"message": "Successfully logged out"}
