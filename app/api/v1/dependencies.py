# app/api/v1/dependencies.py
import logging
from fastapi import Depends, HTTPException, status, Request
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt

from app.core.config import SECRET_KEY, ALGORITHM
from typing import Optional
from app.schemas.user import TokenData, UserInDB, UserCreate
from app.crud import user as user_crud
from app.db.mongodb_utils import get_database

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

async def get_current_user(
    db: AsyncIOMotorClient = Depends(get_database),
    token: str = Depends(oauth2_scheme)
) -> UserInDB:
    """Giải mã token, xác thực và trả về thông tin người dùng."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        purpose: str = payload.get("purpose")
        if email is None or purpose != "access":
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = await user_crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return UserInDB(**user)


async def get_current_active_user(
    security_scopes: SecurityScopes,
    current_user: UserInDB = Depends(get_current_user)
) -> UserInDB:
    """
    Gets the current user, checks if they are active, and verifies scopes.
    """
    if not getattr(current_user, 'is_active', False):
        raise HTTPException(status_code=400, detail="Inactive user")
    
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
        user_roles = getattr(current_user, 'roles', [])
        for scope in security_scopes.scopes:
            if scope not in user_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": authenticate_value},
                )
    return current_user


async def get_any_active_user(
    current_user: UserInDB = Depends(get_current_user)
) -> UserInDB:
    logging.info(f"--- [DEPENDENCY] Entering get_any_active_user for user: {current_user.email} ---")
    """
    Gets the current user and checks if they are active. Does NOT check scopes.
    Used for endpoints accessible to any authenticated user.
    """
    if not getattr(current_user, 'is_active', False):
        logging.warning(f"--- [DEPENDENCY] User {current_user.email} is inactive. ---")
        raise HTTPException(status_code=400, detail="Inactive user")
    logging.info(f"--- [DEPENDENCY] User {current_user.email} is active. Exiting get_any_active_user. ---")
    return current_user


async def get_current_user_for_mfa(
    db: AsyncIOMotorClient = Depends(get_database),
    token: str = Depends(oauth2_scheme)
) -> UserInDB:
    """Giải mã token tạm thời cho MFA, xác thực và trả về thông tin người dùng.
    Chỉ chấp nhận token có mục đích là 'mfa_verification'."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate MFA credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        purpose: str = payload.get("purpose")
        if email is None or purpose != "mfa_verification":
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = await user_crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return UserInDB(**user)


async def try_get_current_user(
    request: Request,
    db: AsyncIOMotorClient = Depends(get_database)
) -> Optional[UserInDB]:
    """
    Tries to get the current user from the Authorization header or an auth cookie.
    Returns None if no valid token is found, instead of raising an exception.
    """
    token = None
    # 1. Try to get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    # 2. If not in header, try to get from cookie
    if not token:
        token = request.cookies.get("access_token")
        # The cookie value might be in the format 'Bearer <token>'
        if token and token.startswith("Bearer "):
            token = token.split(" ")[1]

    if not token:
        return None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        purpose: str = payload.get("purpose")
        if email is None or purpose != "access":
            return None # Yêu cầu access token
        token_data = TokenData(email=email)
    except JWTError:
        return None # Token không hợp lệ

    user = await user_crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        return None # Người dùng không tồn tại
    
    return UserInDB(**user)
