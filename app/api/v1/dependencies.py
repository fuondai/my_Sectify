# app/api/v1/dependencies.py
import logging
from fastapi import Depends, HTTPException, status, Request
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt

from app.core.config import SECRET_KEY, ALGORITHM
from app.core.security import verify_token
from typing import Optional
from app.schemas.user import TokenData, UserInDB, UserCreate
from app.crud import user as user_crud
from app.db.mongodb_utils import get_database

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

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

async def get_current_user(
    request: Request,
    db: AsyncIOMotorClient = Depends(get_database),
    token: str = Depends(oauth2_scheme)
) -> UserInDB:
    """Decode token, authenticate and return user information with enhanced security."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        client_ip = get_client_ip(request)
        
        # Use the enhanced verify_token function with IP binding
        payload = verify_token(token, "access", ip=client_ip)
        
        email: str = payload.get("sub")
        if email is None:
            logger.warning("Token without subject claim")
            raise credentials_exception
            
        token_data = TokenData(email=email)
        
    except ValueError as e:
        # IP binding or other security validation failed
        logger.warning(f"Token security validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token security validation failed",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise credentials_exception
    except Exception as e:
        logger.error(f"Unexpected error in token validation: {e}")
        raise credentials_exception
    
    user = await user_crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        logger.warning(f"User not found for email: {token_data.email}")
        raise credentials_exception
    
    user_obj = UserInDB(**user)
    
    # Additional security checks
    if not getattr(user_obj, 'is_active', False):
        logger.warning(f"Inactive user attempted access: {user_obj.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated"
        )
    
    return user_obj


async def get_current_active_user(
    security_scopes: SecurityScopes,
    current_user: UserInDB = Depends(get_current_user)
) -> UserInDB:
    """
    Gets the current user, checks if they are active, and verifies scopes.
    """
    if not getattr(current_user, 'is_active', False):
        logger.warning(f"Inactive user access attempt: {current_user.email}")
        raise HTTPException(status_code=400, detail="Inactive user")
    
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
        user_roles = getattr(current_user, 'roles', [])
        
        for scope in security_scopes.scopes:
            if scope not in user_roles:
                logger.warning(f"Insufficient permissions for user {current_user.email}: required {scope}, has {user_roles}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": authenticate_value},
                )
    return current_user


async def get_any_active_user(
    current_user: UserInDB = Depends(get_current_user)
) -> UserInDB:
    """
    Gets the current user and checks if they are active. Does NOT check scopes.
    Used for endpoints accessible to any authenticated user.
    """
    logging.info(f"--- [DEPENDENCY] Entering get_any_active_user for user: {current_user.email} ---")
    
    if not getattr(current_user, 'is_active', False):
        logging.warning(f"--- [DEPENDENCY] User {current_user.email} is inactive. ---")
        raise HTTPException(status_code=400, detail="Inactive user")
    
    logging.info(f"--- [DEPENDENCY] User {current_user.email} is active. Exiting get_any_active_user. ---")
    return current_user


async def get_current_user_for_mfa(
    request: Request,
    db: AsyncIOMotorClient = Depends(get_database),
    token: str = Depends(oauth2_scheme)
) -> UserInDB:
    """Decode temporary MFA token, authenticate and return user information.
    Only accepts tokens with purpose 'mfa_verification'."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate MFA credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        client_ip = get_client_ip(request)
        
        # Use the enhanced verify_token function for MFA tokens
        payload = verify_token(token, "mfa_verification", ip=client_ip)
        
        email: str = payload.get("sub")
        if email is None:
            logger.warning("MFA token without subject claim")
            raise credentials_exception
            
        token_data = TokenData(email=email)
        
    except ValueError as e:
        # IP binding or other security validation failed
        logger.warning(f"MFA token security validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA token security validation failed",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        logger.warning(f"MFA JWT validation failed: {e}")
        raise credentials_exception
    except Exception as e:
        logger.error(f"Unexpected error in MFA token validation: {e}")
        raise credentials_exception

    user = await user_crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        logger.warning(f"User not found for MFA email: {token_data.email}")
        raise credentials_exception
    
    return UserInDB(**user)


async def try_get_current_user(
    request: Request,
    db: AsyncIOMotorClient = Depends(get_database)
) -> Optional[UserInDB]:
    """
    Tries to get the current user from the Authorization header or an auth cookie.
    Returns None if no valid token is found, instead of raising an exception.
    Enhanced with IP binding validation.
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
        client_ip = get_client_ip(request)
        
        # Use the enhanced verify_token function
        payload = verify_token(token, "access", ip=client_ip)
        
        email: str = payload.get("sub")
        if email is None:
            return None
            
        token_data = TokenData(email=email)
        
    except (ValueError, JWTError) as e:
        # Log security issues but don't expose them to prevent enumeration
        logger.warning(f"Token validation failed in try_get_current_user: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in try_get_current_user: {e}")
        return None

    user = await user_crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        return None
    
    user_obj = UserInDB(**user)
    
    # Check if user is active
    if not getattr(user_obj, 'is_active', False):
        logger.warning(f"Inactive user attempted access: {user_obj.email}")
        return None
    
    return user_obj
