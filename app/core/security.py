# app/core/security.py
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from jose import JWTError, jwt
from app.core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, MFA_TOKEN_EXPIRE_MINUTES

# Configure logging
logger = logging.getLogger(__name__)

# Use Argon2 for password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashes a password."""
    return pwd_context.hash(password)

def _create_ip_hash(ip: str) -> str:
    """Create a secure hash of IP address for token binding"""
    if not ip:
        ip = "unknown"
    return hashlib.sha256(f"{ip}{SECRET_KEY}".encode()).hexdigest()[:16]

def create_mfa_temp_token(data: dict, ip: Optional[str] = None):
    """Creates a temporary JWT token for multi-factor authentication (MFA)."""
    to_encode = data.copy()
    
    # Add security context
    expire = datetime.now(timezone.utc) + timedelta(minutes=MFA_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire, 
        "purpose": "mfa_verification",
        "iat": datetime.now(timezone.utc),
        "ip_hash": _create_ip_hash(ip) if ip else None
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"MFA token created for user: {data.get('sub', 'unknown')}")
    return encoded_jwt

def create_access_token(data: dict, ip: Optional[str] = None):
    """Creates a JWT access token with IP binding."""
    to_encode = data.copy()
    
    # Add security context
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire, 
        "purpose": "access",
        "iat": datetime.now(timezone.utc),
        "ip_hash": _create_ip_hash(ip) if ip else None,
        "session_id": hashlib.sha256(f"{data.get('sub', '')}{datetime.now(timezone.utc)}{SECRET_KEY}".encode()).hexdigest()[:16]
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"Access token created for user: {data.get('sub', 'unknown')}")
    return encoded_jwt

def verify_token(token: str, purpose: str, ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify JWT token with additional security checks
    
    Args:
        token: JWT token string
        purpose: Expected token purpose ('access' or 'mfa_verification')
        ip: Client IP address for binding verification
        
    Returns:
        Token payload if valid
        
    Raises:
        JWTError: If token is invalid
        ValueError: If security checks fail
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Verify token purpose
        token_purpose = payload.get("purpose")
        if token_purpose != purpose:
            logger.warning(f"Token purpose mismatch. Expected: {purpose}, Got: {token_purpose}")
            raise ValueError("Invalid token purpose")
        
        # Verify IP binding if provided
        if ip:
            token_ip_hash = payload.get("ip_hash")
            current_ip_hash = _create_ip_hash(ip)
            
            if token_ip_hash and token_ip_hash != current_ip_hash:
                logger.warning(f"IP binding verification failed for user: {payload.get('sub', 'unknown')}")
                raise ValueError("Token IP binding mismatch")
        
        # Check token age (additional security)
        issued_at = payload.get("iat")
        if issued_at:
            token_age = datetime.now(timezone.utc).timestamp() - issued_at
            max_age = 86400  # 24 hours maximum regardless of expiry
            
            if token_age > max_age:
                logger.warning(f"Token too old: {token_age} seconds")
                raise ValueError("Token expired due to age")
        
        return payload
        
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise

def invalidate_user_sessions(user_email: str):
    """
    Mark for user session invalidation (would need Redis/cache implementation)
    For now, just log the event
    """
    logger.info(f"Session invalidation requested for user: {user_email}")
    # TODO: Implement with Redis/cache to track invalidated sessions

def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password meets security requirements
    
    Returns:
        (is_valid, list_of_issues)
    """
    issues = []
    
    if len(password) < 12:
        issues.append("Password must be at least 12 characters long")
    
    if not any(c.isupper() for c in password):
        issues.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        issues.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        issues.append("Password must contain at least one digit")
    
    if not any(not c.isalnum() for c in password):
        issues.append("Password must contain at least one special character")
    
    # Check for common patterns
    common_patterns = ['password', '123456', 'qwerty', 'admin', 'sectify']
    if any(pattern.lower() in password.lower() for pattern in common_patterns):
        issues.append("Password contains common patterns")
    
    return len(issues) == 0, issues
