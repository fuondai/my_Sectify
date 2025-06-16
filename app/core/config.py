# app/core/config.py
import os
import secrets
import logging
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Configure logging for security events
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityConfigError(Exception):
    """Raised when security configuration is invalid"""
    pass

def validate_secret_key(key: Optional[str]) -> str:
    """Validate SECRET_KEY meets security requirements"""
    if not key:
        raise SecurityConfigError("SECRET_KEY environment variable is required")
    
    if len(key) < 32:
        raise SecurityConfigError("SECRET_KEY must be at least 32 characters long")
    
    # Check complexity
    has_upper = any(c.isupper() for c in key)
    has_lower = any(c.islower() for c in key)
    has_digit = any(c.isdigit() for c in key)
    has_special = any(not c.isalnum() for c in key)
    
    if not (has_upper and has_lower and has_digit and has_special):
        logger.warning("SECRET_KEY does not meet complexity requirements")
    
    return key

def validate_algorithm(algorithm: Optional[str]) -> str:
    """Validate JWT algorithm is secure"""
    if not algorithm:
        algorithm = "HS256"  # Secure default
    
    allowed_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]
    if algorithm not in allowed_algorithms:
        raise SecurityConfigError(f"Unsupported algorithm: {algorithm}")
    
    return algorithm

def validate_token_expire_minutes(expire_str: Optional[str]) -> int:
    """Validate token expiration time"""
    if not expire_str:
        return 60  # Secure default: 1 hour
    
    try:
        expire_minutes = int(expire_str)
    except ValueError:
        raise SecurityConfigError("ACCESS_TOKEN_EXPIRE_MINUTES must be a valid integer")
    
    if expire_minutes < 5:
        raise SecurityConfigError("Token expiration too short (minimum 5 minutes)")
    
    if expire_minutes > 1440:  # 24 hours
        logger.warning("Token expiration is very long (>24 hours), consider reducing")
    
    return expire_minutes

# Database Configuration
MONGO_DATABASE_URL = os.getenv("MONGO_DATABASE_URL")
MONGO_DATABASE_NAME = os.getenv("MONGO_DATABASE_NAME", "sectify_db")

if not MONGO_DATABASE_URL:
    raise SecurityConfigError("MONGO_DATABASE_URL environment variable is required")

# Security Configuration with validation
try:
    SECRET_KEY = validate_secret_key(os.getenv("SECRET_KEY"))
    ALGORITHM = validate_algorithm(os.getenv("ALGORITHM"))
    ACCESS_TOKEN_EXPIRE_MINUTES = validate_token_expire_minutes(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
    
    # Additional security settings
    MFA_TOKEN_EXPIRE_MINUTES = int(os.getenv("MFA_TOKEN_EXPIRE_MINUTES", "5"))
    RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "100"))
    
    # Production security flags
    IS_PRODUCTION = os.getenv("ENVIRONMENT", "development").lower() == "production"
    SECURE_COOKIES = os.getenv("SECURE_COOKIES", "true" if IS_PRODUCTION else "false").lower() == "true"
    
    logger.info("Security configuration validated successfully")
    
except SecurityConfigError as e:
    logger.error(f"Security configuration error: {e}")
    raise
except Exception as e:
    logger.error(f"Unexpected configuration error: {e}")
    raise SecurityConfigError(f"Configuration validation failed: {e}")

# Security headers configuration
SECURITY_HEADERS = {
    "Cache-Control": "no-store, private",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains" if IS_PRODUCTION else None,
}

# Enhanced CSP policy
CSP_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data: https:; "
    "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
    "font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
    "media-src 'self' blob:; "
    "object-src 'none'; "
    "worker-src 'self' blob:; "
    "frame-ancestors 'none';"
)

# Rate limiting configuration  
RATE_LIMITS = {
    "auth": "5/minute",
    "upload": "3/minute", 
    "stream_key": "10/minute",
    "stream_segment": "60/minute",
    "default": "100/minute"
}
