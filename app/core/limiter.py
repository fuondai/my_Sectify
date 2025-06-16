# app/core/limiter.py
import logging
from typing import Optional
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

logger = logging.getLogger(__name__)

def get_rate_limit_key(request: Request) -> str:
    """
    Enhanced rate limiting key that combines multiple factors
    
    Uses a combination of:
    - Client IP address (primary)
    - User-Agent hash (to detect automated tools)
    - User ID if authenticated (for user-specific limits)
    
    Returns:
        Combined key for rate limiting
    """
    ip = get_remote_address(request)
    
    # Get user info if available
    user_id = None
    if hasattr(request.state, 'user') and request.state.user:
        user_id = request.state.user.id
    
    # Get user agent hash
    user_agent = request.headers.get("user-agent", "unknown")
    user_agent_hash = hash(user_agent) % 10000  # Simple hash for grouping
    
    # Combine factors for rate limiting key
    if user_id:
        # Authenticated users: use user ID + IP for more granular control
        key = f"user:{user_id}:{ip}"
    else:
        # Anonymous users: use IP + UA hash
        key = f"anon:{ip}:{user_agent_hash}"
    
    return key

def get_user_specific_key(request: Request) -> str:
    """
    User-specific rate limiting key for authenticated endpoints
    
    Returns:
        User-specific key if authenticated, IP-based key otherwise
    """
    try:
        # Try to get user from request state (set by authentication middleware)
        if hasattr(request.state, 'user') and request.state.user:
            return f"user:{request.state.user.id}"
    except Exception:
        pass
    
    # Fallback to IP-based limiting
    return get_remote_address(request)

def log_rate_limit_violation(request: Request, limit: str):
    """
    Log rate limit violations for security monitoring
    
    Args:
        request: FastAPI request object
        limit: Rate limit that was exceeded
    """
    ip = get_remote_address(request)
    user_agent = request.headers.get("user-agent", "unknown")
    endpoint = str(request.url.path)
    
    # Check for suspicious patterns
    suspicious_indicators = []
    
    if "bot" in user_agent.lower():
        suspicious_indicators.append("bot_user_agent")
    
    if len(request.headers.get("user-agent", "")) < 10:
        suspicious_indicators.append("short_user_agent")
    
    if not request.headers.get("accept"):
        suspicious_indicators.append("missing_accept_header")
    
    if request.headers.get("x-forwarded-for"):
        suspicious_indicators.append("proxy_headers")
    
    log_level = logging.WARNING
    if suspicious_indicators:
        log_level = logging.ERROR
    
    logger.log(
        log_level,
        f"Rate limit exceeded: {limit} | IP: {ip} | Endpoint: {endpoint} | UA: {user_agent[:100]} | Suspicious: {suspicious_indicators}"
    )

# Initialize the enhanced Limiter
limiter = Limiter(
    key_func=get_rate_limit_key,
    default_limits=["100/minute"],  # Default limit for all endpoints
)

# User-specific limiter for authenticated endpoints
user_limiter = Limiter(
    key_func=get_user_specific_key,
    default_limits=["200/minute"]  # Higher limit for authenticated users
)
