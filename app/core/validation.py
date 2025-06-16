"""
Centralized validation utilities for security and input validation
"""
import uuid
import re
import logging
from typing import Optional, List, Tuple
from fastapi import HTTPException, status
from pathlib import Path

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom validation error"""
    pass

def validate_uuid(value: str, field_name: str = "ID") -> str:
    """
    Validate UUID format to prevent IDOR attacks
    
    Args:
        value: UUID string to validate
        field_name: Name of the field for error messages
        
    Returns:
        Validated UUID string
        
    Raises:
        HTTPException: If UUID format is invalid
    """
    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} is required"
        )
    
    try:
        # Validate UUID format and normalize
        uuid_obj = uuid.UUID(value)
        normalized_uuid = str(uuid_obj)
        
        # Additional security: check for known patterns
        if normalized_uuid.startswith('00000000-0000-0000-0000'):
            logger.warning(f"Suspicious UUID pattern detected: {normalized_uuid}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid {field_name} format"
            )
            
        return normalized_uuid
        
    except ValueError:
        logger.warning(f"Invalid UUID format attempted: {value} for field {field_name}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name} format"
        )

def validate_filename(filename: str, max_length: int = 255) -> str:
    """
    Validate and sanitize filename to prevent path traversal attacks
    
    Args:
        filename: Original filename
        max_length: Maximum allowed length
        
    Returns:
        Sanitized filename
        
    Raises:
        ValidationError: If filename is invalid
    """
    if not filename:
        raise ValidationError("Filename cannot be empty")
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    
    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', sanitized)
    
    # Remove path traversal attempts
    sanitized = sanitized.replace('..', '_')
    sanitized = sanitized.replace('//', '_')
    
    # Trim length
    if len(sanitized) > max_length:
        name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
        max_name_length = max_length - len(ext) - 1 if ext else max_length
        sanitized = f"{name[:max_name_length]}.{ext}" if ext else name[:max_length]
    
    # Ensure filename is not empty after sanitization
    if not sanitized or sanitized.isspace():
        raise ValidationError("Filename becomes empty after sanitization")
    
    # Block dangerous names
    dangerous_names = [
        'con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5',
        'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4',
        'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9'
    ]
    
    base_name = sanitized.split('.')[0].lower()
    if base_name in dangerous_names:
        sanitized = f"file_{sanitized}"
    
    return sanitized

def validate_file_extension(filename: str, allowed_extensions: List[str]) -> str:
    """
    Validate file extension against allowed list
    
    Args:
        filename: Filename to check
        allowed_extensions: List of allowed extensions (with dots, e.g., ['.mp3', '.wav'])
        
    Returns:
        Validated filename
        
    Raises:
        ValidationError: If extension is not allowed
    """
    if not filename:
        raise ValidationError("Filename is required")
    
    # Extract extension
    file_path = Path(filename)
    extension = file_path.suffix.lower()
    
    if extension not in allowed_extensions:
        logger.warning(f"Blocked file upload with disallowed extension: {extension}")
        raise ValidationError(f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}")
    
    return filename

def validate_file_size(file_size: int, max_size_mb: int = 100) -> bool:
    """
    Validate file size
    
    Args:
        file_size: File size in bytes
        max_size_mb: Maximum size in MB
        
    Returns:
        True if valid
        
    Raises:
        ValidationError: If file is too large
    """
    max_size_bytes = max_size_mb * 1024 * 1024
    
    if file_size > max_size_bytes:
        logger.warning(f"File size {file_size} exceeds limit {max_size_bytes}")
        raise ValidationError(f"File size exceeds maximum allowed size of {max_size_mb}MB")
    
    return True

def validate_path_safety(file_path: str, base_directory: str) -> str:
    """
    Validate that a file path is safe and within base directory
    
    Args:
        file_path: Path to validate
        base_directory: Base directory that file should be within
        
    Returns:
        Resolved safe path
        
    Raises:
        ValidationError: If path is unsafe
    """
    try:
        # Resolve paths to absolute
        base_path = Path(base_directory).resolve()
        target_path = Path(file_path).resolve()
        
        # Check if target is within base directory
        try:
            target_path.relative_to(base_path)
        except ValueError:
            logger.warning(f"Path traversal attempt: {file_path} outside {base_directory}")
            raise ValidationError("Path is outside allowed directory")
        
        return str(target_path)
        
    except Exception as e:
        logger.error(f"Path validation error: {e}")
        raise ValidationError("Invalid file path")

def validate_ip_address(ip: str) -> bool:
    """
    Basic IP address validation
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IP format
    """
    if not ip:
        return False
    
    # Basic IPv4 validation
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True
    except ValueError:
        return False

def validate_content_type(content_type: str, allowed_types: List[str]) -> bool:
    """
    Validate content type header
    
    Args:
        content_type: Content-Type header value
        allowed_types: List of allowed content types
        
    Returns:
        True if valid
        
    Raises:
        ValidationError: If content type not allowed
    """
    if not content_type:
        raise ValidationError("Content-Type header is required")
    
    # Extract main content type (ignore charset etc.)
    main_type = content_type.split(';')[0].strip().lower()
    
    if main_type not in allowed_types:
        logger.warning(f"Blocked request with disallowed content type: {main_type}")
        raise ValidationError(f"Content type not allowed: {main_type}")
    
    return True

def sanitize_user_input(input_str: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks
    
    Args:
        input_str: User input string
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not input_str:
        return ""
    
    # Remove null bytes and control characters except whitespace
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', input_str)
    
    # Limit length
    sanitized = sanitized[:max_length]
    
    # Remove potentially dangerous patterns
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>'
    ]
    
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    return sanitized.strip() 