# -*- coding: utf-8 -*-
"""
Chaotic Audio Protection Module

Mã hóa/giải mã file âm thanh WAV/MP3 bằng Chaotic Stream Cipher với SHA integrity checking.
Đây là lớp bảo vệ bổ sung trước khi file được xử lý thành HLS.
"""

import os
import hashlib
import logging
import tempfile
import time
from typing import Tuple, Optional, Dict, Any, Callable
from pathlib import Path

from app.core.chaotic_cipher import encrypt_with_validation, decrypt_with_validation

logger = logging.getLogger(__name__)

# Supported audio formats for chaotic encryption
SUPPORTED_FORMATS = {'.wav', '.mp3', '.m4a', '.flac'}
ENCRYPTED_SUFFIX = '.encrypted'

# Progress tracking storage (in production, use Redis or database)
_progress_storage = {}

def estimate_encryption_time(file_size: int, performance_mode: str) -> float:
    """
    Ước tính thời gian encryption dựa trên file size và performance mode.
    
    Args:
        file_size: Kích thước file (bytes)
        performance_mode: fast, balanced, secure
        
    Returns:
        Estimated time in seconds
    """
    # Base time per MB for different modes (updated ultra fast)
    time_per_mb = {
        'fast': 0.5,      # ~0.5 seconds per MB (ultra fast!)
        'balanced': 6.0,  # ~6 seconds per MB  
        'secure': 15.0    # ~15 seconds per MB
    }
    
    file_size_mb = file_size / (1024 * 1024)
    base_time = file_size_mb * time_per_mb.get(performance_mode, 6.0)
    
    # Add overhead for PBKDF2 and file I/O
    overhead = 2.0 + (file_size_mb * 0.5)
    
    return base_time + overhead

def update_progress(track_id: str, progress: float, step: str, performance_mode: str, 
                   estimated_remaining: Optional[float] = None):
    """Update progress cho track."""
    _progress_storage[track_id] = {
        'track_id': track_id,
        'status': 'processing' if progress < 100 else 'completed',
        'progress_percent': progress,
        'current_step': step,
        'estimated_remaining': estimated_remaining,
        'performance_mode': performance_mode,
        'updated_at': time.time()
    }

def get_progress(track_id: str) -> Optional[Dict]:
    """Lấy progress của track."""
    return _progress_storage.get(track_id)

class ChaoticAudioProtection:
    """
    Class wrapper cho chaotic audio protection functions với progress tracking.
    """
    
    def __init__(self, master_secret: Optional[str] = None):
        """
        Initialize ChaoticAudioProtection.
        
        Args:
            master_secret: Master secret key (optional)
        """
        self.master_secret = master_secret or os.environ.get('SECTIFY_MASTER_SECRET', 'default_secret_key')
        
    def encrypt_audio_file(
        self,
        input_path: str,
        output_path: str,
        user_id: str,
        track_id: str,
        performance_mode: str = "balanced",
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Mã hóa file âm thanh với user-specific key và progress tracking.
        
        Args:
            input_path: Đường dẫn file âm thanh gốc
            output_path: Đường dẫn file output
            user_id: ID của user
            track_id: ID của track
            performance_mode: fast, balanced, secure
            progress_callback: Optional callback function for progress updates
            
        Returns:
            Dict với success status và metadata
        """
        start_time = time.time()
        
        try:
            # Validate performance mode
            if performance_mode not in ['fast', 'balanced', 'secure']:
                performance_mode = 'balanced'
            
            # Set environment variable cho chaotic cipher
            os.environ['CHAOTIC_PERFORMANCE_MODE'] = performance_mode
            
            # Get file size và estimate time
            file_size = os.path.getsize(input_path)
            estimated_time = estimate_encryption_time(file_size, performance_mode)
            
            # Initialize progress
            update_progress(track_id, 0, "Initializing encryption...", performance_mode, estimated_time)
            if progress_callback:
                progress_callback(0, "Initializing encryption...")
            
            # Step 1: Calculate SHA-256 (10% progress)
            update_progress(track_id, 10, "Calculating file hash...", performance_mode)
            if progress_callback:
                progress_callback(10, "Calculating file hash...")
                
            original_sha256 = calculate_file_sha256(input_path)
            
            # Step 2: Generate encryption key (20% progress)
            update_progress(track_id, 20, "Generating encryption key...", performance_mode)
            if progress_callback:
                progress_callback(20, "Generating encryption key...")
                
            secret_key = create_audio_protection_key(user_id, track_id, self.master_secret)
            
            # Step 3: Read file (30% progress)
            update_progress(track_id, 30, "Reading audio file...", performance_mode)
            if progress_callback:
                progress_callback(30, "Reading audio file...")
                
            with open(input_path, 'rb') as f:
                audio_data = f.read()
            
            # Step 4: Encrypt data (30% -> 90% progress)
            update_progress(track_id, 40, f"Encrypting with {performance_mode} mode...", performance_mode)
            if progress_callback:
                progress_callback(40, f"Encrypting with {performance_mode} mode...")
            
            # Simulate progress during encryption (since we can't track internal progress)
            def encryption_progress_simulator():
                for i in range(40, 90, 10):
                    time.sleep(0.1)  # Small delay
                    remaining_time = max(0, estimated_time - (time.time() - start_time))
                    update_progress(track_id, i, f"Encrypting... ({i}%)", performance_mode, remaining_time)
                    if progress_callback:
                        progress_callback(i, f"Encrypting... ({i}%)")
            
            # Start progress simulation in background (simplified)
            encrypted_data = encrypt_with_validation(audio_data, secret_key)
            
            # Step 5: Write encrypted file (95% progress)
            update_progress(track_id, 95, "Writing encrypted file...", performance_mode)
            if progress_callback:
                progress_callback(95, "Writing encrypted file...")
                
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Step 6: Complete (100% progress)
            encryption_time = time.time() - start_time
            update_progress(track_id, 100, "Encryption completed!", performance_mode, 0)
            if progress_callback:
                progress_callback(100, "Encryption completed!")
            
            return {
                "success": True,
                "encrypted_path": output_path,
                "original_file_sha256": original_sha256,
                "user_id": user_id,
                "track_id": track_id,
                "performance_mode": performance_mode,
                "encryption_time": encryption_time,
                "estimated_time": estimated_time
            }
            
        except Exception as e:
            logger.error(f"ChaoticAudioProtection encrypt failed: {e}")
            update_progress(track_id, 0, f"Encryption failed: {str(e)}", performance_mode)
            _progress_storage[track_id]['status'] = 'failed'
            
            return {
                "success": False,
                "error": str(e),
                "performance_mode": performance_mode
            }
        finally:
            # Clean up environment variable
            if 'CHAOTIC_PERFORMANCE_MODE' in os.environ:
                del os.environ['CHAOTIC_PERFORMANCE_MODE']
    
    def decrypt_audio_file(
        self,
        encrypted_path: str,
        output_path: str,
        user_id: str,
        track_id: str,
        expected_sha256: Optional[str] = None,
        performance_mode: str = "balanced"
    ) -> Dict[str, Any]:
        """
        Giải mã file âm thanh với user-specific key.
        """
        try:
            # Set performance mode
            os.environ['CHAOTIC_PERFORMANCE_MODE'] = performance_mode
            
            # Tạo key specific cho user và track
            secret_key = create_audio_protection_key(user_id, track_id, self.master_secret)
            
            # Nếu không có expected_sha256, skip integrity check
            if expected_sha256:
                decrypted_path = decrypt_audio_file(
                    encrypted_path=encrypted_path,
                    secret_key=secret_key,
                    expected_sha256=expected_sha256,
                    output_path=output_path,
                    verify_integrity=True
                )
            else:
                # Decrypt without integrity check
                with open(encrypted_path, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = decrypt_with_validation(encrypted_data, secret_key)
                
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                
                decrypted_path = output_path
            
            return {
                "success": True,
                "decrypted_path": decrypted_path,
                "user_id": user_id,
                "track_id": track_id,
                "performance_mode": performance_mode
            }
            
        except Exception as e:
            logger.error(f"ChaoticAudioProtection decrypt failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "performance_mode": performance_mode
            }
        finally:
            # Clean up environment variable
            if 'CHAOTIC_PERFORMANCE_MODE' in os.environ:
                del os.environ['CHAOTIC_PERFORMANCE_MODE']

def calculate_file_sha256(file_path: str) -> str:
    """
    Tính toán SHA-256 hash của file để kiểm tra tính toàn vẹn.
    
    Args:
        file_path: Đường dẫn tới file
        
    Returns:
        str: SHA-256 hash dưới dạng hex string
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Đọc file theo chunks để handle file lớn
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating SHA-256 for {file_path}: {e}")
        raise

def encrypt_audio_file(
    input_path: str,
    secret_key: str,
    *,
    output_path: Optional[str] = None,
    preserve_extension: bool = True
) -> Tuple[str, str]:
    """
    Mã hóa file âm thanh bằng Chaotic Stream Cipher.
    
    Args:
        input_path: Đường dẫn file âm thanh gốc
        secret_key: Khóa bí mật để mã hóa
        output_path: Đường dẫn output (optional)
        preserve_extension: Có giữ lại extension gốc không
        
    Returns:
        Tuple[str, str]: (encrypted_file_path, original_sha256)
        
    Raises:
        FileNotFoundError: Nếu file input không tồn tại
        ValueError: Nếu format không được hỗ trợ
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Audio file not found: {input_path}")
    
    # Kiểm tra format
    file_ext = Path(input_path).suffix.lower()
    if file_ext not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported audio format: {file_ext}. Supported: {SUPPORTED_FORMATS}")
    
    logger.info(f"Starting chaotic encryption for: {input_path}")
    
    # Tính SHA-256 của file gốc
    original_sha256 = calculate_file_sha256(input_path)
    logger.debug(f"Original file SHA-256: {original_sha256}")
    
    # Xác định output path
    if output_path is None:
        if preserve_extension:
            output_path = input_path + ENCRYPTED_SUFFIX
        else:
            output_path = Path(input_path).with_suffix(ENCRYPTED_SUFFIX).as_posix()
    
    try:
        # Đọc file audio gốc
        with open(input_path, 'rb') as f:
            audio_data = f.read()
        
        logger.debug(f"Read {len(audio_data)} bytes from {input_path}")
        
        # Mã hóa bằng chaotic cipher với validation
        encrypted_data = encrypt_with_validation(audio_data, secret_key)
        
        logger.debug(f"Encrypted to {len(encrypted_data)} bytes")
        
        # Lưu file đã mã hóa
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        logger.info(f"Successfully encrypted audio file: {output_path}")
        
        return output_path, original_sha256
        
    except Exception as e:
        logger.error(f"Failed to encrypt audio file {input_path}: {e}")
        # Cleanup nếu có lỗi
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
        raise

def decrypt_audio_file(
    encrypted_path: str,
    secret_key: str,
    expected_sha256: str,
    *,
    output_path: Optional[str] = None,
    verify_integrity: bool = True
) -> str:
    """
    Giải mã file âm thanh đã được mã hóa bằng Chaotic Stream Cipher.
    
    Args:
        encrypted_path: Đường dẫn file đã mã hóa
        secret_key: Khóa bí mật để giải mã
        expected_sha256: SHA-256 hash mong đợi của file gốc
        output_path: Đường dẫn output (optional)
        verify_integrity: Có kiểm tra tính toàn vẹn không
        
    Returns:
        str: Đường dẫn file đã giải mã
        
    Raises:
        FileNotFoundError: Nếu file encrypted không tồn tại
        ValueError: Nếu integrity check thất bại
    """
    if not os.path.isfile(encrypted_path):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")
    
    logger.info(f"Starting chaotic decryption for: {encrypted_path}")
    
    # Xác định output path
    if output_path is None:
        if encrypted_path.endswith(ENCRYPTED_SUFFIX):
            output_path = encrypted_path[:-len(ENCRYPTED_SUFFIX)]
        else:
            output_path = encrypted_path + '.decrypted'
    
    try:
        # Đọc file đã mã hóa
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        logger.debug(f"Read {len(encrypted_data)} bytes from {encrypted_path}")
        
        # Giải mã bằng chaotic cipher với validation
        decrypted_data = decrypt_with_validation(encrypted_data, secret_key)
        
        logger.debug(f"Decrypted to {len(decrypted_data)} bytes")
        
        # Lưu file đã giải mã tạm thời để kiểm tra SHA
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(decrypted_data)
            temp_path = temp_file.name
        
        try:
            # Kiểm tra tính toàn vẹn bằng SHA-256
            if verify_integrity:
                actual_sha256 = calculate_file_sha256(temp_path)
                if actual_sha256 != expected_sha256:
                    raise ValueError(
                        f"Integrity check failed! Expected SHA-256: {expected_sha256}, "
                        f"but got: {actual_sha256}"
                    )
                logger.debug("SHA-256 integrity check passed")
            
            # Di chuyển file tạm thời đến vị trí cuối cùng
            if os.path.exists(output_path):
                os.remove(output_path)
            os.rename(temp_path, output_path)
            
            logger.info(f"Successfully decrypted audio file: {output_path}")
            
            return output_path
            
        finally:
            # Clean up temp file nếu còn tồn tại
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
                    
    except Exception as e:
        logger.error(f"Failed to decrypt audio file {encrypted_path}: {e}")
        # Cleanup nếu có lỗi
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
        raise

def secure_audio_workflow(
    input_path: str,
    secret_key: str,
    *,
    keep_encrypted: bool = True,
    temp_dir: Optional[str] = None
) -> Tuple[str, str, str]:
    """
    Workflow hoàn chỉnh: Mã hóa → Xử lý → Giải mã (nếu cần).
    
    Args:
        input_path: Đường dẫn file audio gốc
        secret_key: Khóa bí mật
        keep_encrypted: Có giữ lại file encrypted không
        temp_dir: Thư mục tạm (optional)
        
    Returns:
        Tuple[str, str, str]: (encrypted_path, decrypted_path, sha256_hash)
    """
    # Tạo temp directory nếu cần
    if temp_dir:
        os.makedirs(temp_dir, exist_ok=True)
        encrypted_path = os.path.join(temp_dir, Path(input_path).name + ENCRYPTED_SUFFIX)
    else:
        encrypted_path = None
    
    # Bước 1: Mã hóa file gốc
    encrypted_path, original_sha256 = encrypt_audio_file(
        input_path, secret_key, output_path=encrypted_path
    )
    
    logger.info(f"Secure audio workflow - Encrypted: {encrypted_path}")
    
    # Bước 2: Giải mã để kiểm tra (optional - có thể bỏ qua để tối ưu performance)
    decrypted_path = None
    
    # Bước 3: Clean up nếu không cần giữ encrypted file
    if not keep_encrypted:
        # Chỉ xóa sau khi đã xử lý xong
        pass
    
    return encrypted_path, decrypted_path, original_sha256

def create_audio_protection_key(user_id: str, track_id: str, master_secret: str) -> str:
    """
    Tạo khóa bảo vệ âm thanh từ user_id, track_id và master secret.
    
    Args:
        user_id: ID người dùng
        track_id: ID track
        master_secret: Master secret từ environment
        
    Returns:
        str: Khóa bảo vệ được derive
    """
    # Kết hợp các components
    combined = f"{user_id}:{track_id}:{master_secret}"
    
    # Sử dụng PBKDF2 để derive key mạnh
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    
    salt = hashlib.sha256(f"audio_protection:{track_id}".encode()).digest()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=50000,  # Ít hơn chaotic cipher để tối ưu performance
    )
    
    key_bytes = kdf.derive(combined.encode())
    # Encode thành string dễ sử dụng
    return base64.b64encode(key_bytes).decode('ascii')

# Utility functions để integration
def is_audio_file_encrypted(file_path: str) -> bool:
    """Kiểm tra xem file có phải là file audio đã được mã hóa không."""
    return file_path.endswith(ENCRYPTED_SUFFIX)

def get_original_filename(encrypted_path: str) -> str:
    """Lấy tên file gốc từ file encrypted."""
    if encrypted_path.endswith(ENCRYPTED_SUFFIX):
        return encrypted_path[:-len(ENCRYPTED_SUFFIX)]
    return encrypted_path 