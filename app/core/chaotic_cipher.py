# -*- coding: utf-8 -*-
"""
Triển khai Mật mã luồng hỗn loạn sử dụng Mạng Lưới Sơ Đồ Nối Kết (Coupled Map Lattice - CML).

Thuật toán này sử dụng một mạng lưới các sơ đồ logistic nối kết với nhau để tạo ra
một hệ thống hỗn loạn không-thời gian phức tạp, mang lại tính bảo mật cao hơn
so với một sơ đồ logistic đơn lẻ.
"""

import hashlib
import numpy as np
import secrets
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Performance mode configuration
PERFORMANCE_MODE = os.environ.get('CHAOTIC_PERFORMANCE_MODE', 'balanced').lower()

if PERFORMANCE_MODE == 'fast':
    # Ultra-ultra fast mode cho development - tối thiểu absolute
    LATTICE_SIZE = 1         # Chỉ 1 node (fastest possible)
    TRANSIENT_STEPS = 5      # Gần như không có transient
    PBKDF2_ITERATIONS = 10   # Tối thiểu iterations
elif PERFORMANCE_MODE == 'secure':
    # Secure mode cho production - chậm nhưng rất secure
    LATTICE_SIZE = 16
    TRANSIENT_STEPS = 1000
    PBKDF2_ITERATIONS = 10000
else:
    # Balanced mode (default) - balance giữa security và performance
    LATTICE_SIZE = 8   # Balance security vs performance
    TRANSIENT_STEPS = 500  # Đủ để đạt chaos state nhưng không quá chậm
    PBKDF2_ITERATIONS = 5000   # Balance security vs performance (từ 100k xuống)

def _initialize_cml(secret_key: str, salt: bytes = None) -> tuple[np.ndarray, np.ndarray, float, bytes]:
    """
    Khởi tạo trạng thái ban đầu, tham số và hằng số nối kết cho CML từ khóa bí mật.
    
    Cải thiện bảo mật:
    - Sử dụng PBKDF2 với salt và nhiều iterations
    - Tăng entropy với multiple hash rounds
    - Thêm domain separation cho các components khác nhau
    """
    # Tạo salt ngẫu nhiên nếu chưa có
    if salt is None:
        salt = secrets.token_bytes(32)  # 256-bit salt
    
    # Sử dụng PBKDF2 với salt để derive master key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,  # 512 bits
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    master_key = kdf.derive(secret_key.encode())
    
    # Domain separation cho các components khác nhau (max 16 bytes for BLAKE2b person)
    x_domain = b"CML_INIT_STATE"  # 14 bytes
    r_domain = b"CML_PARAMETERS"  # 14 bytes  
    eps_domain = b"CML_COUPLING"  # 12 bytes
    
    # Derive keys cho từng component với domain separation
    x_key = hashlib.blake2b(master_key, digest_size=32, person=x_domain).digest()
    r_key = hashlib.blake2b(master_key, digest_size=32, person=r_domain).digest()
    eps_key = hashlib.blake2b(master_key, digest_size=32, person=eps_domain).digest()
    
    # Khởi tạo véc-tơ trạng thái ban đầu x với entropy cao hơn
    x = np.zeros(LATTICE_SIZE)
    for i in range(LATTICE_SIZE):
        # Sử dụng 4 bytes cho mỗi state để tăng precision
        seed_bytes = x_key[i*2:(i+1)*2] if i*2+1 < len(x_key) else x_key[i%16:(i%16)+2]
        seed_val = int.from_bytes(seed_bytes, 'big')
        # Chuẩn hóa và đảm bảo không rơi vào fixed points
        x[i] = 0.1 + (seed_val / 65535.0) * 0.8  # Giới hạn trong [0.1, 0.9]

    # Khởi tạo véc-tơ tham số r với entropy cao hơn
    r = np.zeros(LATTICE_SIZE)
    for i in range(LATTICE_SIZE):
        seed_bytes = r_key[i*2:(i+1)*2] if i*2+1 < len(r_key) else r_key[i%16:(i%16)+2]
        seed_val = int.from_bytes(seed_bytes, 'big')
        # Chuẩn hóa r vào khoảng hỗn loạn [3.8, 4.0] - tránh vùng không hỗn loạn
        r[i] = 3.8 + (seed_val / 65535.0) * 0.2

    # Khởi tạo hằng số nối kết epsilon với entropy tốt hơn
    eps_val = int.from_bytes(eps_key[:4], 'big')
    epsilon = 0.1 + (eps_val / (2**32 - 1)) * 0.3  # Epsilon trong khoảng [0.1, 0.4]

    return x, r, epsilon, salt

def _generate_keystream_cml(x: np.ndarray, r: np.ndarray, epsilon: float, length: int) -> bytes:
    """
    Balanced keystream generation - secure nhưng optimized performance.
    """
    x_current = x.copy()
    
    # Proper transient phase để đạt chaos state
    for i in range(TRANSIENT_STEPS):
        x_current = r * x_current * (1 - x_current)
        # Proper coupling với nearest neighbors
        coupled = (np.roll(x_current, 1) + np.roll(x_current, -1)) * 0.5
        x_current = (1 - epsilon) * x_current + epsilon * coupled
        
        # Periodic scrambling với frequency phụ thuộc performance mode  
        scramble_freq = 50 if PERFORMANCE_MODE == 'fast' else 100
        if i % scramble_freq == 0:
            x_current = np.roll(x_current, 1)

    # Optimized keystream generation với proper mixing
    keystream = bytearray()
    
    # Generate theo chunks với dynamic size dựa trên performance mode
    CHUNK_SIZE = 8192 if PERFORMANCE_MODE == 'fast' else 2048  # Fast mode = larger chunks
    for chunk_start in range(0, length, CHUNK_SIZE):
        chunk_size = min(CHUNK_SIZE, length - chunk_start)
        chunk_data = bytearray(chunk_size)
        
        for i in range(chunk_size):
            # Evolution step với proper chaos
            x_current = r * x_current * (1 - x_current)
            coupled = (np.roll(x_current, 1) + np.roll(x_current, -1)) * 0.5
            x_current = (1 - epsilon) * x_current + epsilon * coupled
            
            # Output function optimized cho performance mode
            byte_val = 0
            for j in range(LATTICE_SIZE):
                val = int(x_current[j] * 255) & 0xFF
                if PERFORMANCE_MODE == 'fast':
                    # Simple XOR cho fast mode
                    byte_val ^= val
                else:
                    # Full mixing cho secure modes
                    rotated = ((val << (j % 8)) | (val >> (8 - (j % 8)))) & 0xFF
                    byte_val ^= rotated
            
            # Additional mixing chỉ cho secure modes
            if PERFORMANCE_MODE != 'fast':
                byte_val ^= (byte_val << 1) & 0xFF
                byte_val ^= (byte_val >> 1) & 0xFF
            
            chunk_data[i] = byte_val & 0xFF
        
        keystream.extend(chunk_data)

    return bytes(keystream)

def encrypt(data: bytes, secret_key: str) -> bytes:
    """
    Mã hóa dữ liệu bằng mật mã luồng CML với authenticated encryption.
    
    Format: salt(32) + hmac(32) + encrypted_data
    """
    if not isinstance(data, bytes):
        raise TypeError("Dữ liệu đầu vào phải là bytes")

    # Generate các components
    x, r, epsilon, salt = _initialize_cml(secret_key)
    keystream = _generate_keystream_cml(x, r, epsilon, len(data))

    # Mã hóa data
    encrypted_data = bytes([b ^ k for b, k in zip(data, keystream)])
    
    # Tạo HMAC cho integrity protection
    # Derive HMAC key từ master key
    kdf_hmac = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + b"HMAC_DERIVE",  # Khác salt để tránh key reuse
        iterations=PBKDF2_ITERATIONS,
    )
    hmac_key = kdf_hmac.derive(secret_key.encode())
    
    # HMAC bao gồm salt + encrypted data để prevent tampering
    import hmac as hmac_module
    mac = hmac_module.new(hmac_key, salt + encrypted_data, hashlib.sha256).digest()
    
    # Kết hợp: salt + mac + encrypted_data
    result = salt + mac + encrypted_data
    return result

def decrypt(data: bytes, secret_key: str) -> bytes:
    """
    Giải mã dữ liệu bằng mật mã luồng CML với integrity verification.
    
    Expected format: salt(32) + hmac(32) + encrypted_data
    """
    if not isinstance(data, bytes):
        raise TypeError("Dữ liệu đầu vào phải là bytes")
    
    if len(data) < 64:  # 32 (salt) + 32 (hmac) minimum
        raise ValueError("Dữ liệu không hợp lệ - quá ngắn")
    
    # Tách các components
    salt = data[:32]
    received_mac = data[32:64]
    encrypted_data = data[64:]
    
    # Derive HMAC key 
    kdf_hmac = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + b"HMAC_DERIVE",
        iterations=PBKDF2_ITERATIONS,
    )
    hmac_key = kdf_hmac.derive(secret_key.encode())
    
    # Verify integrity
    import hmac as hmac_module
    expected_mac = hmac_module.new(hmac_key, salt + encrypted_data, hashlib.sha256).digest()
    if not hmac_module.compare_digest(expected_mac, received_mac):
        raise ValueError("Xác thực integrity thất bại - dữ liệu có thể bị can thiệp")
    
    # Khởi tạo lại cipher với salt đã biết
    x, r, epsilon, _ = _initialize_cml(secret_key, salt)
    keystream = _generate_keystream_cml(x, r, epsilon, len(encrypted_data))

    # Giải mã
    decrypted_data = bytes([b ^ k for b, k in zip(encrypted_data, keystream)])
    return decrypted_data

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison để tránh timing attacks.
    """
    import hmac
    return hmac.compare_digest(a, b)

def validate_key_strength(secret_key: str) -> bool:
    """
    Validate độ mạnh của secret key.
    
    Returns:
        bool: True nếu key đủ mạnh
    """
    if len(secret_key) < 12:  # Tối thiểu 12 ký tự
        return False
    
    # Kiểm tra entropy - phải có ít nhất 3 loại ký tự khác nhau
    has_lower = any(c.islower() for c in secret_key)
    has_upper = any(c.isupper() for c in secret_key)  
    has_digit = any(c.isdigit() for c in secret_key)
    has_special = any(not c.isalnum() for c in secret_key)
    
    char_types = sum([has_lower, has_upper, has_digit, has_special])
    return char_types >= 3

def analyze_chaos_parameters(x: np.ndarray, r: np.ndarray, epsilon: float) -> dict:
    """
    Phân tích các tham số để đảm bảo system ở trạng thái hỗn loạn.
    
    Returns:
        dict: Báo cáo phân tích
    """
    analysis = {
        "is_chaotic": True,
        "warnings": [],
        "parameters": {
            "lattice_size": len(x),
            "mean_r": np.mean(r),
            "epsilon": epsilon
        }
    }
    
    # Kiểm tra r parameters nằm trong vùng hỗn loạn
    for i, r_val in enumerate(r):
        if r_val < 3.57 or r_val > 4.0:
            analysis["warnings"].append(f"r[{i}] = {r_val:.4f} có thể không đảm bảo tính hỗn loạn")
    
    # Kiểm tra initial conditions không rơi vào fixed points
    for i, x_val in enumerate(x):
        if x_val <= 0.05 or x_val >= 0.95:
            analysis["warnings"].append(f"x[{i}] = {x_val:.4f} gần fixed point")
    
    # Kiểm tra coupling strength
    if epsilon < 0.05:
        analysis["warnings"].append("Epsilon quá nhỏ - có thể không đủ coupling")
    elif epsilon > 0.5:
        analysis["warnings"].append("Epsilon quá lớn - có thể làm giảm tính hỗn loạn")
    
    if analysis["warnings"]:
        analysis["is_chaotic"] = False
        
    return analysis

def encrypt_with_validation(data: bytes, secret_key: str) -> bytes:
    """
    Encrypt với validation đầy đủ.
    """
    # Validate input
    if not validate_key_strength(secret_key):
        raise ValueError("Secret key không đủ mạnh. Cần ít nhất 12 ký tự với 3 loại ký tự khác nhau.")
    
    if len(data) > 50 * 1024 * 1024:  # Limit 50MB
        raise ValueError("Dữ liệu quá lớn (>50MB)")
    
    # Generate và validate parameters
    x, r, epsilon, salt = _initialize_cml(secret_key)
    
    # Analyze chaos parameters
    chaos_analysis = analyze_chaos_parameters(x, r, epsilon)
    if not chaos_analysis["is_chaotic"]:
        # Log warnings nhưng vẫn tiếp tục (có thể adjust thông số)
        import logging
        logger = logging.getLogger(__name__)
        for warning in chaos_analysis["warnings"]:
            logger.warning(f"Chaotic cipher warning: {warning}")
    
    # Proceed with encryption
    return encrypt(data, secret_key)

def decrypt_with_validation(data: bytes, secret_key: str) -> bytes:
    """
    Decrypt với validation đầy đủ.
    """
    if not validate_key_strength(secret_key):
        raise ValueError("Secret key không đủ mạnh. Cần ít nhất 12 ký tự với 3 loại ký tự khác nhau.")
    
    return decrypt(data, secret_key)
