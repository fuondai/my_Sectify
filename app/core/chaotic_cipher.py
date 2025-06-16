# -*- coding: utf-8 -*-
"""
Triển khai Mật mã luồng hỗn loạn sử dụng Mạng Lưới Sơ Đồ Nối Kết (Coupled Map Lattice - CML).

Thuật toán này sử dụng một mạng lưới các sơ đồ logistic nối kết với nhau để tạo ra
một hệ thống hỗn loạn không-thời gian phức tạp, mang lại tính bảo mật cao hơn
so với một sơ đồ logistic đơn lẻ.
"""

import hashlib
import numpy as np

LATTICE_SIZE = 16  # Kích thước của mạng lưới (số lượng sơ đồ logistic)
TRANSIENT_STEPS = 2000 # Số bước bỏ qua để hệ thống đạt trạng thái hỗn loạn

def _initialize_cml(secret_key: str) -> tuple[np.ndarray, np.ndarray, float]:
    """
    Khởi tạo trạng thái ban đầu, tham số và hằng số nối kết cho CML từ khóa bí mật.

    Sử dụng SHA-512 để có đủ entropy cho tất cả các tham số.
    """
    # Sử dụng SHA-512 để có một hạt giống 512-bit (64 bytes)
    hashed_key = hashlib.sha512(secret_key.encode()).digest()

    # Khởi tạo véc-tơ trạng thái ban đầu x
    x = np.zeros(LATTICE_SIZE)
    for i in range(LATTICE_SIZE):
        # Mỗi trạng thái lấy 2 bytes từ hash
        seed_val = int.from_bytes(hashed_key[i*2 : (i+1)*2], 'big')
        x[i] = seed_val / 65535.0  # Chuẩn hóa về [0, 1]

    # Khởi tạo véc-tơ tham số r
    r = np.zeros(LATTICE_SIZE)
    for i in range(LATTICE_SIZE):
        # Mỗi tham số r lấy 2 bytes tiếp theo
        seed_val = int.from_bytes(hashed_key[32 + i*2 : 32 + (i+1)*2], 'big')
        # Chuẩn hóa r vào khoảng hỗn loạn [3.57, 4.0]
        r[i] = 3.57 + (seed_val / 65535.0) * 0.43

    # Khởi tạo hằng số nối kết epsilon
    seed_eps = int.from_bytes(hashed_key[60:62], 'big')
    epsilon = (seed_eps / 65535.0) * 0.5  # Epsilon trong khoảng [0, 0.5]

    return x, r, epsilon

def _generate_keystream_cml(x: np.ndarray, r: np.ndarray, epsilon: float, length: int) -> bytes:
    """
    Tạo ra một chuỗi khóa (keystream) từ CML.
    """
    keystream = bytearray()
    x_current = np.copy(x)

    # Hàm logistic vector hóa
    logistic_map = lambda x_val, r_val: r_val * x_val * (1 - x_val)

    # Bỏ qua các bước chuyển tiếp
    for _ in range(TRANSIENT_STEPS):
        fx = logistic_map(x_current, r)
        # Áp dụng nối kết (với điều kiện biên tuần hoàn)
        coupled_term = (np.roll(fx, 1) + np.roll(fx, -1)) / 2
        x_current = (1 - epsilon) * fx + epsilon * coupled_term

    # Tạo chuỗi khóa
    for _ in range(length):
        fx = logistic_map(x_current, r)
        coupled_term = (np.roll(fx, 1) + np.roll(fx, -1)) / 2
        x_current = (1 - epsilon) * fx + epsilon * coupled_term
        
        # Lấy một giá trị từ mạng lưới và chuyển đổi thành byte
        # XOR tất cả các giá trị trạng thái lại với nhau để tăng tính khuếch tán
        xor_val = 0
        for val in x_current:
            xor_val ^= int(val * 255)
        keystream.append(xor_val)

    return bytes(keystream)

def encrypt(data: bytes, secret_key: str) -> bytes:
    """
    Mã hóa dữ liệu bằng mật mã luồng CML.
    """
    if not isinstance(data, bytes):
        raise TypeError("Dữ liệu đầu vào phải là bytes")

    x, r, epsilon = _initialize_cml(secret_key)
    keystream = _generate_keystream_cml(x, r, epsilon, len(data))

    encrypted_data = bytes([b ^ k for b, k in zip(data, keystream)])
    return encrypted_data

def decrypt(data: bytes, secret_key: str) -> bytes:
    """
    Giải mã dữ liệu bằng mật mã luồng CML.
    """
    # Quá trình giải mã giống hệt mã hóa cho mật mã luồng XOR
    return encrypt(data, secret_key)
