"""Script kiểm thử tự động tính năng Just-In-Time key alias.

Chạy sau khi server Sectify đang chạy cục bộ.
Sử dụng requests để:
1. Đăng ký tài khoản ngẫu nhiên
2. Đăng nhập lấy access_token
3. Upload file j97.mp3 (public)
4. Tải playlist, trích xuất URL key (đã có alias)
5. Gọi key lần 1 (thành công) rồi đợi 70 s
6. Gọi key lần 2 (phải 403 do alias hết hạn)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from pathlib import Path

import requests

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
J97_PATH = Path(__file__).resolve().parent.parent / "j97.mp3"

if not J97_PATH.exists():
    print(f"Không tìm thấy {J97_PATH}")
    sys.exit(1)

session = requests.Session()

print("=== 1. Signup ===")
email = f"demo{uuid.uuid4().hex[:6]}@example.com"
password = "Password123!"
resp = session.post(
    f"{BASE_URL}/api/v1/auth/signup",
    json={"email": email, "name": "Demo", "password": password},
    timeout=30,
)
resp.raise_for_status()
print("Tạo user", email)

print("=== 2. Login ===")
resp = session.post(
    f"{BASE_URL}/api/v1/auth/login",
    data={"username": email, "password": password},
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    timeout=30,
)
resp.raise_for_status()
login_data: dict = resp.json()
if login_data.get("mfa_required"):
    print("Tài khoản yêu cầu 2FA, script không hỗ trợ.")
    sys.exit(1)
access_token = login_data["access_token"]
print("Đăng nhập thành công, token", access_token[:20], "...")

print("=== 3. Upload j97.mp3 ===")
with open(J97_PATH, "rb") as f:
    resp = session.post(
        f"{BASE_URL}/api/v1/audio/upload",
        headers={"Authorization": f"Bearer {access_token}"},
        files={"file": (J97_PATH.name, f, "audio/mpeg")},
        data={"is_public": "true"},
        timeout=120,
    )
resp.raise_for_status()
up = resp.json()
track_id = up["track_id"]
print("Track ID:", track_id)

print("=== 4. Lấy playlist (chờ đến khi sẵn sàng) ===")
for _ in range(40):  # tối đa ~200 s
    try:
        resp = session.get(f"{BASE_URL}/api/v1/stream/playlist/{track_id}", timeout=60)
        if resp.status_code == 200:
            playlist_text = resp.text
            break
        else:
            print("Playlist chưa sẵn sàng, status", resp.status_code)
    except requests.RequestException as exc:
        print("Lỗi khi lấy playlist:", exc)
    time.sleep(5)
else:
    print("Timeout đợi playlist sẵn sàng")
    sys.exit(1)
print("Playlist nhận", len(playlist_text.splitlines()), "dòng")

# Tìm dòng EXT-X-KEY
key_line_match = re.search(r'URI="([^"]+)"', playlist_text)
if not key_line_match:
    print("Không tìm thấy dòng EXT-X-KEY trong playlist!")
    sys.exit(1)
key_path = key_line_match.group(1)
key_url = f"{BASE_URL}{key_path}"
print("Key URL:", key_url)

print("=== 5. Yêu cầu key lần 1 (Range bytes=0-15) ===")
resp = session.get(key_url, headers={"Range": "bytes=0-15"}, timeout=30)
print("Status lần 1:", resp.status_code)
if resp.status_code != 206 and resp.status_code != 200:
    print("Lần 1 thất bại", resp.text)
    sys.exit(1)

print("Ngủ 70 giây để alias hết hạn ...")
time.sleep(70)

print("=== 6. Yêu cầu key lần 2 (sau khi alias hết hạn) ===")
resp2 = session.get(key_url, headers={"Range": "bytes=0-15"}, timeout=30)
print("Status lần 2:", resp2.status_code)
if resp2.status_code == 403:
    print("✅ Test pass: Alias hết hạn và bị chặn (403)")
    sys.exit(0)
else:
    print("❌ Test fail: Expected 403, got", resp2.status_code)
    sys.exit(1)
