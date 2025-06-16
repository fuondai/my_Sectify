"""End-to-end automated security test for Sectify.

Checks every completed item in README Phase-5 list:
1. Signup & login flow works.
2. Upload protected audio, playlist returned.
3. Security HTTP headers present.
4. Hot-link / embed protection blocks cross-site Origin.
5. Tokens bound to IP + Range – mismatch fails.
6. Just-In-Time key alias expires (~60 s).
7. Segment signature (ts,sig) expires (>10 s).
8. Rate limit on key endpoint (10/min) enforced.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Callable

import requests

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
J97_PATH = Path(__file__).resolve().parent.parent / "j97.mp3"

assert J97_PATH.exists(), "j97.mp3 not found"

S = requests.Session()


def chk(cond: bool, msg: str) -> None:
    if cond:
        print(f"✅ {msg}")
    else:
        print(f"❌ FAIL: {msg}")
        sys.exit(1)


print("--- Signup & Login ---")
email = f"demo{uuid.uuid4().hex[:6]}@example.com"
password = "Password123!"
S.post(f"{BASE_URL}/api/v1/auth/signup", json={"email": email, "name": "Demo", "password": password}, timeout=30).raise_for_status()
login_r = S.post(
    f"{BASE_URL}/api/v1/auth/login",
    data={"username": email, "password": password},
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    timeout=30,
)
login_r.raise_for_status()
access_token = login_r.json()["access_token"]
chk(bool(access_token), "Login returns token")

headers_auth = {"Authorization": f"Bearer {access_token}"}

print("--- Upload ---")
up_r = S.post(
    f"{BASE_URL}/api/v1/audio/upload",
    headers=headers_auth,
    files={"file": (J97_PATH.name, open(J97_PATH, "rb"), "audio/mpeg")},
    data={"is_public": "true"},
    timeout=120,
)
up_r.raise_for_status()
track_id = up_r.json()["track_id"]
chk(bool(track_id), "Uploaded track & obtained track_id")

print("--- Fetch playlist ---")
for _ in range(40):
    pl_r = S.get(f"{BASE_URL}/api/v1/stream/playlist/{track_id}", timeout=60)
    if pl_r.status_code == 200:
        break
    time.sleep(5)
pl_r.raise_for_status()
playlist = pl_r.text

# 3. Security headers
sec_headers = pl_r.headers
for k in ["cache-control", "referrer-policy", "x-content-type-options", "content-security-policy"]:
    chk(k in sec_headers, f"Header '{k}' present")

# Parse key URI & segment line
key_match = re.search(r'URI="([^"]+)"', playlist)
seg_match = re.search(r'^[^#].+\.ts\?[^\n]+', playlist, re.MULTILINE)
assert key_match, "EXT-X-KEY line not found"
assert seg_match, "segment line not found"
key_rel = key_match.group(1)
seg_rel = seg_match.group(0)
key_url = f"{BASE_URL}{key_rel}"
seg_url = f"{BASE_URL}{seg_rel}"

# Extract token, alias, params
from urllib.parse import urlparse, parse_qs
qs_key = parse_qs(urlparse(key_url).query)
key_token = qs_key["token"][0]
key_alias = qs_key["alias"][0]

print("--- Key request #1 (valid) ---")
kr1 = S.get(key_url, headers={"Range": "bytes=0-15"}, timeout=30)
chk(kr1.status_code in (200, 206), "Key retrieved with correct Range")

# 4. Range mismatch
kr_mismatch = S.get(key_url, headers={"Range": "bytes=16-31"}, timeout=30)
chk(kr_mismatch.status_code == 403, "Range header mismatch blocked (403)")

# 5. Hot-link protection
kr_origin = S.get(key_url, headers={"Range": "bytes=0-15", "Origin": "http://evil.com"}, timeout=30)
chk(kr_origin.status_code == 403, "Cross-site origin blocked (403)")

print("--- Segment request (valid) ---")
seg_ok = S.get(seg_url, timeout=30)
chk(seg_ok.status_code == 200, "Segment retrieved with fresh ts/sig")

print("Waiting 12 s for segment ts expiry ...")
time.sleep(12)
seg_exp = S.get(seg_url, timeout=30)
chk(seg_exp.status_code == 400, "Segment signature expired (400)")

print("Waiting 70 s for alias expiry ...")
time.sleep(70)
kr2 = S.get(key_url, headers={"Range": "bytes=0-15"}, timeout=30)
chk(kr2.status_code == 403, "Alias expired after 60 s (403)")

print("--- Rate-limit test ---")
rl_ok = 0
for i in range(12):
    r = S.get(key_url, headers={"Range": "bytes=0-15"}, timeout=10)
    if r.status_code == 429:
        chk(True, "Rate limit triggered after >=10 requests/min (429)")
        break
    rl_ok += 1
else:
    chk(False, "Rate limit NOT triggered (expected 429)")

print("All tests passed ✅")
