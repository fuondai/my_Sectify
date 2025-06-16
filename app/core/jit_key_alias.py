"""Just-In-Time key alias store.

Provides short-lived alias IDs mapped to the actual AES-128 key files so that
each playlist contains a unique, expiring key reference. This limits the window
of opportunity for attackers to reuse a leaked key URL.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict

from fastapi import HTTPException, status

_ALIAS_STORE: Dict[str, dict] = {}


def _cleanup_expired() -> None:
    """Remove expired aliases from the in-memory store."""
    now = datetime.now(timezone.utc)
    for alias in list(_ALIAS_STORE):
        if _ALIAS_STORE[alias]["expires"] < now:
            _ALIAS_STORE.pop(alias, None)


def create_key_alias(track_id: str, key_path: str, ttl_seconds: int = 60) -> str:
    """Create a new alias for `key_path` valid for *ttl_seconds* seconds."""
    _cleanup_expired()
    alias = uuid.uuid4().hex
    _ALIAS_STORE[alias] = {
        "track_id": track_id,
        "key_path": key_path,
        "expires": datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
    }
    return alias


def resolve_key_alias(alias: str, track_id: str) -> str:
    """Return the key path if alias is valid; raise 403 otherwise."""
    _cleanup_expired()
    info = _ALIAS_STORE.get(alias)
    if not info or info["track_id"] != track_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired key alias")
    return info["key_path"]
