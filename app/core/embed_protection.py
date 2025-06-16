"""Origin / embed protection helper.
Blocks hot-linking from external sites by validating headers.
"""
from __future__ import annotations

from urllib.parse import urlparse

from fastapi import Request, HTTPException, status

# Allowed hosts that can embed content. For production, read from env.
ALLOWED_EMBED_HOSTS: set[str] = {"127.0.0.1", "localhost"}


async def check_embed_source(request: Request) -> None:
    """Raise 403 if request originates from disallowed site."""
    sec_site = request.headers.get("sec-fetch-site", "").lower()
    if sec_site and sec_site not in ("same-origin", "same-site", "none"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-site request blocked")

    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin:
        host = urlparse(origin).hostname or ""
        allowed_hosts = ALLOWED_EMBED_HOSTS.union({request.url.hostname})
        if host and host not in allowed_hosts:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin not allowed")
