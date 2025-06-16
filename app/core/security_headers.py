"""Middleware to append security-related HTTP headers.

Các header giúp giảm nguy cơ tấn công XSS, click-jacking, cache-leak.
"""
from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Append security headers to every response."""

    async def dispatch(self, request, call_next):  # type: ignore[override]
        response = await call_next(request)

        headers = MutableHeaders(response.headers)
        # Không lưu cache ở client / proxy
        headers["Cache-Control"] = "no-store, private"
        # Ngăn chặn truyền referrer
        headers["Referrer-Policy"] = "no-referrer"
        # Ngăn chặn MIME sniff
        headers["X-Content-Type-Options"] = "nosniff"
        # Cơ bản chặn XSS, plugin nguy hiểm
        headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "media-src 'self' blob:; object-src 'none';"
        )
        return response
