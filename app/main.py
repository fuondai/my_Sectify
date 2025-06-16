# app/main.py
import logging
from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
import contextlib

# Configure logging
logging.basicConfig(level=logging.INFO)

from app.db.mongodb_utils import connect_to_mongo, close_mongo_connection, get_database
from app.schemas.user import UserInDB
from typing import Optional
from app.crud import audio as audio_crud
from app.api.v1.dependencies import try_get_current_user
from contextlib import asynccontextmanager
from app.api.v1.api import api_router
from app.core.limiter import limiter
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles startup and shutdown events."""
    # Startup
    app.state.limiter = limiter
    await connect_to_mongo()
    # Start HLS cleanup background task
    from app.core.hls_cleanup import cleanup_loop
    cleanup_task = asyncio.create_task(cleanup_loop())

    try:
        yield  # ----- Application running -----
    finally:
        # Shutdown
        cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await cleanup_task
        await close_mongo_connection()

app = FastAPI(
    title="Sectify - Secure Music Platform",
    description="A platform focused on protecting artists' intellectual property.",
    version="1.0.0",
    lifespan=lifespan,
    exception_handlers={RateLimitExceeded: _rate_limit_exceeded_handler}
)

app.add_middleware(SlowAPIMiddleware)

# Mount static directories and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")

# Include the API router
app.include_router(api_router, prefix="/api/v1")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Displays the home page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def read_dashboard(request: Request, current_user: Optional[UserInDB] = Depends(try_get_current_user)):
    """Displays the user's dashboard. Requires authentication."""
    if not current_user:
        # If not logged in, redirect to the home page or a login page
        return RedirectResponse(url="/")
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": current_user})

@app.get("/discover", response_class=HTMLResponse)
async def read_discover(request: Request):
    """Displays the discover page."""
    return templates.TemplateResponse("discover.html", {"request": request})

@app.get("/account", response_class=HTMLResponse)
async def read_account_settings(request: Request, current_user: Optional[UserInDB] = Depends(try_get_current_user)):
    """Serves the account settings page. Requires authentication."""
    if not current_user:
        return RedirectResponse(url="/")
    return templates.TemplateResponse("account.html", {"request": request, "user": current_user})

@app.get("/play/{track_id}", response_class=HTMLResponse)
async def play_track(
    request: Request, 
    track_id: str, 
    db: AsyncIOMotorClient = Depends(get_database),
    current_user: Optional[UserInDB] = Depends(try_get_current_user)
):
    """Displays the player page, with server-side authorization."""
    try:
        track = await audio_crud.get_track_by_id(db, track_id)
        if not track:
            return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

        # Server-side authorization logic
        is_public = track.get("is_public", False)
        owner_id = track.get("owner_id")

        if not is_public and (not current_user or owner_id != current_user.id):
            # If the track is private and the user is not the owner, show an error page
            return templates.TemplateResponse("unauthorized.html", {"request": request}, status_code=403)

        return templates.TemplateResponse("hls_player.html", {"request": request, "track": track, "user": current_user})
    except Exception as e:
        logging.error(f"Error playing track {track_id}: {e}")
        return templates.TemplateResponse("500.html", {"request": request}, status_code=500)
