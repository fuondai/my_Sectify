# app/crud/user.py
from motor.motor_asyncio import AsyncIOMotorClient
from app.schemas.user import UserCreate, UserInDB
from app.core.security import get_password_hash

async def get_user_by_email(db: AsyncIOMotorClient, email: str):
    """Finds a user by email."""
    user = await db["users"].find_one({"email": email.lower()})
    return user

async def update_user_totp_info(db: AsyncIOMotorClient, email: str, *, secret: str | None, enabled: bool):
    """Updates TOTP information for a user."""
    update_data = {
        "$set": {
            "totp_secret": secret,
            "is_totp_enabled": enabled
        }
    }
    await db["users"].update_one({"email": email.lower()}, update_data)
    return await get_user_by_email(db, email)

async def create_user(db: AsyncIOMotorClient, user: UserCreate):
    """Creates a new user in the database."""
    hashed_password = get_password_hash(user.password)
    user_in_db = UserInDB(
        email=user.email.lower(),
        name=user.name,
        hashed_password=hashed_password,
        roles=["user", "author"]  # Assign default roles
    )
    await db["users"].insert_one(user_in_db.dict())
    return user_in_db
