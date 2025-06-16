# app/api/v1/endpoints/users.py
from fastapi import APIRouter, Depends
from app.schemas.user import UserInDB
from app.api.v1.dependencies import get_current_user
from app.crud import user as user_crud
from app.db.mongodb_utils import get_database
from motor.motor_asyncio import AsyncIOMotorClient

router = APIRouter()

@router.get("/me", response_model=UserInDB)
async def read_users_me(current_user: UserInDB = Depends(get_current_user), db: AsyncIOMotorClient = Depends(get_database)):
    """Lấy thông tin của người dùng hiện tại."""
    user = await user_crud.get_user_by_email(db, email=current_user.email)
    return user
