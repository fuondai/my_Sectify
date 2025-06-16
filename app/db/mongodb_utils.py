# app/db/mongodb_utils.py
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import MONGO_DATABASE_URL, MONGO_DATABASE_NAME

class DataBase:
    client: AsyncIOMotorClient = None

db = DataBase()

async def get_database() -> AsyncIOMotorClient:
    return db.client[MONGO_DATABASE_NAME]

async def connect_to_mongo():
    print("Connecting to MongoDB...")
    db.client = AsyncIOMotorClient(MONGO_DATABASE_URL)
    print("Successfully connected to MongoDB!")

async def close_mongo_connection():
    print("Closing MongoDB connection...")
    db.client.close()
    print("MongoDB connection closed.")
