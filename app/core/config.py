# app/core/config.py
import os
from dotenv import load_dotenv

load_dotenv()

# Database
MONGO_DATABASE_URL = os.getenv("MONGO_DATABASE_URL")
MONGO_DATABASE_NAME = os.getenv("MONGO_DATABASE_NAME")


# Security
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
