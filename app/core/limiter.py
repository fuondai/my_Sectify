# app/core/limiter.py
from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize the Limiter object
# `key_func=get_remote_address` will use the client's IP address as the key for tracking requests
limiter = Limiter(key_func=get_remote_address)
