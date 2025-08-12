import os
from fastapi import Header, HTTPException

API_KEY_ENV = "DLP_API_KEY"
DEFAULT_API_KEY = "dev-secret"

def get_api_key(x_api_key: str = Header(None)) -> str:
    expected = os.getenv(API_KEY_ENV, DEFAULT_API_KEY)
    if x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key