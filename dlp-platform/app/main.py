from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import os

from .security import get_api_key
from .storage import init_db, get_session
from .schemas import PolicyCreate, ScanTextRequest, FindingOut, PolicyOut
from .services import policy_service, scan_service

app = FastAPI(title="DLP Platform MVP", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/policies", response_model=PolicyOut)
def create_or_update_policy(payload: PolicyCreate, api_key: str = Depends(get_api_key)):
    return policy_service.create_or_update_policy(payload)

@app.get("/policies", response_model=List[PolicyOut])
def list_policies(api_key: str = Depends(get_api_key)):
    return policy_service.list_policies()

@app.post("/scan/text", response_model=List[FindingOut])
def scan_text(payload: ScanTextRequest, api_key: str = Depends(get_api_key)):
    return scan_service.scan_text(payload)

@app.post("/scan/file", response_model=List[FindingOut])
async def scan_file(policy_name: Optional[str] = None, file: UploadFile = File(...), api_key: str = Depends(get_api_key)):
    content = await file.read()
    return scan_service.scan_bytes(content, policy_name)

@app.get("/findings", response_model=List[FindingOut])
def list_findings(api_key: str = Depends(get_api_key)):
    return scan_service.list_recent_findings(limit=100)