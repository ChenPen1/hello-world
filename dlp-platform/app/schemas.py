from pydantic import BaseModel, Field
from typing import List, Optional

class PolicyCreate(BaseModel):
    name: str
    enabled: bool = True
    detectors: List[str] = Field(default_factory=list)
    min_severity: str = "low"
    actions: List[str] = Field(default_factory=list)

class PolicyOut(PolicyCreate):
    id: int
    class Config:
        from_attributes = True

class ScanTextRequest(BaseModel):
    text: str
    policy_name: Optional[str] = None

class FindingOut(BaseModel):
    id: int
    detector: str
    match: str
    start: int
    end: int
    severity: str
    class Config:
        from_attributes = True