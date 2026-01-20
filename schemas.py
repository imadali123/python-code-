from pydantic import BaseModel
from datetime import datetime
from typing import Optional

# 1. Base Schema for creating a Scan
class ScanJobCreate(BaseModel):
    targets: str  # e.g., "192.168.1.1"
    scan_type: str # e.g., "Quick" or "Full"

# 2. Schema for reading a Scan (what the API returns)
class ScanJobResponse(ScanJobCreate):
    scan_id: int
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# 3. Schema for reading a Finding (Vulnerability)
class FindingResponse(BaseModel):
    title: str
    severity: str
    description: Optional[str] = None
    
    class Config:
        from_attributes = True