from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text, Float
from sqlalchemy.orm import relationship
from database import Base
import datetime

# 1. Users Model
class User(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True)
    password_hash = Column(String)
    role = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# 2. Assets Model
class Asset(Base):
    __tablename__ = "assets"
    asset_id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False)
    hostname = Column(String)
    owner_id = Column(Integer, ForeignKey("users.user_id"))
    criticality = Column(String, default="Medium")
    last_scan_time = Column(DateTime)

# 3. Scan Jobs Model
class ScanJob(Base):
    __tablename__ = "scan_jobs"
    scan_id = Column(Integer, primary_key=True, index=True)
    targets = Column(String, nullable=False)
    scan_type = Column(String, nullable=False) # Quick, Full
    status = Column(String, default="Queued") # Queued, Running, Completed
    started_at = Column(DateTime)
    finished_at = Column(DateTime)

# 4. Findings (Vulnerabilities) Model
class Finding(Base):
    __tablename__ = "findings"
    finding_id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_jobs.scan_id"))
    asset_id = Column(Integer, ForeignKey("assets.asset_id"))
    title = Column(String, nullable=False)
    severity = Column(String) # High, Medium, Low
    description = Column(Text)
    remediation_steps = Column(Text)