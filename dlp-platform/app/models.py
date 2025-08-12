from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .storage import Base

class Policy(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    enabled = Column(Boolean, default=True)
    detectors = Column(Text, default="[]")  # JSON array
    min_severity = Column(String(20), default="low")
    actions = Column(Text, default="[]")  # JSON array
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    policy_name = Column(String(100), index=True)
    source_kind = Column(String(20))  # text|file
    created_at = Column(DateTime, default=datetime.utcnow)
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    detector = Column(String(50), index=True)
    match = Column(Text)
    start = Column(Integer)
    end = Column(Integer)
    severity = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)
    scan = relationship("Scan", back_populates="findings")