import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DB_URL_ENV = "DLP_DB_URL"
DEFAULT_DB_URL = "sqlite:///./dlp.db"

database_url = os.getenv(DB_URL_ENV, DEFAULT_DB_URL)
engine = create_engine(database_url, connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

def init_db():
    from . import models  # noqa: F401 ensure models are imported
    Base.metadata.create_all(bind=engine)

# Dependency

def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()