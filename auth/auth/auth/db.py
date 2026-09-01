# db.py
"""
Database session setup shared across the app (auth, comparison engine, etc).
Works with either SQLite or PostgreSQL via DATABASE_URL.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from models import Base
import models_auth  # noqa: F401  (ensures User table is registered on Base.metadata)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///vcf_drift.db")

engine = create_engine(DATABASE_URL, future=True)
db_session = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))


def init_db():
    Base.metadata.create_all(bind=engine)