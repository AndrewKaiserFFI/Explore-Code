# models_auth.py
"""
User model for authentication / self-signup.
Extends the models.py Base from the comparison engine so it shares the
same SQLAlchemy metadata/session and database (SQLite or PostgreSQL).
"""

from datetime import datetime
from enum import Enum

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum as SAEnum
from flask_login import UserMixin

from models import Base  # shared declarative base from comparison engine models


class UserRole(str, Enum):
    ADMIN = "admin"
    VIEWER = "viewer"


class User(Base, UserMixin):
    """
    Represents an application user who can log in to view drift reports,
    remediation plans, breaking changes, and remediation history.

    Self-signup creates VIEWER-role accounts by default. Promote to ADMIN
    manually (e.g. via DB or an admin-only route) as needed.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active_account = Column(Boolean, default=True)  # allows disabling accounts
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    # Flask-Login required interface
    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return self.is_active_account

    def is_admin(self):
        return self.role == UserRole.ADMIN