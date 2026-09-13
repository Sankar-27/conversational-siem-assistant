import uuid
from sqlalchemy import Column, String, Boolean, Enum as SAEnum, Uuid
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin
import enum


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)

    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.analyst)
    is_active = Column(Boolean, default=True, nullable=False)

    conversations = relationship("Conversation", back_populates="user", lazy="dynamic")
    investigations = relationship("Investigation", back_populates="user", lazy="dynamic")
    reports = relationship("Report", back_populates="user", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<User {self.email} [{self.role}]>"
