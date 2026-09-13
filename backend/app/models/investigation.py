import uuid
from sqlalchemy import Column, String, Text, Integer, Float, ForeignKey, Enum as SAEnum, JSON, Uuid
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin
import enum


class InvestigationStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    ambiguous = "ambiguous"


class Conversation(Base, TimestampMixin):
    __tablename__ = "conversations"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(500), nullable=False, default="New Investigation")
    context_window = Column(JSON, default=list)  # last N turns for LLM context


    user = relationship("User", back_populates="conversations")
    investigations = relationship("Investigation", back_populates="conversation", lazy="dynamic")


class Investigation(Base, TimestampMixin):
    __tablename__ = "investigations"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    conversation_id = Column(Uuid, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)


    nl_query = Column(Text, nullable=False)                  # Original natural-language question
    generated_query = Column(JSON, nullable=True)            # JSON intermediate representation
    elasticsearch_query = Column(JSON, nullable=True)        # Compiled ES DSL
    result_count = Column(Integer, default=0)
    status = Column(SAEnum(InvestigationStatus), default=InvestigationStatus.pending, nullable=False)
    explanation = Column(Text, nullable=True)                # AI-generated explanation
    ai_summary = Column(Text, nullable=True)                 # Brief executive summary

    conversation = relationship("Conversation", back_populates="investigations")
    user = relationship("User", back_populates="investigations")
    iocs = relationship("IOC", back_populates="investigation", lazy="dynamic", cascade="all, delete-orphan")
    mitre_mappings = relationship("MITREMapping", back_populates="investigation", lazy="dynamic", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="investigation", lazy="dynamic", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="investigation", uselist=False)


class IOCType(str, enum.Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    url = "url"
    hash_md5 = "hash_md5"
    hash_sha256 = "hash_sha256"
    username = "username"
    email = "email"
    port = "port"
    filename = "filename"
    user_agent = "user_agent"


class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id = Column(Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(SAEnum(IOCType), nullable=False)
    value = Column(String(1000), nullable=False)
    confidence = Column(Float, default=1.0)
    occurrence_count = Column(Integer, default=1)
    first_seen = Column(String(50), nullable=True)
    last_seen = Column(String(50), nullable=True)

    investigation = relationship("Investigation", back_populates="iocs")


class MITREMapping(Base, TimestampMixin):
    __tablename__ = "mitre_mappings"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id = Column(Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(String(20), nullable=False)        # e.g. T1110
    technique_name = Column(String(255), nullable=False)     # e.g. Brute Force
    tactic = Column(String(100), nullable=False)             # e.g. Credential Access
    sub_technique_id = Column(String(30), nullable=True)     # e.g. T1110.001
    sub_technique_name = Column(String(255), nullable=True)
    confidence = Column(Float, default=0.0)
    evidence_count = Column(Integer, default=0)
    description = Column(Text, nullable=True)

    investigation = relationship("Investigation", back_populates="mitre_mappings")


class Evidence(Base, TimestampMixin):
    __tablename__ = "evidence"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id = Column(Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    log_id = Column(String(100), nullable=True)              # ES document ID
    timestamp = Column(String(50), nullable=True)
    source_ip = Column(String(50), nullable=True)
    destination_ip = Column(String(50), nullable=True)
    username = Column(String(255), nullable=True)
    event_type = Column(String(100), nullable=True)
    event_action = Column(String(100), nullable=True)
    severity = Column(Integer, nullable=True)
    raw_log = Column(JSON, nullable=True)                    # Full normalized log document

    investigation = relationship("Investigation", back_populates="evidence")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id = Column(Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), unique=True, nullable=False)
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(500), nullable=False)
    content_json = Column(JSON, nullable=False)              # Full structured report data
    pdf_path = Column(String(500), nullable=True)
    html_path = Column(String(500), nullable=True)


    investigation = relationship("Investigation", back_populates="report")
    user = relationship("User", back_populates="reports")
