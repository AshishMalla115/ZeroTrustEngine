"""
SQLAlchemy ORM models — owned by Indra, shared with Ashish.
sizeof(UserProfile) = 320 bytes confirmed from Uthkarsh.
Never rename columns without telling Ashish — it breaks his queries.
"""

import uuid
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float,
    ForeignKey, Integer, LargeBinary, String, Text,
    ARRAY, Index, text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship

load_dotenv()

def _now():
    return datetime.now(timezone.utc)

class Base(DeclarativeBase):
    pass


# ── users ──────────────────────────────────────────────────────────────────
class User(Base):
    """
    profile_blob: Uthkarsh's serialized UserProfile C struct.
    sizeof(UserProfile) = 320 bytes.
    Ashish reads this before re_evaluate_login, writes after re_profile_serialize.
    NULL means no behavioral history yet — engine starts a fresh profile.
    """
    __tablename__ = "users"

    id            = Column(UUID(as_uuid=True), primary_key=True,
                           default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    email         = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(Text, nullable=False)
    role          = Column(String(20), nullable=False, default="user")
    profile_blob  = Column(LargeBinary(320), nullable=True)   # max 320 bytes
    is_active     = Column(Boolean, nullable=False, default=True)
    mfa_enabled   = Column(Boolean, nullable=False, default=False)
    created_at    = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at    = Column(DateTime(timezone=True), nullable=True)

    sessions = relationship("ActiveSession", back_populates="user", cascade="all, delete-orphan")
    devices  = relationship("DeviceRegistry", back_populates="user", cascade="all, delete-orphan")
    alerts   = relationship("Alert", back_populates="user")


# ── active_sessions ────────────────────────────────────────────────────────
class ActiveSession(Base):
    __tablename__ = "active_sessions"

    id                  = Column(UUID(as_uuid=True), primary_key=True,
                                 default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    user_id             = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                                 nullable=False, index=True)
    jwt_jti             = Column(String(64), nullable=False, unique=True, index=True)
    device_hash         = Column(String(64), nullable=False)
    ip_hash             = Column(String(64), nullable=False)   # SHA256 of raw IP
    current_risk_score  = Column(Float, nullable=False, default=0.0)
    current_decision    = Column(String(20), nullable=False, default="allow")
    created_at          = Column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at          = Column(DateTime(timezone=True), nullable=False)
    last_event_at       = Column(DateTime(timezone=True), nullable=True)

    user        = relationship("User", back_populates="sessions")
    risk_events = relationship("RiskEventLog", back_populates="session")


# ── risk_event_log  (APPEND-ONLY) ──────────────────────────────────────────
class RiskEventLog(Base):
    """
    APPEND-ONLY. ztrust_app has no UPDATE or DELETE on this table.
    feature_vector order (agreed with Adnaan and Uthkarsh):
      [0] hour_of_day/23.0  [1] failed_attempts/10.0  [2] device_hash%1000/1000.0
      [3] geo_hash%1000/1000.0  [4] ip_hash%1000/1000.0  [5] login_count/100.0
    hmac: Ashish computes HMAC-SHA256 before insert. verify_hmac.py checks it.
    """
    __tablename__ = "risk_event_log"

    id                = Column(BigInteger, primary_key=True, autoincrement=True)
    session_id        = Column(UUID(as_uuid=True), ForeignKey("active_sessions.id"),
                               nullable=False, index=True)
    user_id           = Column(UUID(as_uuid=True), ForeignKey("users.id"),
                               nullable=False, index=True)
    event_type        = Column(String(50), nullable=False)
    risk_score_before = Column(Float, nullable=False)
    risk_score_after  = Column(Float, nullable=False)
    decision          = Column(String(20), nullable=False)
    ml_score          = Column(Float, nullable=True)   # NULL until model.isof loaded
    feature_vector    = Column(ARRAY(Float), nullable=True)   # 6 elements
    hmac              = Column(String(64), nullable=False)
    created_at        = Column(DateTime(timezone=True), nullable=False,
                               default=_now, index=True)

    session = relationship("ActiveSession", back_populates="risk_events")

Index("ix_risk_event_log_session_created", RiskEventLog.session_id, RiskEventLog.created_at)
Index("ix_risk_event_log_user_created",    RiskEventLog.user_id,    RiskEventLog.created_at)


# ── admin_audit_log  (APPEND-ONLY) ─────────────────────────────────────────
class AdminAuditLog(Base):
    __tablename__ = "admin_audit_log"

    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    admin_user_id   = Column(UUID(as_uuid=True), ForeignKey("users.id"),
                             nullable=False, index=True)
    action_type     = Column(String(50), nullable=False)
    target_user_id  = Column(UUID(as_uuid=True), nullable=True)
    target_session_id = Column(UUID(as_uuid=True), nullable=True)
    details         = Column(JSONB, nullable=True)
    created_at      = Column(DateTime(timezone=True), nullable=False, default=_now)


# ── device_registry ────────────────────────────────────────────────────────
class DeviceRegistry(Base):
    __tablename__ = "device_registry"

    id           = Column(UUID(as_uuid=True), primary_key=True,
                          default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    user_id      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                          nullable=False)
    device_hash  = Column(String(64), nullable=False)
    is_trusted   = Column(Boolean, nullable=False, default=False)
    first_seen   = Column(DateTime(timezone=True), nullable=False, default=_now)
    last_seen    = Column(DateTime(timezone=True), nullable=False, default=_now)

    user = relationship("User", back_populates="devices")

    __table_args__ = (
        Index("ix_device_registry_user_device", "user_id", "device_hash", unique=True),
    )


# ── alerts ─────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id          = Column(UUID(as_uuid=True), primary_key=True,
                         default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"),
                         nullable=False, index=True)
    session_id  = Column(UUID(as_uuid=True), ForeignKey("active_sessions.id"), nullable=True)
    alert_type  = Column(String(50), nullable=False)
    severity    = Column(String(10), nullable=False)
    resolved    = Column(Boolean, nullable=False, default=False, index=True)
    resolved_by = Column(UUID(as_uuid=True), nullable=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=_now, index=True)

    user = relationship("User", back_populates="alerts")


# ── ml_model_versions ──────────────────────────────────────────────────────
class MlModelVersion(Base):
    """
    Only one row has active=TRUE at a time.
    Enforced by trigger trg_single_active_model (created in migration 0005).
    Adnaan inserts a new row with active=TRUE after each retraining run.
    """
    __tablename__ = "ml_model_versions"

    id                  = Column(UUID(as_uuid=True), primary_key=True,
                                 default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    file_path           = Column(Text, nullable=False)
    training_date       = Column(DateTime(timezone=True), nullable=False)
    training_data_size  = Column(Integer, nullable=False)
    false_positive_rate = Column(Float, nullable=False)
    detection_rate      = Column(Float, nullable=False)
    active              = Column(Boolean, nullable=False, default=False)
    created_at          = Column(DateTime(timezone=True), nullable=False, default=_now)