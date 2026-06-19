"""
models/all_models.py
Owner: Indra (Layer 4 — Database)
Shared with: Ashish (Layer 3 — Backend)

All enum string values match risk_engine.h exactly — UPPERCASE.
  DecisionType: ALLOW, RESTRICT, MFA_REQUIRED, BLOCK
  RiskLevel:    LOW, MEDIUM, HIGH, CRITICAL
  EventType:    LOGIN, API_CALL, FILE_DOWNLOAD, PASSWORD_CHANGE,
                ADMIN_ACTION, DATA_EXPORT, FAILED_AUTH

sizeof(UserProfile) = 320 bytes, confirmed by ctypes against risk_engine.h:
  user_id                   uint64   offset=0
  login_hour_mean           double   offset=8
  login_hour_variance       double   offset=16
  login_count               uint64   offset=24
  bytes_per_session_mean    double   offset=32
  bytes_per_session_variance double  offset=40
  current_risk_score        float    offset=48
  [4 bytes padding]
  last_seen_unix            int64    offset=56
  bloom_filter[256]         uint8[]  offset=64
  total = 320 bytes

NEVER rename a column without telling Ashish first.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float,
    ForeignKey, Integer, LargeBinary, String, Text,
    ARRAY, Index, text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship


def _now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ── users ────────────────────────────────────────────────────────────────────
class User(Base):
    """
    profile_blob stores Uthkarsh's UserProfile struct as raw bytes (memcpy).
    Maximum 320 bytes — enforced by CHECK constraint in migration 0001.
    NULL means the user has never logged in; the C engine starts a fresh profile.

    Ashish workflow:
      On login:  if profile_blob is not NULL → call re_profile_deserialize()
      After login: call re_profile_serialize() → store the returned bytes here
    """
    __tablename__ = "users"

    id            = Column(UUID(as_uuid=True), primary_key=True,
                           default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    email         = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(Text, nullable=False)           # bcrypt hash, Ashish writes this
    role          = Column(String(20), nullable=False, default="user")
    profile_blob  = Column(LargeBinary(320), nullable=True)  # max 320 = sizeof(UserProfile)
    is_active     = Column(Boolean, nullable=False, default=True)
    mfa_enabled   = Column(Boolean, nullable=False, default=False)
    created_at    = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at    = Column(DateTime(timezone=True), nullable=True)  # set when blob is written

    sessions = relationship("ActiveSession", back_populates="user",
                            cascade="all, delete-orphan")
    devices  = relationship("DeviceRegistry", back_populates="user",
                            cascade="all, delete-orphan")
    alerts   = relationship("Alert", back_populates="user")


# ── active_sessions ──────────────────────────────────────────────────────────
class ActiveSession(Base):
    """
    One row per live authenticated session.
    current_risk_score, current_risk_level, and current_decision are updated
    by Ashish's middleware after every re_evaluate_event() call.

    Values MUST match C enum strings (uppercase):
      current_decision:  ALLOW | RESTRICT | MFA_REQUIRED | BLOCK
      current_risk_level: LOW | MEDIUM | HIGH | CRITICAL
    """
    __tablename__ = "active_sessions"

    id                  = Column(UUID(as_uuid=True), primary_key=True,
                                 default=uuid.uuid4,
                                 server_default=text("gen_random_uuid()"))
    user_id             = Column(UUID(as_uuid=True),
                                 ForeignKey("users.id", ondelete="CASCADE"),
                                 nullable=False, index=True)
    jwt_jti             = Column(String(64), nullable=False, unique=True, index=True)
    device_hash         = Column(String(64), nullable=False)   # SHA256(user-agent + lang)
    ip_hash             = Column(String(64), nullable=False)   # SHA256(raw_ip)
    current_risk_score  = Column(Float, nullable=False, default=0.0)
    current_risk_level  = Column(String(10), nullable=False, default="LOW")    # NEW
    current_decision    = Column(String(15), nullable=False, default="ALLOW")  # FIXED: uppercase
    created_at          = Column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at          = Column(DateTime(timezone=True), nullable=False)
    last_event_at       = Column(DateTime(timezone=True), nullable=True)

    user        = relationship("User", back_populates="sessions")
    risk_events = relationship("RiskEventLog", back_populates="session")


# ── risk_event_log (APPEND-ONLY) ─────────────────────────────────────────────
class RiskEventLog(Base):
    """
    Immutable record of every risk scoring decision.
    APPEND-ONLY: ztrust_app has REVOKE UPDATE, DELETE on this table.
    Belt-and-suspenders: PostgreSQL RULE also converts DELETE/UPDATE to no-ops.

    rule_score: from RiskDecision.rule_score (rule-based component)
    ml_score:   from RiskDecision.ml_score   (isolation forest, NULL until model loaded)
    Final score in C = (rule_score × 0.6) + (ml_score × 0.4)

    feature_vector[6] — exact order from build_feature_vector() in scoring.c:
      [0] tm_hour / 23.0f
      [1] failed_attempts / 10.0f
      [2] device_hash % 1000 / 1000.0f
      [3] geo_hash % 1000 / 1000.0f
      [4] ip_hash % 1000 / 1000.0f
      [5] login_count / 100.0f
    Adnaan reads this column for retraining.

    hmac: Ashish computes HMAC-SHA256 over the canonical string (see verify_hmac.py)
    before INSERT. verify_hmac.py rechecks periodically and writes to tamper_log.
    """
    __tablename__ = "risk_event_log"

    id                = Column(BigInteger, primary_key=True, autoincrement=True)
    session_id        = Column(UUID(as_uuid=True),
                               ForeignKey("active_sessions.id"), nullable=False)
    user_id           = Column(UUID(as_uuid=True),
                               ForeignKey("users.id"), nullable=False)
    # LOGIN | API_CALL | FILE_DOWNLOAD | PASSWORD_CHANGE |
    # ADMIN_ACTION | DATA_EXPORT | FAILED_AUTH
    event_type        = Column(String(20), nullable=False)
    risk_score_before = Column(Float, nullable=False)
    risk_score_after  = Column(Float, nullable=False)
    rule_score        = Column(Float, nullable=False)   # NEW: RiskDecision.rule_score
    ml_score          = Column(Float, nullable=True)    # NULL until model.isof delivered
    # ALLOW | RESTRICT | MFA_REQUIRED | BLOCK
    decision          = Column(String(15), nullable=False)
    # LOW | MEDIUM | HIGH | CRITICAL
    risk_level        = Column(String(10), nullable=False)  # NEW: RiskDecision.risk_level
    feature_vector    = Column(ARRAY(Float), nullable=True)  # 6 elements
    hmac              = Column(String(64), nullable=False)
    created_at        = Column(DateTime(timezone=True), nullable=False,
                               default=_now, index=True)

    session = relationship("ActiveSession", back_populates="risk_events")


# Composite indexes — essential for dashboard WebSocket queries
Index("ix_rel_session_created", RiskEventLog.session_id, RiskEventLog.created_at)
Index("ix_rel_user_created",    RiskEventLog.user_id,    RiskEventLog.created_at)


# ── admin_audit_log (APPEND-ONLY) ────────────────────────────────────────────
class AdminAuditLog(Base):
    """
    Immutable record of every admin action.
    Same REVOKE + RULE enforcement as risk_event_log.
    """
    __tablename__ = "admin_audit_log"

    id                = Column(BigInteger, primary_key=True, autoincrement=True)
    admin_user_id     = Column(UUID(as_uuid=True),
                               ForeignKey("users.id"), nullable=False, index=True)
    # force_mfa | override_session | deactivate_user | change_threshold | reload_model
    action_type       = Column(String(50), nullable=False)
    target_user_id    = Column(UUID(as_uuid=True), nullable=True)
    target_session_id = Column(UUID(as_uuid=True), nullable=True)
    details           = Column(JSONB, nullable=True)  # e.g. {"old_threshold": 0.7}
    created_at        = Column(DateTime(timezone=True), nullable=False, default=_now)


# ── device_registry ──────────────────────────────────────────────────────────
class DeviceRegistry(Base):
    """
    Persistent record of device hashes seen per user.
    The C engine uses its bloom filter for fast in-memory checks;
    this table is the authoritative persistent store for the dashboard.
    """
    __tablename__ = "device_registry"

    id          = Column(UUID(as_uuid=True), primary_key=True,
                         default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    user_id     = Column(UUID(as_uuid=True),
                         ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_hash = Column(String(64), nullable=False)
    is_trusted  = Column(Boolean, nullable=False, default=False)
    first_seen  = Column(DateTime(timezone=True), nullable=False, default=_now)
    last_seen   = Column(DateTime(timezone=True), nullable=False, default=_now)

    user = relationship("User", back_populates="devices")

    __table_args__ = (
        Index("ix_device_registry_user_device", "user_id", "device_hash", unique=True),
    )


# ── alerts ───────────────────────────────────────────────────────────────────
class Alert(Base):
    """
    Triggered anomalies surfaced to the admin dashboard.
    Ashish writes these when the C engine returns high-risk decisions.
    severity must match RiskLevel enum strings: LOW | MEDIUM | HIGH | CRITICAL
    """
    __tablename__ = "alerts"

    id          = Column(UUID(as_uuid=True), primary_key=True,
                         default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    user_id     = Column(UUID(as_uuid=True),
                         ForeignKey("users.id"), nullable=False, index=True)
    session_id  = Column(UUID(as_uuid=True),
                         ForeignKey("active_sessions.id"), nullable=True)
    # high_risk_score | new_device | off_hours | brute_force | data_export
    alert_type  = Column(String(50), nullable=False)
    # LOW | MEDIUM | HIGH | CRITICAL  (matches RiskLevel enum)
    severity    = Column(String(10), nullable=False)
    resolved    = Column(Boolean, nullable=False, default=False, index=True)
    resolved_by = Column(UUID(as_uuid=True), nullable=True)  # admin user_id
    created_at  = Column(DateTime(timezone=True), nullable=False,
                         default=_now, index=True)

    user = relationship("User", back_populates="alerts")


# ── ml_model_versions ────────────────────────────────────────────────────────
class MlModelVersion(Base):
    """
    Tracks every model.isof binary Adnaan produces.
    Only one row has active=TRUE — enforced by trigger trg_single_active_model
    created in migration 0005.

    Adnaan's retraining pipeline just does:
        INSERT INTO ml_model_versions (..., active) VALUES (..., TRUE)
    The trigger flips all other rows to active=FALSE automatically.

    Ashish reads the active row's file_path and passes it to re_engine_reload_model().

    Binary format header (from model.h / model.c):
      Offset 0:  uint32 magic = 0x464F5349
      Offset 4:  uint32 version
      Offset 8:  uint32 tree_count
      Offset 12: uint32 feature_count (must = 6, matches MODEL_FEATURES)
      Offset 16: uint32 data_offset
      Offset 20: uint32 checksum (CRC32 of bytes from offset 32+)
      Offset 24: 8 bytes reserved
      Offset 32+: IsoNode[] array
    """
    __tablename__ = "ml_model_versions"

    id                  = Column(UUID(as_uuid=True), primary_key=True,
                                 default=uuid.uuid4,
                                 server_default=text("gen_random_uuid()"))
    file_path           = Column(Text, nullable=False)
    training_date       = Column(DateTime(timezone=True), nullable=False)
    training_data_size  = Column(Integer, nullable=False)
    false_positive_rate = Column(Float, nullable=False)
    detection_rate      = Column(Float, nullable=False)
    active              = Column(Boolean, nullable=False, default=False)
    created_at          = Column(DateTime(timezone=True), nullable=False, default=_now)