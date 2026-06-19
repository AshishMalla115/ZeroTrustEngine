"""
tests/test_schema.py
Owner: Indra (Layer 4 — Database)

Integration tests against the real local PostgreSQL database.
Each test is wrapped in a transaction that rolls back — no permanent data written.

Run with:
    python -m pytest tests/ -v

Requirements:
  - venv must be active
  - alembic upgrade head must have been run
  - PostgreSQL must be running
"""

import os
import sys
import uuid
import pytest
from datetime import datetime, timezone, timedelta

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

import sqlalchemy as sa
from sqlalchemy.orm import Session

from models.all_models import (
    User, ActiveSession, RiskEventLog, AdminAuditLog,
    DeviceRegistry, Alert, MlModelVersion
)

# ── Fixtures ─────────────────────────────────────────────────────────────────

DB_URL = (
    f"postgresql+psycopg2://"
    f"{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}"
    f"@{os.environ['DB_HOST']}:{os.environ['DB_PORT']}"
    f"/{os.environ['DB_NAME']}"
)


@pytest.fixture(scope="module")
def engine():
    return sa.create_engine(DB_URL)


@pytest.fixture
def sess(engine):
    """
    Each test gets a rolled-back transaction — no data persists.
    This lets us test constraints without cleaning up after every test.
    """
    with engine.connect() as conn:
        txn = conn.begin()
        s = Session(bind=conn)
        yield s
        s.close()
        txn.rollback()


@pytest.fixture
def user(sess):
    u = User(
        email=f"test_{uuid.uuid4().hex[:8]}@zt.local",
        password_hash="$2b$12$placeholder",
        role="user"
    )
    sess.add(u)
    sess.flush()
    return u


@pytest.fixture
def admin_user(sess):
    u = User(
        email=f"admin_{uuid.uuid4().hex[:8]}@zt.local",
        password_hash="$2b$12$placeholder",
        role="admin"
    )
    sess.add(u)
    sess.flush()
    return u


@pytest.fixture
def active_session(sess, user):
    s = ActiveSession(
        user_id=user.id,
        jwt_jti=uuid.uuid4().hex,
        device_hash="a" * 64,
        ip_hash="b" * 64,
        current_risk_score=0.1,
        current_risk_level="LOW",
        current_decision="ALLOW",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    sess.add(s)
    sess.flush()
    return s


# ── Users table tests ─────────────────────────────────────────────────────────

class TestUsersTable:

    def test_create_user_defaults(self, sess, user):
        assert user.id is not None
        assert user.role == "user"
        assert user.is_active is True
        assert user.mfa_enabled is False
        assert user.profile_blob is None

    def test_email_unique_constraint(self, sess, user):
        duplicate = User(
            email=user.email,
            password_hash="hash",
            role="user"
        )
        sess.add(duplicate)
        with pytest.raises(Exception):  # IntegrityError (unique violation)
            sess.flush()

    def test_role_check_constraint_valid(self, sess):
        for role in ("user", "admin", "readonly"):
            u = User(
                email=f"r_{role}_{uuid.uuid4().hex[:4]}@zt.local",
                password_hash="h",
                role=role
            )
            sess.add(u)
            sess.flush()  # must not raise

    def test_role_check_constraint_invalid(self, sess):
        u = User(
            email=f"bad_{uuid.uuid4().hex[:8]}@zt.local",
            password_hash="h",
            role="superuser"  # not in CHECK list
        )
        sess.add(u)
        with pytest.raises(Exception):
            sess.flush()

    def test_profile_blob_accepts_320_bytes(self, sess, user):
        """sizeof(UserProfile) = 320 — exact match must be accepted."""
        user.profile_blob = b"\x00" * 320
        sess.flush()  # must not raise

    def test_profile_blob_rejects_321_bytes(self, sess, user):
        """321 bytes must be rejected by the CHECK constraint."""
        user.profile_blob = b"\x00" * 321
        with pytest.raises(Exception):
            sess.flush()

    def test_profile_blob_null_accepted(self, sess, user):
        """NULL is valid — means the user has no behavioral history yet."""
        assert user.profile_blob is None  # default
        sess.flush()  # must not raise


# ── active_sessions table tests ───────────────────────────────────────────────

class TestActiveSessionsTable:

    def test_create_session_defaults(self, sess, active_session):
        assert active_session.id is not None
        assert active_session.current_risk_score == 0.1
        assert active_session.current_decision == "ALLOW"
        assert active_session.current_risk_level == "LOW"

    def test_decision_check_valid_values(self, sess, active_session):
        for dec in ("ALLOW", "RESTRICT", "MFA_REQUIRED", "BLOCK"):
            active_session.current_decision = dec
            sess.flush()  # each must succeed

    def test_decision_check_rejects_lowercase(self, sess, active_session):
        """
        CRITICAL: the old model had default="allow" (lowercase).
        The CHECK constraint now requires uppercase C enum strings.
        """
        active_session.current_decision = "allow"
        with pytest.raises(Exception):
            sess.flush()

    def test_decision_check_rejects_invalid(self, sess, active_session):
        active_session.current_decision = "PERMIT"
        with pytest.raises(Exception):
            sess.flush()

    def test_risk_level_check_valid(self, sess, active_session):
        for lvl in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            active_session.current_risk_level = lvl
            sess.flush()

    def test_risk_level_check_invalid(self, sess, active_session):
        active_session.current_risk_level = "EXTREME"
        with pytest.raises(Exception):
            sess.flush()

    def test_risk_score_range_below_zero(self, sess, active_session):
        active_session.current_risk_score = -0.1
        with pytest.raises(Exception):
            sess.flush()

    def test_risk_score_range_above_one(self, sess, active_session):
        active_session.current_risk_score = 1.01
        with pytest.raises(Exception):
            sess.flush()

    def test_cascade_delete_on_user_delete(self, sess, user, active_session):
        session_id = active_session.id
        sess.delete(user)
        sess.flush()
        assert sess.get(ActiveSession, session_id) is None


# ── risk_event_log table tests ────────────────────────────────────────────────

class TestRiskEventLog:

    def test_insert_valid_event(self, sess, active_session, user):
        event = RiskEventLog(
            session_id=active_session.id,
            user_id=user.id,
            event_type="LOGIN",
            risk_score_before=0.0,
            risk_score_after=0.15,
            rule_score=0.15,
            decision="ALLOW",
            risk_level="LOW",
            feature_vector=[0.5, 0.0, 0.3, 0.2, 0.4, 0.05],
            hmac="a" * 64
        )
        sess.add(event)
        sess.flush()
        assert event.id is not None

    def test_requires_rule_score_column(self, sess, active_session, user):
        """rule_score is a new required column from RiskDecision.rule_score."""
        event = RiskEventLog(
            session_id=active_session.id,
            user_id=user.id,
            event_type="LOGIN",
            risk_score_before=0.0,
            risk_score_after=0.2,
            rule_score=0.2,   # must be present
            decision="ALLOW",
            risk_level="LOW",
            hmac="b" * 64
        )
        sess.add(event)
        sess.flush()
        assert event.rule_score == 0.2

    def test_requires_risk_level_column(self, sess, active_session, user):
        """risk_level is a new required column from RiskDecision.risk_level."""
        event = RiskEventLog(
            session_id=active_session.id,
            user_id=user.id,
            event_type="API_CALL",
            risk_score_before=0.1,
            risk_score_after=0.1,
            rule_score=0.1,
            decision="ALLOW",
            risk_level="LOW",   # must be present
            hmac="c" * 64
        )
        sess.add(event)
        sess.flush()
        assert event.risk_level == "LOW"

    def test_event_type_check_valid(self, sess, active_session, user):
        for et in ("LOGIN", "API_CALL", "FILE_DOWNLOAD", "PASSWORD_CHANGE",
                   "ADMIN_ACTION", "DATA_EXPORT", "FAILED_AUTH"):
            e = RiskEventLog(
                session_id=active_session.id, user_id=user.id,
                event_type=et, risk_score_before=0.0, risk_score_after=0.1,
                rule_score=0.1, decision="ALLOW", risk_level="LOW", hmac="d" * 64
            )
            sess.add(e)
            sess.flush()

    def test_event_type_check_invalid(self, sess, active_session, user):
        e = RiskEventLog(
            session_id=active_session.id, user_id=user.id,
            event_type="BULK_DOWNLOAD",  # not in EventType enum
            risk_score_before=0.0, risk_score_after=0.5,
            rule_score=0.5, decision="RESTRICT", risk_level="HIGH", hmac="e" * 64
        )
        sess.add(e)
        with pytest.raises(Exception):
            sess.flush()

    def test_feature_vector_must_be_6_elements(self, sess, active_session, user):
        e = RiskEventLog(
            session_id=active_session.id, user_id=user.id,
            event_type="LOGIN",
            risk_score_before=0.0, risk_score_after=0.1,
            rule_score=0.1, decision="ALLOW", risk_level="LOW",
            feature_vector=[0.1, 0.2, 0.3],   # only 3 — invalid
            hmac="f" * 64
        )
        sess.add(e)
        with pytest.raises(Exception):
            sess.flush()

    def test_feature_vector_null_allowed(self, sess, active_session, user):
        """feature_vector is NULL for non-LOGIN events."""
        e = RiskEventLog(
            session_id=active_session.id, user_id=user.id,
            event_type="API_CALL",
            risk_score_before=0.0, risk_score_after=0.05,
            rule_score=0.05, decision="ALLOW", risk_level="LOW",
            feature_vector=None,  # OK for non-login events
            hmac="g" * 64
        )
        sess.add(e)
        sess.flush()


# ── ml_model_versions trigger tests ──────────────────────────────────────────

class TestMlModelVersionTrigger:

    def test_single_active_model_enforced(self, sess):
        """
        When model2 is inserted with active=TRUE, the trigger must flip
        model1.active to FALSE automatically.
        """
        model1 = MlModelVersion(
            file_path="/models/v1/model.isof",
            training_date=datetime.now(timezone.utc),
            training_data_size=10000,
            false_positive_rate=0.02,
            detection_rate=0.95,
            active=True
        )
        sess.add(model1)
        sess.flush()
        assert model1.active is True

        model2 = MlModelVersion(
            file_path="/models/v2/model.isof",
            training_date=datetime.now(timezone.utc),
            training_data_size=15000,
            false_positive_rate=0.018,
            detection_rate=0.97,
            active=True
        )
        sess.add(model2)
        sess.flush()

        # Trigger must have flipped model1 to inactive
        sess.refresh(model1)
        assert model2.active is True, "New model must be active"
        assert model1.active is False, "Trigger must deactivate previous model"

    def test_inactive_model_unaffected(self, sess):
        """Inserting an inactive model must not affect other rows."""
        model1 = MlModelVersion(
            file_path="/models/v1/model.isof",
            training_date=datetime.now(timezone.utc),
            training_data_size=10000,
            false_positive_rate=0.02,
            detection_rate=0.95,
            active=True
        )
        sess.add(model1)
        sess.flush()

        model2 = MlModelVersion(
            file_path="/models/v2/model.isof",
            training_date=datetime.now(timezone.utc),
            training_data_size=12000,
            false_positive_rate=0.025,
            detection_rate=0.93,
            active=False   # inactive — should not affect model1
        )
        sess.add(model2)
        sess.flush()

        sess.refresh(model1)
        assert model1.active is True, "model1 must remain active"


# ── device_registry tests ─────────────────────────────────────────────────────

class TestDeviceRegistry:

    def test_unique_device_per_user(self, sess, user):
        d1 = DeviceRegistry(user_id=user.id, device_hash="c" * 64)
        d2 = DeviceRegistry(user_id=user.id, device_hash="c" * 64)  # duplicate
        sess.add(d1)
        sess.flush()
        sess.add(d2)
        with pytest.raises(Exception):
            sess.flush()

    def test_same_device_different_users(self, sess, user, admin_user):
        """The same device hash for two different users is allowed."""
        d1 = DeviceRegistry(user_id=user.id,       device_hash="d" * 64)
        d2 = DeviceRegistry(user_id=admin_user.id,  device_hash="d" * 64)
        sess.add(d1)
        sess.add(d2)
        sess.flush()  # must not raise
        