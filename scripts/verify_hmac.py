"""
scripts/verify_hmac.py
Owner: Indra (Layer 4 — Database)
Shared with: Ashish — he must use compute_hmac() with the exact same
             canonical string format before every INSERT into risk_event_log.

CANONICAL STRING FORMAT (Ashish must match this exactly):
  "{id}|{session_id}|{user_id}|{event_type}|{risk_score_before:.6f}|
   {risk_score_after:.6f}|{rule_score:.6f}|{ml_score_or_null}|
   {decision}|{risk_level}|{created_at_iso}"

ml_score is written as the string "null" when NULL.
created_at uses Python's datetime.isoformat() which includes timezone offset.

Usage:
    # Activate venv first
    python scripts/verify_hmac.py --once            # check last 60 min
    python scripts/verify_hmac.py --once --lookback 1440  # check last 24 hours
    python scripts/verify_hmac.py --watch           # check every 15 min continuously
"""

import os
import sys
import hmac
import hashlib
import argparse
import time
from datetime import datetime, timezone, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

import sqlalchemy as sa


# ── HMAC key from .env ───────────────────────────────────────────────────────

HMAC_KEY = os.environ.get("HMAC_SECRET_KEY", "").encode("utf-8")

if not HMAC_KEY:
    print("ERROR: HMAC_SECRET_KEY not set in .env")
    print("Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
    sys.exit(1)


# ── Canonical string + HMAC computation ─────────────────────────────────────

def compute_hmac(row: dict) -> str:
    """
    Recomputes the HMAC for a risk_event_log row.

    ASHISH: Your backend must compute the same string and HMAC before INSERT.
    If the canonical string format ever changes, coordinate with Indra first.
    Any difference causes every row to appear tampered.

    Python implementation for Ashish's backend:
    ──────────────────────────────────────────
    import hmac, hashlib

    HMAC_KEY = os.environ["HMAC_SECRET_KEY"].encode()

    def make_row_hmac(row_dict: dict) -> str:
        ml = f"{row_dict['ml_score']:.6f}" if row_dict['ml_score'] is not None else "null"
        canonical = (
            f"{row_dict['id']}|{row_dict['session_id']}|{row_dict['user_id']}|"
            f"{row_dict['event_type']}|{row_dict['risk_score_before']:.6f}|"
            f"{row_dict['risk_score_after']:.6f}|{row_dict['rule_score']:.6f}|"
            f"{ml}|{row_dict['decision']}|{row_dict['risk_level']}|"
            f"{row_dict['created_at'].isoformat()}"
        )
        return hmac.new(HMAC_KEY, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    ──────────────────────────────────────────
    """
    ml = f"{row['ml_score']:.6f}" if row["ml_score"] is not None else "null"
    canonical = (
        f"{row['id']}|{row['session_id']}|{row['user_id']}|"
        f"{row['event_type']}|{row['risk_score_before']:.6f}|"
        f"{row['risk_score_after']:.6f}|{row['rule_score']:.6f}|"
        f"{ml}|{row['decision']}|{row['risk_level']}|"
        f"{row['created_at'].isoformat()}"
    )
    return hmac.new(
        HMAC_KEY,
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


# ── Database connection ──────────────────────────────────────────────────────

def get_engine():
    url = (
        f"postgresql+psycopg2://"
        f"{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}"
        f"@{os.environ['DB_HOST']}:{os.environ['DB_PORT']}"
        f"/{os.environ['DB_NAME']}"
    )
    return sa.create_engine(url)


# ── Main verification logic ──────────────────────────────────────────────────

def run_check(engine, lookback_minutes: int = 60) -> dict:
    """
    Verifies HMACs for all risk_event_log rows created in the last
    `lookback_minutes` minutes. Writes tamper_log entries for any mismatch.
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    now_str = datetime.now(timezone.utc).isoformat()

    print(f"\n[{now_str}] Checking rows since {since.isoformat()}")

    total = ok = tampered = 0
    tampered_ids = []

    with engine.connect() as conn:
        rows = conn.execute(
            sa.text("SELECT * FROM get_risk_events_since(:since)"),
            {"since": since}
        ).mappings().all()

        for row in rows:
            total += 1
            expected = compute_hmac(dict(row))
            stored   = row["hmac"]

            if hmac.compare_digest(expected, stored):
                ok += 1
            else:
                tampered += 1
                tampered_ids.append(row["id"])
                print(f"  *** TAMPER DETECTED: risk_event_log.id = {row['id']}")
                print(f"      stored:   {stored}")
                print(f"      expected: {expected}")

                # Write to tamper_log
                try:
                    conn.execute(
                        sa.text(
                            "INSERT INTO tamper_log "
                            "(risk_event_id, stored_hmac, notes) "
                            "VALUES (:eid, :stored, :notes)"
                        ),
                        {
                            "eid":    row["id"],
                            "stored": stored,
                            "notes":  (
                                f"HMAC mismatch detected at {now_str}. "
                                f"Expected: {expected}"
                            ),
                        }
                    )
                    conn.commit()
                except Exception as exc:
                    print(f"  WARNING: Could not write to tamper_log: {exc}")

    print(f"  Rows checked: {total}  |  OK: {ok}  |  TAMPERED: {tampered}")
    if tampered > 0:
        print(f"  *** ALERT: Tampered row IDs: {tampered_ids}")
        print(f"  *** These have been written to the tamper_log table.")
    else:
        print("  All rows OK — audit log integrity verified.")

    return {"total": total, "ok": ok, "tampered": tampered}


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Verify HMAC integrity of risk_event_log"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single check and exit"
    )
    parser.add_argument(
        "--watch", action="store_true",
        help="Run checks every 15 minutes continuously (Ctrl+C to stop)"
    )
    parser.add_argument(
        "--lookback", type=int, default=60,
        help="How many minutes back to check (default: 60)"
    )
    args = parser.parse_args()

    engine = get_engine()

    if args.watch:
        print("Watching for tampered rows. Checking every 15 minutes.")
        print("Press Ctrl+C to stop.\n")
        while True:
            run_check(engine, args.lookback)
            time.sleep(900)  # 15 minutes
    else:
        run_check(engine, args.lookback)


if __name__ == "__main__":
    main()
    