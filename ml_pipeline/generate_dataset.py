"""
Stage 1 — Synthetic Dataset Generator
======================================
Generates synthetic LoginEvent records that mirror Uthkarsh's C struct exactly:

    typedef struct {
        uint64_t user_id;
        int64_t  timestamp_unix;
        uint64_t device_hash;
        uint32_t ip_hash;
        uint32_t geo_hash;
        uint8_t  failed_attempts;
    } LoginEvent;

Output: data/login_events.csv  (normal + attack samples)
        data/normal_samples.csv
        data/attack_samples.csv

Author : Adnaan (Layer 2 — ML Training Pipeline)
Connects to : Uthkarsh's risk_engine.c / scoring.c (Layer 1)
"""

import numpy as np
import pandas as pd
from datetime import datetime, timezone
import hashlib
import os
import random

# ─────────────────────────────────────────────
# Seed for reproducibility
# ─────────────────────────────────────────────
SEED = 42
np.random.seed(SEED)
random.seed(SEED)

# ─────────────────────────────────────────────
# Constants — mirror Uthkarsh's C type limits
# ─────────────────────────────────────────────
UINT64_MAX = 0xFFFFFFFFFFFFFFFF
UINT32_MAX = 0xFFFFFFFF
UINT8_MAX  = 255

N_NORMAL  = 10_000
N_ATTACK  =    500

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def make_device_hash(device_id: int) -> int:
    """Simulate a 64-bit device fingerprint hash."""
    raw = f"device_{device_id}".encode()
    return int(hashlib.sha256(raw).hexdigest()[:16], 16) & UINT64_MAX


def make_ip_hash(ip_str: str) -> int:
    """Simulate a 32-bit IP hash (like Uthkarsh's ip_hash field)."""
    raw = ip_str.encode()
    return int(hashlib.md5(raw).hexdigest()[:8], 16) & UINT32_MAX


def make_geo_hash(city: str) -> int:
    """Simulate a 32-bit geo hash from a city name."""
    raw = city.encode()
    return int(hashlib.md5(raw).hexdigest()[:8], 16) & UINT32_MAX


def hour_to_unix(base_date: str, hour: float, jitter_minutes: int = 15) -> int:
    """
    Convert a base date + hour-of-day into a Unix timestamp (int64).
    Adds small jitter so timestamps aren't perfectly round.
    """
    dt = datetime.strptime(base_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    seconds = int(hour * 3600) + random.randint(-jitter_minutes * 60, jitter_minutes * 60)
    return int(dt.timestamp()) + seconds


# ─────────────────────────────────────────────
# Normal User Population
# ─────────────────────────────────────────────
# 200 synthetic users, each with:
#   - a preferred login hour  (business hours, 9–18)
#   - 1–3 known devices
#   - 1–2 known locations
#   - almost never fails login

OFFICE_CITIES = ["Bengaluru", "Mumbai", "Hyderabad", "Chennai", "Pune"]
HOME_CITIES   = ["Bengaluru_home", "Mumbai_home", "Hyderabad_home"]

def build_user_profiles(n_users: int = 200) -> dict:
    profiles = {}
    for uid in range(1, n_users + 1):
        preferred_hour = np.random.normal(loc=11.0, scale=2.0)   # centred ~11am
        preferred_hour = float(np.clip(preferred_hour, 8.0, 18.0))

        n_devices   = random.randint(1, 3)
        device_ids  = [random.randint(1000, 9999) for _ in range(n_devices)]

        n_locations = random.randint(1, 2)
        cities      = random.sample(OFFICE_CITIES + HOME_CITIES, n_locations)

        profiles[uid] = {
            "preferred_hour" : preferred_hour,
            "device_ids"     : device_ids,
            "cities"         : cities,
        }
    return profiles


def generate_normal_samples(n: int, user_profiles: dict) -> pd.DataFrame:
    """
    Normal behaviour:
      - login hour close to user's preferred hour (business hours)
      - known device (from user's registered devices)
      - known location (from user's usual cities)
      - failed_attempts almost always 0, rarely 1
    """
    records = []
    user_ids = list(user_profiles.keys())

    # Spread across 90 days of dates
    base_dates = pd.date_range("2024-10-01", periods=90, freq="D").strftime("%Y-%m-%d").tolist()

    for _ in range(n):
        uid     = random.choice(user_ids)
        profile = user_profiles[uid]

        # Hour: normal distribution around user's preferred hour
        hour = np.random.normal(loc=profile["preferred_hour"], scale=1.5)
        hour = float(np.clip(hour, 0.0, 23.99))

        base_date     = random.choice(base_dates)
        timestamp_unix = hour_to_unix(base_date, hour)

        # Known device — very occasionally (2%) a new temporary device
        if random.random() < 0.02:
            device_hash = make_device_hash(random.randint(10000, 99999))  # unknown
        else:
            device_hash = make_device_hash(random.choice(profile["device_ids"]))

        # Known location — very occasionally (3%) roaming
        if random.random() < 0.03:
            city = random.choice(OFFICE_CITIES)
        else:
            city = random.choice(profile["cities"])
        geo_hash = make_geo_hash(city)

        # IP: consistent subnet for known office/home
        ip_str       = f"192.168.{random.randint(1,5)}.{random.randint(1,254)}"
        ip_hash      = make_ip_hash(ip_str)

        # Failed attempts: 90% → 0, 8% → 1, 2% → 2
        failed_attempts = int(np.random.choice([0, 1, 2], p=[0.90, 0.08, 0.02]))
        failed_attempts = min(failed_attempts, UINT8_MAX)

        records.append({
            "user_id"        : uid,
            "timestamp_unix" : timestamp_unix,
            "device_hash"    : device_hash,
            "ip_hash"        : ip_hash,
            "geo_hash"       : geo_hash,
            "failed_attempts": failed_attempts,
            "label"          : 0,          # 0 = normal
            "attack_type"    : "none",
            "hour_of_day"    : round(hour, 4),
        })

    return pd.DataFrame(records)


# ─────────────────────────────────────────────
# Attack Pattern Generation
# ─────────────────────────────────────────────
# Three realistic attack types from the brief:
#   1. Credential stuffing / brute force
#   2. Off-hours login from new device + new location (account takeover)
#   3. Insider threat (known user, odd hour, unusual IP)

def generate_attack_samples(n: int, user_profiles: dict) -> pd.DataFrame:
    records   = []
    user_ids  = list(user_profiles.keys())
    base_dates = pd.date_range("2024-10-01", periods=90, freq="D").strftime("%Y-%m-%d").tolist()

    n_brute    = int(n * 0.40)   # 40% brute force
    n_takeover = int(n * 0.40)   # 40% account takeover
    n_insider  = n - n_brute - n_takeover  # 20% insider threat

    # ── 1. Brute Force / Credential Stuffing ──────────────────────────────
    for _ in range(n_brute):
        uid       = random.choice(user_ids)

        # Off-hours: late night or early morning
        hour = random.choice([
            random.uniform(0.0,  5.99),   # midnight–6am
            random.uniform(22.0, 23.99),  # 10pm–midnight
        ])

        base_date      = random.choice(base_dates)
        timestamp_unix = hour_to_unix(base_date, hour)

        # Unknown device (attacker's machine)
        device_hash    = make_device_hash(random.randint(100000, 999999))

        # Foreign IP range
        ip_str   = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        ip_hash  = make_ip_hash(ip_str)

        # Unknown geo
        geo_hash = make_geo_hash(f"unknown_{random.randint(1,100)}")

        # Many failed attempts before potential success
        failed_attempts = int(np.random.choice(
            [3, 4, 5, 6, 7, 8, 9, 10],
            p=[0.15, 0.15, 0.20, 0.15, 0.15, 0.10, 0.05, 0.05]
        ))
        failed_attempts = min(failed_attempts, UINT8_MAX)

        records.append({
            "user_id"        : uid,
            "timestamp_unix" : timestamp_unix,
            "device_hash"    : device_hash,
            "ip_hash"        : ip_hash,
            "geo_hash"       : geo_hash,
            "failed_attempts": failed_attempts,
            "label"          : 1,
            "attack_type"    : "brute_force",
            "hour_of_day"    : round(hour, 4),
        })

    # ── 2. Account Takeover (new device + new location + off-hours) ────────
    for _ in range(n_takeover):
        uid = random.choice(user_ids)

        hour = random.choice([
            random.uniform(0.0,  5.99),
            random.uniform(22.0, 23.99),
        ])

        base_date      = random.choice(base_dates)
        timestamp_unix = hour_to_unix(base_date, hour)

        # Completely new device — attacker's machine
        device_hash = make_device_hash(random.randint(200000, 299999))

        # Foreign country IP
        ip_str  = f"{random.randint(50,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        ip_hash = make_ip_hash(ip_str)

        # Foreign geo
        foreign_cities = ["Moscow", "Lagos", "Beijing", "Minsk", "Pyongyang"]
        geo_hash = make_geo_hash(random.choice(foreign_cities))

        # Usually succeeds first try (stolen credentials)
        failed_attempts = int(np.random.choice([0, 1, 2], p=[0.60, 0.30, 0.10]))

        records.append({
            "user_id"        : uid,
            "timestamp_unix" : timestamp_unix,
            "device_hash"    : device_hash,
            "ip_hash"        : ip_hash,
            "geo_hash"       : geo_hash,
            "failed_attempts": failed_attempts,
            "label"          : 1,
            "attack_type"    : "account_takeover",
            "hour_of_day"    : round(hour, 4),
        })

    # ── 3. Insider Threat (known user, odd hour, unusual IP) ──────────────
    for _ in range(n_insider):
        uid     = random.choice(user_ids)
        profile = user_profiles[uid]

        # Slightly off-hours but not extreme — makes insider harder to detect
        hour = random.choice([
            random.uniform(6.0,  8.99),   # very early
            random.uniform(19.0, 21.99),  # evening
        ])

        base_date      = random.choice(base_dates)
        timestamp_unix = hour_to_unix(base_date, hour)

        # Known device (insider uses own machine)
        device_hash = make_device_hash(random.choice(profile["device_ids"]))

        # Unusual IP — VPN or home network outside normal subnet
        ip_str  = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        ip_hash = make_ip_hash(ip_str)

        # Known location but occasionally roaming
        city     = random.choice(profile["cities"])
        geo_hash = make_geo_hash(city)

        # Rarely fails — insider knows credentials
        failed_attempts = int(np.random.choice([0, 1], p=[0.85, 0.15]))

        records.append({
            "user_id"        : uid,
            "timestamp_unix" : timestamp_unix,
            "device_hash"    : device_hash,
            "ip_hash"        : ip_hash,
            "geo_hash"       : geo_hash,
            "failed_attempts": failed_attempts,
            "label"          : 1,
            "attack_type"    : "insider_threat",
            "hour_of_day"    : round(hour, 4),
        })

    return pd.DataFrame(records)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print("=" * 60)
    print("ZeroTrustEngine — Stage 1: Synthetic Dataset Generator")
    print("=" * 60)

    os.makedirs("data", exist_ok=True)

    print(f"\n[1/4] Building user profiles (200 synthetic users)...")
    user_profiles = build_user_profiles(n_users=200)

    print(f"[2/4] Generating {N_NORMAL:,} normal samples...")
    normal_df = generate_normal_samples(N_NORMAL, user_profiles)

    print(f"[3/4] Generating {N_ATTACK:,} attack samples...")
    attack_df = generate_attack_samples(N_ATTACK, user_profiles)

    # ── Combine and shuffle ───────────────────────────────────────────────
    full_df = pd.concat([normal_df, attack_df], ignore_index=True)
    full_df = full_df.sample(frac=1, random_state=SEED).reset_index(drop=True)

    # ── Save ──────────────────────────────────────────────────────────────
    normal_df.to_csv("data/normal_samples.csv",  index=False)
    attack_df.to_csv("data/attack_samples.csv",  index=False)
    full_df.to_csv(  "data/login_events.csv",    index=False)

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n[4/4] Dataset summary")
    print("-" * 40)
    print(f"  Normal samples  : {len(normal_df):>6,}")
    print(f"  Attack samples  : {len(attack_df):>6,}")
    print(f"    ├─ brute_force    : {len(attack_df[attack_df.attack_type=='brute_force']):>4}")
    print(f"    ├─ account_takeover: {len(attack_df[attack_df.attack_type=='account_takeover']):>4}")
    print(f"    └─ insider_threat  : {len(attack_df[attack_df.attack_type=='insider_threat']):>4}")
    print(f"  Total           : {len(full_df):>6,}")
    print(f"\n  Files written:")
    print(f"    data/normal_samples.csv")
    print(f"    data/attack_samples.csv")
    print(f"    data/login_events.csv")

    print("\n  Column mapping to Uthkarsh's LoginEvent struct:")
    print("    user_id         → uint64_t user_id")
    print("    timestamp_unix  → int64_t  timestamp_unix")
    print("    device_hash     → uint64_t device_hash")
    print("    ip_hash         → uint32_t ip_hash")
    print("    geo_hash        → uint32_t geo_hash")
    print("    failed_attempts → uint8_t  failed_attempts")
    print("\n  Extra columns (ML only, not in C struct):")
    print("    label           → 0=normal, 1=attack")
    print("    attack_type     → none / brute_force / account_takeover / insider_threat")
    print("    hour_of_day     → derived from timestamp_unix (for readability)")

    print("\n✓ Stage 1 complete.\n")

    return full_df, normal_df, attack_df


if __name__ == "__main__":
    full_df, normal_df, attack_df = main()