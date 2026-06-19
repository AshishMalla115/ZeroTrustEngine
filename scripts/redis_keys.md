# Redis Key Schema
**Owner:** Indra (Layer 4 — Database)
**For:** Ashish (Layer 3 — Backend)

---

## Key Patterns (use EXACTLY these — never invent new keys)

### 1. `session:{jwt_jti}`
**Purpose:** Cached active_sessions row — avoids PostgreSQL hit on every request.

| Field | Value |
|-------|-------|
| Type | Redis STRING (JSON) |
| TTL | Match JWT expiry — typically `3600` seconds |
| Value | JSON: `{"session_id": "uuid", "user_id": "uuid", "current_risk_score": 0.15, "current_decision": "ALLOW", "current_risk_level": "LOW", "device_hash": "hex64", "ip_hash": "hex64"}` |

**Operations:**
- **WRITE:** After login — `SET session:{jti} {json} EX 3600`
- **READ:** On every middleware call — `GET session:{jti}` (fall back to PostgreSQL on miss)
- **UPDATE:** After every `re_evaluate_event()` call — update `current_risk_score`, `current_decision`, `current_risk_level`
- **DELETE:** On logout — `DEL session:{jti}`

> **Note on decision values:** Store as uppercase C enum strings — `ALLOW`, `RESTRICT`, `MFA_REQUIRED`, `BLOCK`. These must match the PostgreSQL CHECK constraints.

---

### 2. `failed:{user_id}`
**Purpose:** Counts failed login attempts per user for brute-force detection.

| Field | Value |
|-------|-------|
| Type | Redis STRING (integer) |
| TTL | `900` seconds (15 minutes — resets counter after inactivity) |

**Operations:**
- **WRITE:** On failed login — `INCR failed:{user_id}` then set TTL if key is new
```python
  pipe = r.pipeline()
  pipe.incr(f"failed:{user_id}")
  pipe.expire(f"failed:{user_id}", 900)
  pipe.execute()
```
- **READ:** Before processing login — if value `>= 5`, return 429 Too Many Requests
  (score_failed_attempts() in scoring.c returns 1.0f at 5 attempts)
- **DELETE:** On successful login — `DEL failed:{user_id}`

> **NEVER use GET + SET** for incrementing — use atomic `INCR` to avoid race conditions.

---

### 3. `ratelimit:user:{user_id}`
**Purpose:** Sliding window request counter per user (per-minute rate limiting).

| Field | Value |
|-------|-------|
| Type | Redis STRING (integer) |
| TTL | `60` seconds (auto-resets every minute) |

**Operations:**
- **WRITE:** On every authenticated request — `INCR ratelimit:user:{user_id}`
- **READ:** If value `>= 200`, return 429 (token bucket in C engine also limits)
- **TTL is managed by the key expiry** — do not manually reset.

---

### 4. `ratelimit:ip:{ip_hash}`
**Purpose:** Sliding window request counter per IP (catches unauthenticated attacks).

| Field | Value |
|-------|-------|
| Type | Redis STRING (integer) |
| TTL | `60` seconds |

> Store `ip_hash` (SHA256 of raw IP in hex), **never** the raw IP.

**Operations:**
- **WRITE:** On every request (before auth check) — `INCR ratelimit:ip:{ip_hash}`
- **READ:** If value `>= 500`, return 429 immediately

---

### 5. `ws:admins`
**Purpose:** Tracks which admin sessions have active WebSocket connections.

| Field | Value |
|-------|-------|
| Type | Redis SET of jwt_jti strings |
| TTL | None (managed manually) |

**Operations:**
- **WRITE:** On WebSocket connect — `SADD ws:admins {jwt_jti}`
- **READ:** When broadcasting risk updates — `SMEMBERS ws:admins`
- **DELETE member:** On WebSocket disconnect — `SREM ws:admins {jwt_jti}`

---

### 6. `mfa:{user_id}:{random_token}`
**Purpose:** Short-lived MFA pending token issued when C engine returns `MFA_REQUIRED`.

| Field | Value |
|-------|-------|
| Type | Redis STRING (JSON) |
| TTL | `300` seconds (5 minutes — hard expiry) |
| Value | JSON: `{"session_id": "uuid", "issued_at_unix": 1234567890}` |

**Operations:**
- **WRITE:** When decision is `MFA_REQUIRED` — generate token, `SET mfa:{user_id}:{token} {json} EX 300`
- **READ:** When user submits MFA code — verify key exists
- **DELETE:** On successful MFA verification — `DEL mfa:{user_id}:{token}`

---

## Connection Pool (paste into Ashish's startup code)

```python
import redis

redis_pool = redis.ConnectionPool(
    host=os.environ["REDIS_HOST"],
    port=int(os.environ["REDIS_PORT"]),
    decode_responses=True,
    max_connections=20
)
r = redis.Redis(connection_pool=redis_pool)
```

**Never** create a new `redis.Redis()` per request — always use the pool.

---

## TTL Summary

| Key Pattern | TTL | Managed By |
|-------------|-----|-----------|
| `session:{jti}` | Match JWT expiry (3600s) | Auto-expiry |
| `failed:{user_id}` | 900s (15 min) | Auto-expiry, DELETE on success |
| `ratelimit:user:{user_id}` | 60s | Auto-expiry |
| `ratelimit:ip:{ip_hash}` | 60s | Auto-expiry |
| `ws:admins` | None | Manual SADD/SREM |
| `mfa:{user_id}:{token}` | 300s (5 min) | Auto-expiry |
