-- scripts/behavioral_log_query.sql
-- Owner: Indra (Layer 4 — Database)
-- For: Adnaan (Layer 2 — ML Pipeline) — hand this to him in Week 4
--
-- PURPOSE: Pulls behavioral event logs for Adnaan's Isolation Forest retraining.
-- CONNECT AS: ztrust_readonly (password: ReadOnlyPass456!)
-- NEVER use ztrust_app for Adnaan's pipeline — it has write permissions.
--
-- FEATURE VECTOR ORDER (must match build_feature_vector() in scoring.c exactly):
--   feature_vector[0] = tm_hour / 23.0f              (hour_of_day normalized)
--   feature_vector[1] = failed_attempts / 10.0f      (failed login count)
--   feature_vector[2] = device_hash % 1000 / 1000.0f (device novelty signal)
--   feature_vector[3] = geo_hash % 1000 / 1000.0f    (location novelty)
--   feature_vector[4] = ip_hash % 1000 / 1000.0f     (IP novelty)
--   feature_vector[5] = login_count / 100.0f          (session frequency)
--
-- PYTHON USAGE (Adnaan's retraining pipeline):
--
--   import psycopg2, numpy as np
--
--   conn = psycopg2.connect(
--       host="localhost", port=5432, dbname="zero_trust_db",
--       user="ztrust_readonly", password="ReadOnlyPass456!"
--   )
--   cur = conn.cursor()
--
--   with open("scripts/behavioral_log_query.sql") as f:
--       sql = f.read()
--
--   # Pull last 30 days for retraining
--   cur.execute(sql, {"since": "30 days"})
--   rows = cur.fetchall()
--   # Each row: (feature_vector, decision, rule_score, ml_score, event_type, created_at, user_role)
--   X = np.array([row[0] for row in rows if row[0] is not None])  # shape (N, 6)
--
-- ISOLATION FOREST NOTE:
--   Train ONLY on rows WHERE decision = 'ALLOW' (normal behavior).
--   The model learns what normal looks like — not what attacks look like.
--   The full dataset (including RESTRICT/BLOCK rows) is used only for evaluation.

SELECT
    rel.feature_vector,           -- float8[6] — the 6 features from scoring.c
    rel.decision,                 -- ALLOW | RESTRICT | MFA_REQUIRED | BLOCK
    rel.rule_score,               -- rule-based component of the score
    rel.ml_score,                 -- isolation forest output at time of event (NULL early on)
    rel.risk_score_after,         -- final combined score
    rel.event_type,               -- LOGIN | API_CALL | etc.
    rel.created_at,               -- timestamp for time-series analysis
    u.role AS user_role           -- user | admin | readonly (for per-role FP analysis)
FROM
    risk_event_log rel
    JOIN users u ON rel.user_id = u.id
WHERE
    rel.created_at >= NOW() - INTERVAL %(since)s
    AND rel.feature_vector IS NOT NULL
    AND array_length(rel.feature_vector, 1) = 6   -- safety check
    AND rel.event_type = 'LOGIN'                  -- feature vectors only on LOGIN events
ORDER BY
    rel.created_at ASC;

-- ─────────────────────────────────────────────────────────────────────────────
-- TRAINING-ONLY VARIANT: normal behavior only (uncomment for unsupervised training)
-- ─────────────────────────────────────────────────────────────────────────────
-- SELECT rel.feature_vector
-- FROM risk_event_log rel
-- WHERE
--     rel.created_at >= NOW() - INTERVAL %(since)s
--     AND rel.feature_vector IS NOT NULL
--     AND array_length(rel.feature_vector, 1) = 6
--     AND rel.decision = 'ALLOW'        -- normal logins only
--     AND rel.event_type = 'LOGIN'
-- ORDER BY rel.created_at ASC;

-- ─────────────────────────────────────────────────────────────────────────────
-- STATISTICS QUERY: check how many samples are available before training
-- ─────────────────────────────────────────────────────────────────────────────
-- SELECT
--     decision,
--     COUNT(*) AS sample_count,
--     MIN(created_at) AS oldest,
--     MAX(created_at) AS newest
-- FROM risk_event_log
-- WHERE
--     feature_vector IS NOT NULL
--     AND created_at >= NOW() - INTERVAL %(since)s
-- GROUP BY decision
-- ORDER BY decision;
