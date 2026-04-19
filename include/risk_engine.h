#ifndef RISK_ENGINE_H
#define RISK_ENGINE_H

#include <stdint.h>

typedef enum {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
} RiskLevel;

typedef enum {
    ALLOW,
    RESTRICT,
    MFA_REQUIRED,
    BLOCK
} DecisionType;

typedef enum {
    LOGIN,
    API_CALL,
    FILE_DOWNLOAD,
    PASSWORD_CHANGE,
    ADMIN_ACTION,
    DATA_EXPORT,
    FAILED_AUTH
} EventType;

typedef struct {
    uint64_t user_id;
    int64_t  timestamp_unix;
    uint64_t device_hash;
    uint32_t ip_hash;
    uint32_t geo_hash;
    uint8_t failed_attempts;
} LoginEvent;

typedef struct {
    uint64_t  session_id;
    uint64_t  user_id;
    EventType event_type;
    int64_t   timestamp_unix;
    uint32_t  bytes_transferred;
    uint32_t  endpoint_hash;
} SessionEvent;

typedef struct {
    DecisionType decision;
    RiskLevel    risk_level;
    float        score;
    uint32_t     reason_code;
    float        ml_score;
    float        rule_score;
} RiskDecision;

typedef struct {
    uint64_t user_id;
    double   login_hour_mean;
    double   login_hour_variance;
    uint64_t login_count;
    double   bytes_per_session_mean;
    double   bytes_per_session_variance;
    float    current_risk_score;
    int64_t  last_seen_unix;
    uint8_t  bloom_filter[256];
} UserProfile;

typedef struct {
    char     model_path[256];
    float    score_threshold_mfa;
    float    score_threshold_block;
    float    decay_rate;
    uint32_t tick_interval_sec;
    uint32_t max_users;
} EngineConfig;

typedef struct RiskEngine RiskEngine;

RiskEngine*  re_engine_create(const EngineConfig* config);
void         re_engine_destroy(RiskEngine* engine);
int          re_engine_reload_model(RiskEngine* engine, const char* model_path);

RiskDecision re_evaluate_login(RiskEngine* engine, const LoginEvent* event);
RiskDecision re_evaluate_event(RiskEngine* engine, const SessionEvent* event);

int re_profile_serialize(RiskEngine* engine, uint64_t user_id,uint8_t* out_buf, uint32_t buf_size,uint32_t* written);
int re_profile_deserialize(RiskEngine* engine,const uint8_t* buf, uint32_t buf_size);

void re_engine_tick(RiskEngine* engine);

int re_hmac_validate(const uint8_t* key, uint32_t key_len,const uint8_t* data, uint32_t data_len,const uint8_t* expected_hmac);
int re_constant_time_compare(const uint8_t* a, const uint8_t* b,uint32_t len);

#endif
