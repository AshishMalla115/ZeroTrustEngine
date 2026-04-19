#include <stdio.h>
#include "risk_engine.h"

int main(void) {

    // 1. Configure the engine
    EngineConfig config = {
        .model_path            = "none",
        .score_threshold_mfa   = 0.4f,
        .score_threshold_block = 0.75f,
        .decay_rate            = 0.1f,
        .tick_interval_sec     = 60,
        .max_users             = 1000
    };

    // 2. Create the engine
    RiskEngine* engine = re_engine_create(&config);
    if (engine == NULL) {
        printf("ERROR: Failed to create engine\n");
        return 1;
    }
    printf("Engine created successfully\n");

    // 3. Simulate a login event
    LoginEvent login = {
        .user_id         = 42,
        .timestamp_unix  = 1700000000,
        .device_hash     = 99999,
        .ip_hash         = 12345,
        .geo_hash        = 67890,
        .failed_attempts = 3
    };

    // 4. Evaluate it
    RiskDecision decision = re_evaluate_login(engine, &login);

    // 5. Print results
    printf("Score      : %.2f\n", decision.score);
    printf("Rule Score : %.2f\n", decision.rule_score);
    printf("ML Score   : %.2f\n", decision.ml_score);

    printf("Risk Level : ");
    switch (decision.risk_level) {
        case LOW:      printf("LOW\n");      break;
        case MEDIUM:   printf("MEDIUM\n");   break;
        case HIGH:     printf("HIGH\n");     break;
        case CRITICAL: printf("CRITICAL\n"); break;
    }

    printf("Decision   : ");
    switch (decision.decision) {
        case ALLOW:        printf("ALLOW\n");        break;
        case RESTRICT:     printf("RESTRICT\n");     break;
        case MFA_REQUIRED: printf("MFA_REQUIRED\n"); break;
        case BLOCK:        printf("BLOCK\n");        break;
    }

    // 6. Cleanup
    re_engine_destroy(engine);
    printf("Engine destroyed cleanly\n");

    return 0;
}
