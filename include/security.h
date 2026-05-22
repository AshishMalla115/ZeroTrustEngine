#ifndef SECURITY_H
#define SECURITY_H

#include "risk_engine.h"
#include<openssl/hmac.h>

typedef struct{
    float tokens; 
    float capacity; 
    float refill_rate; 
    int64_t last_refill; 
}TokenBucket; 

void token_bucket_init(TokenBucket* bucket, float capacity, float refill_rate);

int token_bucket_consume(TokenBucket* bucket, int64_t current_time); 

int re_constant_time_compare(const uint8_t *a,const uint8_t* b, uint32_t len); 

int re_hmac_validate(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t data_len, const uint8_t *expected_hmac);

#endif
