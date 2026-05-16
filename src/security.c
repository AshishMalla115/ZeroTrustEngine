#include "risk_engine.c"
#include "security.h"
#include<openssl/hmac.h>
#include<string.h>

int re_hmac_validate(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t data_len, const uint8_t *expected_hmac){
	unsigned char computed[32]; 
	unsigned int computed_len = 0; 

	HMAC(EVP_sha256(),key, (int)key_len,data, (size_t)data_len,computed, &computed_len);
   	if(computed_len != 32){
       		return -1;
    	}

    	return re_constant_time_compare(computed, expected_hmac, 32) == 0 ? 0 : -1;
}

void token_bucket_init(TokenBucket *bucket, float capacity, float refill_rate)
{
   	 bucket->capacity = capacity;
   	 bucket->refill_rate = refill_rate;
   	 bucket->tokens = capacity;
   	 bucket->last_refill = 0;
}

int token_bucket_consume(TokenBucket *bucket, int64_t current_time)
{
    	int64_t elapsed = current_time - bucket->last_refill;
    	bucket->tokens += (float)elapsed * bucket->refill_rate;
    	if (bucket->tokens > bucket->capacity)
    	{
    	    bucket->tokens = bucket->capacity;
    	}
    	bucket->last_refill = current_time;
    	if (bucket->tokens >= 1.0f)
    	{
    	    bucket->tokens -= 1;
    	    return 1;
   	 }
   	 else
   	 {
   	     return 0;
    	}
}

int re_constant_time_compare(const uint8_t *a, const uint8_t *b, uint32_t len)
{
	    int result = 0;
	    for (uint32_t i = 0; i < len; i++)
	    {
	        result |= a[i] ^ b[i];
	    }
	    return result != 0;
}
