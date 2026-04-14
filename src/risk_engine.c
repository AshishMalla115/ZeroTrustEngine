#include "risk_engine.h"
#include "scoring.h"
#include <stdlib.h>
#include <string.h>
struct RiskEngine{
	EngineConfig config;
	UserProfile profiles[1024];
	uint32_t profile_count;
};

RiskEngine* re_engine_create(const EngineConfig* config){
	RiskEngine* engine = malloc(sizeof(RiskEngine));
	engine->profile_count =0;
	memset(engine->profile, 0 ,sizeof(engine->profiles));
	if(engine == NULL){
		return NULL;
	}
	engine->config = *config;
	return engine;
}
void  re_engine_destroy(RiskEngine* engine){
	free(engine);
}
static UserProfile* find_or_create_profile(RiskEngine* engine, uint64_t user_id){
	while(engine->profiles){
		if(profile.user_id == user_id){
			return *user_id; 
		}
	}
	if(profile.count <1024){
		// i dont know what to do here
	}
	// dont know the step3 either
}
RiskDecision re_evaluate_login(RiskEngine* engine,const LoginEvent*event){
	UserProfile* profile = find_or_create_profile(engine , event->user_id);
	int known_device = 0; 
	int known_location = 0; 
	if(profile != NULL){
		known_device = profile_bloom_check(profile, event->device_hash); 
		known_location = profile_bloom_check(profile , (uint64_t)event->geo_hash);
	}

	float score = compute_login_score(event , known_device, known_location);
	if(profile != NULL){
		profile_update_login(profile,event);
	}	

	DecisionType decision; 
	if(score < engine->config.score_threshold_mfa){
		decision = ALLOW; 
	}else if(score < engine->config.score_threshold_block){
		decision = MFA_REQUIRED;
	}else{
		decision = BLOCK;
	}

	RiskLevel risk; 
	if(score < 0.3f){
		risk = LOW; 
	}else if(score < 0.6f){
		risk = MEDIUM;
	}else if(score < 0.8f){
		risk = HIGH;
	}else{
		risk = CRITICAL;
	}

	RiskDecision result; 
	result.decision = decision; 
	result.risk_level = risk; 
	result.score = score; 
	result.rule_score = score; 
	result.ml_score = 0.0f; 
	result.reason_code = 0; 
	return result; 
}
