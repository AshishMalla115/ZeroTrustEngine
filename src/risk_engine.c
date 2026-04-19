#include "risk_engine.h"
#include "scoring.h"
#include "profile.h"
#include "session.h"
#include <stdlib.h>
#include <string.h>
struct RiskEngine{
	EngineConfig config;
	UserProfile profiles[1024];
	uint32_t profile_count;
	SessionBuffer sessions[1024]; 
	uint64_t session_count;
};

RiskEngine* re_engine_create(const EngineConfig* config){
	RiskEngine* engine = malloc(sizeof(RiskEngine));
	if(engine == NULL){
                return NULL;
        }
	engine->config = *config;
	engine->profile_count =0;
	memset(engine->profiles, 0 ,sizeof(engine->profiles));
	return engine;
}
void  re_engine_destroy(RiskEngine* engine){
	free(engine);
}

void re_engine_tick(RiskEngine* engine){
	for(uint32_t i = 0; i < engine->profile_count; i++){
		engine->profiles[i].current_risk_score *= (1.0f - engine->config.decay_rate);
	}
}
static UserProfile* find_or_create_profile(RiskEngine* engine, uint64_t user_id){
	for(uint32_t i = 0; i < engine->profile_count; i++){
		if(engine->profiles[i].user_id == user_id){
			return &engine->profiles[i];
		}
	}
	if(engine->profile_count < 1024){
		UserProfile* p = &engine->profiles[engine->profile_count];
		p->user_id = user_id; 
		engine->profile_count++; 
		return p; 
	}
	return NULL;
}

static SessionBuffer* find_or_create_session(RiskEngine* engine, uint64_t session_id){
	for(uint32_t i = 0; i < engine->session_count; i++){
		if(engine->sessions[i].session_id == session_id){
			return &engine->sessions[i];
		}
	}
	if(engine->session_count < 1024){
		SessionBuffer* s = &engine->sessions[engine->session_count]; 
		s->session_id = session_id; 
		engine->session_count++;
		return s;
	}
	return NULL;
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
