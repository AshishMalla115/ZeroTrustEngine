#include "risk_engine.h"
#include "scoring.h"
#include <stdlib.h>

struct RiskEngine{
	EngineConfig config;
};
RiskEngine* re_engine_create(const EngineConfig* config){
	RiskEngine* engine = malloc(sizeof(RiskEngine));
	if(engine == NULL){
		return NULL;
	}
	engine->config = *config;
	return engine;
}
void  re_engine_destroy(RiskEngine* engine){
	free(engine);
}
RiskDecision re_evaluate_login(RiskEngine* engine,const LoginEvent*event){
	float score = compute_login_score(event); 
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
