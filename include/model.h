#ifndef MODEL_H
#define MODEL_H

#include "risk_engine.h"

#define MODEL_MAGIC 0x464F5349 
#define LEAF_SENTINEL 0xFFFFFFFF
#define MODEL_FEATURES 6

typedef struct{
	uint32_t node_id; 
	uint32_t left_child;
	uint32_t right_child;  
	uint32_t feature_index; 
	float threshold; 
	float path_length;
}IsoNode; 

typedef struct{
	uint32_t tree_count; 
	uint32_t feature_count;
       	uint32_t total_nodes;	
	uint32_t* tree_offsets;
	IsoNode* nodes;
}IsolationForest;

int model_load(IsolationForest* model, const char* path); 
void model_free(IsolationForest* model); 
float model_predict(const IsolationForest* model, const float* features,uint32_t feature_count); 

#endif
