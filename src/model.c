#include "model.h"
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <math.h>

static uint32_t crc32_compute(const uint8_t* data, size_t len){
	uint32_t crc = 0xFFFFFFFF;
	for(size_t i = 0; i < len; i++){
		crc ^= data[i];
		for(int j = 0; j <8; j++){
			if(crc & 1) 
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
	}
	return crc ^ 0xFFFFFFFF;
}

int model_load(IsolationForest* model, const char* path){
	FILE* f = fopen(path,"rb");
	if(f == NULL) return -1;
	
	fseek(f,0,SEEK_END); 
	long file_size = ftell(f);
	fseek(f,0,SEEK_SET);

	uint8_t* buf = malloc((size_t)file_size); 
	if(buf == NULL){
		fclose(f); 
		return -1;
	}
	fread(buf,1,(size_t)file_size, f);
	fclose(f);

	uint32_t magic; 
	memcpy(&magic, buf,4); 
	if(magic != MODEL_MAGIC){
		free(buf); 
		return -1;
	}
	uint32_t version, tree_count, feature_count, data_offset, checksum;
	memcpy(&version,      buf + 4,  4);
	memcpy(&tree_count,   buf + 8,  4);
	memcpy(&feature_count,buf + 12, 4);
	memcpy(&data_offset,  buf + 16, 4);
	memcpy(&checksum,     buf + 20, 4);
	
	if(feature_count != MODEL_FEATURES) { 	
		free(buf); 
		return -1; 
	}	

	uint32_t computed = crc32_compute(buf + 32, (size_t)file_size - 32);
	if(computed != checksum) { 
		free(buf); 
		return -1; 
	}
	uint32_t total_nodes = (uint32_t)((file_size - 32) / sizeof(IsoNode));
	model->nodes = malloc(total_nodes * sizeof(IsoNode));
	if(model->nodes == NULL) { 
		free(buf); 
		return -1; 
	}
	model->tree_offsets = malloc(tree_count * sizeof(uint32_t));
	if(model->tree_offsets == NULL) { 
		free(model->nodes); 
		free(buf); 
		return -1; 
	}

	memcpy(model->nodes, buf + 32, total_nodes * sizeof(IsoNode));
	free(buf);

	uint32_t tree_index = 0;
	for(uint32_t i = 0; i < total_nodes && tree_index < tree_count; i++){
		if(model->nodes[i].node_id == 0){
			model->tree_offsets[tree_index] = i;
			tree_index++;
		}
	}

	model->tree_count   = tree_count;
	model->feature_count = feature_count;
	model->total_nodes  = total_nodes;
	return 0;	
}

void model_free(IsolationForest* model){
	free(model->nodes);
	free(model->tree_offsets);
	model->nodes = NULL; 
	model->tree_offsets = NULL; 
	model->tree_count = 0;
}

float model_predict(const IsolationForest* model, const float* features, uint32_t feature_count){
	if(model == NULL || features == NULL) return 0.0f;
	double total_path = 0.0;
	for(uint32_t t = 0; t < model->tree_count; t++) {
    		uint32_t node_idx = model->tree_offsets[t];
    		while(1) {
        		IsoNode* node = &model->nodes[node_idx];
		        if(node->left_child == LEAF_SENTINEL) {
            			total_path += node->path_length;
            			break;
        		}
        		if(features[node->feature_index] < node->threshold) {
            			node_idx = model->tree_offsets[t] + node->left_child;
        		} else {
            			node_idx = model->tree_offsets[t] + node->right_child;
        		}
    		}	
	}

	double avg_path = total_path / model->tree_count;
	double h = log(255.0) + 0.5772156649;
	double c = 2.0 * h - (2.0 * 255.0 / 256.0);

	double anomaly_score = pow(2.0, -avg_path / c);
	return (float)anomaly_score;
}
