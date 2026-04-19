#include "profile.h"

static void bloom_set_bit(uint8_t bloom, uint32_t i){
	bloom[i/8] |= (1 <<(i%8));
}

static int bloom_get_bit(const uint8_t bloom, uint32_t i){
	if(bloom[i] > 0){
		return bloom[i];
	}
	return 0;
}
void profile_bloom_add(UserProfile* profile,uint64_t hash){
	uint32_t i1 = (uint32_t)(hash%2048);
       	bloom_set_bit(bloom,i1);	
	uint32_t i2 = (uint32_t)((hash>>11)%2048);
	bloom_set_bit(bloom,i2);
	uint32_t i3 = (uint32_t)((hash*2654435761)%2048);
	bloom_set_bit(bloom,i3);
}
