#include "risk_engine.h"
#include <time.h>

float score_time_of_day(int64_t timestamp_unix){
	time_t t = (time_t)timestamp_unix;
	struct tm* tm_info = localtime(&t);
	int hour = tm_info->tm_hour;
	if(hour>= 9 && hour<= 18){
		return 0.0f;
	}if(hour>= 18 && hour<= 22){
                return 0.3f;
        }if(hour>= 22 || hour< 6){
                return 1.0f;
        }if(hour>= 6 && hour<= 9){
                return 0.5f;
        }
	return 0.5f;
}
float score_failed_attempts(uint8_t failed_attempts){
	if(failed_attempts >= 5){
		return 1.0f;
	}if(failed_attempts >= 3){
		return 0.7f;
	}if(failed_attempts >=1){
		return 0.3f;
	}
	return 0.0f;
}
float score_new_device(uint64_t device_hash){
	return 1.0f;
}
float score_new_location(uint32_t geo_hash){
	return 0.5f;
}

float compute_login_score(const LoginEvent* event, int known_device, int known_location){
	float sum = 0.0f; 
	sum = sum + score_time_of_day(event->timestamp_unix)*0.25f;
       	sum = sum + score_failed_attempts(event->failed_attempts)*0.30f;
	sum += (known_device ? 0.0f : 1.0f)*0.25f;
	sum += (known_location ? 0.0f : 0.5f)*0.20f;
	if(sum < 0.0f){
		return 0.0f;
	}
	if(sum > 1.0f){
		return 1.0f;
	}
	return sum;	
}

float score_event_type(EventType type){
	switch(type){
		case LOGIN:		return 0.1f;
		case API_CALL:		return 0.0f;
		case FILE_DOWNLOAD:	return 0.2f; 
		case DATA_EXPORT:	return 0.5f;
		case PASSWORD_CHANGE:	return 0.3f;
		case ADMIN_ACTION:	return 0.4f;
		case FAILED_AUTH:	return 0.6f; 
		default:		return 0.1f;		
	}
}
<<<<<<< HEAD
=======

void build_feature_vector(const LoginEvent* event,const UserProfile* profile,float* features) {
	time_t t = (time_t)event->timestamp_unix;	   
	struct tm* tm_info = localtime(&t);
    	features[0] = (float)tm_info->tm_hour / 23.0f;
    	features[1] = (float)event->failed_attempts / 10.0f;
    	features[2] = (float)(event->device_hash % 1000) / 1000.0f;
    	features[3] = (float)(event->geo_hash % 1000) / 1000.0f;
    	features[4] = (float)(event->ip_hash % 1000) / 1000.0f;
    	features[5] = (float)(profile->login_count) / 100.0f;
}
>>>>>>> main
