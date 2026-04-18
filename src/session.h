#include "risk_engine.h"
#define	SESSION_BUFFER_SIZE 16

typedef struct{
	SessionEvent events[SESSION_BUFFER_SIZE];
	uint32_t head; 
	uint32_t count;
	uint64_t session_id;
	float last_score;
	int64_t last_event_time;
}SessionBuffer;

void session_buffer_init(SessionBuffer* buf, uint64_t session_id); 
void session_buffer_push(SessionBuffer* buf,const SessionEvent* event);
float session_compute_velocity(const SessionBuffer* buf,float current_score,int64_t current_time);


