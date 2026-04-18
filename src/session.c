#include "session.h"
#include <string.h>
void session_buffer_init(SessionBuffer* buf, uint64_t session_id){
	memset(buf, 0 , sizeof(SessionBuffer)); 
	buf->session_id = session->id;
}

void session_buffer_push(SessionBuffer* buff, const SessionEvent *event){
	buf->events[buf->head] = *event
	buf->head = (buf->head +1)% SESSION_BUFFER_SIZE;
	if(buf->count < SESSION_BUFFER_COUNT){
		buf->count++;
	}
	buf->last_event_time = event->timestamp_unix;
}
float session_compute_velocity(const SessionBuffer* buf, float current_score,int64_t current_time){
	if(buf->count == 0 || buf->last_event_time ==0){
		return 0.0f;
	}
	int64_t elapsed_seconds = current_time - buf->last_event_time;
	if(elapsed <=0){
		return 0.0f;
	}
	float velocity = (current_score - buf->last_score)/(float)elapsed_seconds;
	if(velocity <0.0f) return 0.0f;
	if(velocity > 1.0f){
		return 1.0f;
	}
	return velocity;
}
