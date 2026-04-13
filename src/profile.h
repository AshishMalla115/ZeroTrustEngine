#ifndef PROFILE_H
#define PROFILE_H

#include "risk_engine.h"

void profile_update_login(UserProfile* profile, const LoginEvent* event);
void profile_bloom_add(UserProfile* profile, uint64_t hash);
int  profile_bloom_check(const UserProfile* profile, uint64_t hash);

int  profile_serialize(const UserProfile* profile, uint8_t* buf, uint32_t buf_size, uint32_t* written);
int  profile_deserialize(UserProfile* profile,const uint8_t* buf, uint32_t buf_size);

#endif
