#include "profile.h"
#include <string.h>
#include <time.h>

static void bloom_set_bit(uint8_t* bloom, uint32_t i) {
    bloom[i / 8] |= (1 << (i % 8));
}

static int bloom_get_bit(const uint8_t* bloom, uint32_t i) {
    return (bloom[i / 8] & (1 << (i % 8))) != 0;
}

void profile_bloom_add(UserProfile* profile, uint64_t hash) {
    uint32_t i1 = (uint32_t)(hash % 2048);
    uint32_t i2 = (uint32_t)((hash >> 11) % 2048);
    uint32_t i3 = (uint32_t)((hash * 2654435761UL) % 2048);
    bloom_set_bit(profile->bloom_filter, i1);
    bloom_set_bit(profile->bloom_filter, i2);
    bloom_set_bit(profile->bloom_filter, i3);
}

int profile_bloom_check(const UserProfile* profile, uint64_t hash) {
    uint32_t i1 = (uint32_t)(hash % 2048);
    uint32_t i2 = (uint32_t)((hash >> 11) % 2048);
    uint32_t i3 = (uint32_t)((hash * 2654435761UL) % 2048);
    if (!bloom_get_bit(profile->bloom_filter, i1) ||
        !bloom_get_bit(profile->bloom_filter, i2) ||
        !bloom_get_bit(profile->bloom_filter, i3)) {
         return 0;
    }
    return 1;
}

void profile_update_login(UserProfile* profile, const LoginEvent* event) {
    time_t t = (time_t)event->timestamp_unix;
    struct tm* tm_info = localtime(&t);
    double new_value = (double)tm_info->tm_hour;

    profile->login_count++;
    double delta  = new_value - profile->login_hour_mean;
    profile->login_hour_mean += delta / (double)profile->login_count;
    double delta2 = new_value - profile->login_hour_mean;
    profile->login_hour_variance += delta * delta2;

    profile_bloom_add(profile, event->device_hash);
    profile_bloom_add(profile, (uint64_t)event->geo_hash);
}

int profile_serialize(const UserProfile* profile,uint8_t* buf, uint32_t buf_size,uint32_t* written) {
    if (buf_size < sizeof(UserProfile)) {
        return -1;
    }
    memcpy(buf, profile, sizeof(UserProfile));
    *written = sizeof(UserProfile);
    return 0;
}

int profile_deserialize(UserProfile* profile, const uint8_t* buf, uint32_t buf_size) {
    if (buf_size < sizeof(UserProfile)) {
        return -1;
    }
    memcpy(profile, buf, sizeof(UserProfile));
    return 0;
}
