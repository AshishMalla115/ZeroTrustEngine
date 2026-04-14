#ifndef SCORING_H
#define SCORING_H

#include "risk_engine.h"

float compute_login_score(const LoginEvent* event, int known_device, int known_location);

#endif
