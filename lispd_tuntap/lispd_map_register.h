/*
 *	Send registration messages for each database mapping to
 *	configured map-servers.
 *
 *	Author: Chris White and David Meyer
 *	Copyright 2010 Cisco Systems
 */

#pragma once

#include "lispd_timers.h"

#define REGISTER_INTERVAL 60  // Seconds

void map_register(timer *t, void *arg);
