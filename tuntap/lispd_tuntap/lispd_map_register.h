/*
 *	Send registration messages for each database mapping to
 *	configured map-servers.
 *
 *	Author: Chris White and David Meyer
 *	Copyright 2010 Cisco Systems
 */

#pragma once

#include "lispd_timers.h"
#include "lispd_db.h"

#define REGISTER_INTERVAL 60  // Seconds

int map_register(timer *t, void *arg);
int get_locator_length_and_count(lispd_locator_chain_elt_t *locator_chain_elt, uint32_t *loc_count);

