/*
 *	Send registration messages for each database mapping to
 *	configured map-servers.
 *
 *	Author: Chris White and David Meyer
 *	Copyright 2010 Cisco Systems
 */

#pragma once

#define REGISTER_INTERVAL 60  // Seconds

int map_register(void);
