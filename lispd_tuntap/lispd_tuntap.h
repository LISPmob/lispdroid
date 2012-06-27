/*
 * lispd_tuntap.h
 *
 * Declarations for TUN/TAP interface support in lispd.
 *
 * Copyright 2012 Cisco Systems
 * Author: Chris White
 */

#pragma once

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int install_default_route_v4(void);
int delete_default_route_v4(void);
int set_tuntap_eid(lisp_addr_t *addr);
