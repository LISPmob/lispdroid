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
#include "lispd_if.h"
#include "packettypes.h"
#include <netinet/udp.h>
#include <netinet/ip.h>

#define TUNTAP

#define TUN_OVERRIDE_MTU (OVERRIDE_MTU - 100)

extern int tun_receive_fd;
void tuntap_process_input_packet(char *packet_buf, int length, void *source);
void tuntap_process_output_packet(void);
int delete_default_route_v4 (lispd_if_t *intf);
