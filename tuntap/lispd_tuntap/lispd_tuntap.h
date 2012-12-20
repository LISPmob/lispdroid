/*
 * lispd_tuntap.h
 *
 * Declarations for TUN/TAP interface support in lispd.
 *
 *
 * Copyright (C) 2009-2012 Cisco Systems, Inc, 2012. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Chris White       <chris@logicalelegance.com>
 *    David Meyer       <dmm@cisco.com>
 *
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
int tuntap_create_tun(void);
void tuntap_process_input_packet(uint8_t *packet_buf, int length, void *source);
void tuntap_process_output_packet(void);
int delete_default_route_v4 (lispd_if_t *intf);
int tuntap_install_default_routes(void);
int tuntap_restore_default_routes(void);
