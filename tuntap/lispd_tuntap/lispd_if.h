/*
 * lispd_if.c
 *
 * Interface property change handling for lispd.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "lispd.h"
#include "lispd_config.h"
#include "lispd_packets.h"
#include "lispd_timers.h"

#define IF_MSG_SIZE 4096
#define NAT_QUICK_CHECK_TIME 5 // retry every five seconds if we are detecting NAT and haven't heard
#define NAT_PERIODIC_CHECK_TIME 60 // check for address change every minute
#define GATEWAY_DETECT_TIME 1

#define OVERRIDE_MTU 1500 // Override the mtu on any interface we are configured on.

/*
 * Different from lispd_if_t to maintain
 * linux system call compatibility.
 */
typedef struct ifaddrs {
    struct ifaddrs      *ifa_next;
    char                *ifa_name;
    unsigned int         ifa_flags;
    struct sockaddr      *ifa_addr;
    int                  ifa_index;
} ifaddrs;

typedef struct {
    struct nlmsghdr nlh;
    struct rtgenmsg  rtmsg;
} request_struct;

typedef enum {
    NATStatic,
    NATDynamic,
    NATOff
} NATType_e;


#define NAT_INCOMPLETE  0
#define NAT_HAS_ADDR    1
#define NAT_HAS_ENCAP   2
#define NAT_HAS_CONTROL 4

#define NAT_TRAVERSAL_COMPLETE 0x7

typedef struct lispd_if_t_ {
    struct lispd_if_t_ *next_if;
    char              *name;
    lisp_addr_t       address;
    lisp_addr_t       default_gw; // Gleaned from the OS
    unsigned int      dev_prio;   // Prioritize our use on this device for sourcing, routes, etc.
    NATType_e         nat_type;
    unsigned char     nat_complete;
    uint64_t          nat_request_nonce;
    lisp_addr_t       nat_address;
    uint16_t          translated_encap_port;
    unsigned int      flags;
    unsigned int      if_index;
} lispd_if_t;

int getifaddrs(ifaddrs **addrlist);
int add_lisp_interface(cfg_t *if_cfg);
int setup_eid(cfg_t *cfg);
int setup_rtnetlink(void);
lispd_if_t *get_interface_list(void);
int get_live_interface_count(void);
lispd_if_t *find_interace(char *);
lispd_if_t *get_primary_interface(void);
void reconfigure_lisp_interfaces(void);
int setup_nat(lispd_if_t *intf);
void process_interface_notification(void);
void update_map_server_routes(void);
int send_lisp_echo_request(lispd_if_t *intf);
int process_lisp_echo_reply(lispd_pkt_echo_t *pkt, uint16_t sport);
inline int is_nat_complete(lispd_if_t *intf);
int check_nat_status(timer *, void *);
int check_default_gateway(timer *, void *);
void cleanup_routes(void);





