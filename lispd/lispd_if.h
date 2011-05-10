/*
 * lispd_if.c
 *
 * Interface property change handling for lispd.
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems
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

#define IF_MSG_SIZE 4096
#define NAT_QUICK_CHECK_TIME 5 // retry every five seconds if we are detecting NAT and haven't heard
#define NAT_PERIODIC_CHECK_TIME 60 // check for address change every minute
#define GATEWAY_DETECT_TIME 1

#define OVERRIDE_MTU 1400 // Override the mtu on any interface we are configured on.

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
    struct rtgenmsg rtmsg;
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
void check_nat_status(void);
void check_default_gateway(void);
void cleanup_routes(void);





