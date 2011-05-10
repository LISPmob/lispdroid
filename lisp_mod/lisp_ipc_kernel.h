/*
 * lisp_ipc_kernel.h
 *
 * Declares the kernel private structures and 
 * functions for inter-process communications.
 *
 * Copyright 2010, Cisco Systems.
 * Author: Chris White
 */

#pragma once

#include "net/ip.h"

/*
 * Function declarations
 */
void dump_message(char *msg, int length);
void send_cache_miss_notification(lisp_addr_t, short);
void send_cache_sample_notification(lisp_map_cache_t *, sample_reason_e);
void send_map_cache_list(int dstpid, uint16_t request_type,
                         char with_traffic_only);

void handle_no_action(lisp_cmd_t *cmd, int pid);
void handle_map_cache_lookup(lisp_cmd_t *cmd, int pid);
void handle_map_cache_add(lisp_cmd_t *cmd, int pid);
void handle_map_cache_list_request(lisp_cmd_t *cmd, int pid);
void handle_map_db_lookup(lisp_cmd_t *cmd, int pid);
void handle_map_db_add(lisp_cmd_t *cmd, int pid);
void handle_map_db_delete(lisp_cmd_t *cmd, int pid);
void handle_cache_sample(lisp_cmd_t *cmd, int pid);
void handle_set_rloc(lisp_cmd_t *cmd, int pid);
void handle_daemon_register(lisp_cmd_t *cmd, int pid);
void handle_traffic_mon_start(lisp_cmd_t *cmd, int pid);
void handle_set_udp_ports(lisp_cmd_t *cmd, int pid);

void lisp_netlink_input(struct sk_buff *skb);
int setup_netlink_socket(void);
void teardown_netlink_socket(void);
