/*
 *	lispd_netlink.h
 *
 *	Kernel IPC support for lispd
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

#include "lispd_db.h"
#include "lispd_timers.h"

int process_kernel_msg(void);
int setup_netlink(void);
int send_command(lisp_cmd_t *cmd, int length);
int register_lispd_process(void);
int install_map_cache_entry(lisp_eid_map_msg_t *map_msg, int loc_count);
int map_cache_entry_exists(lisp_addr_t eid_prefix, int prefix_length);
int install_database_mapping(lispd_locator_chain_t *chain);
int install_database_mappings(void);
int set_udp_ports(void);
int update_locator_status(rloc_probe_item_t *item);
void clear_map_cache(void);
int start_smr_traffic_monitor(timer *, void *);
void handle_cache_miss(lisp_addr_t eid);

