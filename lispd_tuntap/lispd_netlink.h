/*
 *	lispd_kernel.h
 *
 *	Kernel IPC suport for the lispd
 *
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 22 10:29:27 2010
 *
 *	$Header: $
 *
 */

#include "lispd_db.h"
#include "lisp_ipc.h"
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
void start_smr_traffic_monitor(timer *, void *);
