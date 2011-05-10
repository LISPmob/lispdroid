/*
 * lispd_config.h
 *
 * Configuration parameters and functions to manipulate them
 * for the lispd process.
 */

#pragma once

#include "cmdline.h"
#include "confuse/src/confuse.h"
#include "lispd.h"

#define DEFAULT_PROBE_INTERVAL 0
#define DEFAULT_PROBE_RETRIES 3

typedef	struct _lispd_map_server_list_t {
    lisp_addr_t	            *address;
    uint8_t		            key_type;
    char	 	            *key;
    uint8_t			    proxy_reply;
    uint8_t			    verify;
    struct _lispd_map_server_list_t *next;
} lispd_map_server_list_t;

typedef struct {
    lispd_addr_list_t *map_resolvers;
    lispd_map_server_list_t *map_servers;
    char		    *config_file;
    char                    *map_resolver_name;
    char		    *map_server_name;
    char                     map_request_retries;
    uint16_t                 local_control_port; // For receiving
    uint16_t	             control_port;       // For sending
    uint16_t                 data_port;          // For sending
    uint16_t                 local_data_port;    // For receiving
    uint16_t                 translated_control_port;
    char                     use_nat_lcaf;       // Convey port we want to use in LISP echoes using LCAF
    char                     debug;
    char                     daemonize;
    char                     use_ms_as_petr;
    char                     petr_addr_is_set;
    int                      rloc_probe_interval; /* 0 means do not RLOC-probe */
    char                     rloc_probe_retries;
    lisp_addr_t              petr_addr;
    char                    *eid_interface;
    lisp_addr_t             eid_address;
} lispd_config_t;

extern lispd_config_t lispd_config;

int add_database_mapping(cfg_t	*dm);
int add_static_map_cache_entry(cfg_t *smc);
int handle_lispd_command_line(int argc, char **argv);
int handle_lispd_config_file(void);
int add_map_resolver(char *map_resolver);
int add_map_server(char *map_server, int key_type, char *key, uint8_t proxy_reply, uint8_t verify);
int set_kernel_rloc(lisp_addr_t *addr);


