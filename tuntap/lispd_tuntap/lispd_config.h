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
    char                     use_dns_override;
    lisp_addr_t              petr_addr;
    lisp_addr_t              eid_address_v4;  /* AF of 0 means unset */
    lisp_addr_t              eid_address_v6;  /* ""                  */
    lisp_addr_t              dns_override_address1; /* Alternate DNS server for when LISP is running */
    lisp_addr_t              dns_override_address2; /* "" */
    lisp_addr_t              original_dns_address1; /* For restoration */
    lisp_addr_t              original_dns_address2; /* "" */
    unsigned int             instance_id;
    char                     use_instance_id;
    char                     use_location;
    unsigned int             tun_mtu;         /* MTU Override for TUN/TAP */
} lispd_config_t;

extern lispd_config_t lispd_config;

int add_database_mapping(cfg_t	*dm);
int add_static_map_cache_entry(cfg_t *smc);
int handle_lispd_command_line(int argc, char **argv);
int handle_lispd_config_file(void);
int add_map_resolver(char *map_resolver);
int add_map_server(char *map_server, int key_type, char *key, uint8_t proxy_reply, uint8_t verify);
int set_kernel_rloc(lisp_addr_t *addr);
int set_dns_override(char *dns_server1, char *dns_server2);
int set_instance_id(char *instance_str);
int restore_dns_servers(void);

