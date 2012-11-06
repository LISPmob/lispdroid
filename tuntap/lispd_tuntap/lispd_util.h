/*
 * lispd_util.h
 *
 * Declaration of various miscellaneous utility functions
 * for lispd.
 */

#pragma once

#include <signal.h>
#include <time.h>
#include "lispd.h"
#include "lispd_db.h"

int get_afi(char *str);
int get_lisp_afi(int afi, uint32_t *len);
int lisp2inetafi(int afi);
int get_addr_len(int afi);
int get_ip_header_len(int afi);
char *prefix_toa(prefix_t *prefix);
int setbit(int word, char bit);
int clearbit(int word, char bit);

struct udphdr *build_ip_header(void *cur_ptr, lisp_addr_t *src,
                               lisp_addr_t *dest, int ip_len);
uint64_t build_nonce(int seed);
char *encode_eid_for_map_record(char *dest, lisp_addr_t eid, uint16_t eid_afi, int eid_afi_len);

void setup_loopback_route(void);
int copy_lisp_addr_t(lisp_addr_t *a1, lisp_addr_t *a2, uint16_t afi, int convert);
int copy_addr(void *a1, lisp_addr_t *a2, int afi, int convert);
lisp_addr_t *get_my_addr(char *if_name, int afi);
lisp_addr_t *lispd_get_address(char *host, lisp_addr_t *addr, uint32_t *flags);
int isfqdn(char *s);

/*
 * Debug routines
 */
int  dump_database(patricia_tree_t *tree, int afi, FILE *fp);
void dump_database_entry(lispd_locator_chain_t *locator_chain, lispd_locator_chain_elt_t *db_entry, FILE *fp);
void dump_interfaces(FILE *fp);
void dump_map_resolvers(void);
void dump_map_servers(void);
void dump_map_server(lispd_map_server_list_t *ms);
void dump_map_cache(void);
void dump_tree_elt(lispd_locator_chain_t *locator_chain);
void dump_tree(int afi, patricia_tree_t *tree);
void dump_message(char *msg, int length);
void debug_installed_database_entry(lispd_locator_chain_t *locator_chain,
                                    lispd_locator_chain_elt_t *db_entry);
void print_hmac(uchar *hmac, int len);
void print_nonce (uint64_t nonce);








