/*
 * lispd_db.h
 *
 * Database management routines for lispd, includes
 * local copies of the mapping database, map-cache, etc.
 */

#pragma once

#include <time.h>
#include "patricia/patricia.h"
#include "lispd_if.h"
#include "lispd_ipc.h"
#include "lispd_map_request.h"

/*
 * RLOC probe work items and subitems
 */

typedef enum {
    WaitingForProbeResponse,
    ProbeResponseReceived,
    ProbedDown
} rloc_status_e;

typedef struct rloc_probe_rloc_t_ {
    lisp_addr_t    locator;
    rloc_status_e  status;
    uint64_t       nonce;
    struct timeval last_sent;
    int            probes_sent;
} rloc_probe_rloc_t;

typedef struct rloc_probe_item_t_ {
    lisp_addr_t eid_prefix;
    uint8_t     eid_prefix_length;
    uint8_t     locator_count;
    lisp_cache_sample_msg_t   *msg;
    int         msg_size;
    struct rloc_probe_item_t_ *next;
    rloc_probe_rloc_t locators[0];
} rloc_probe_item_t;

/*
 *  Data cache
 */
typedef struct datacache_elt_t_ {
    uint64_t	            nonce;
    uint8_t	            ttl;
    lisp_addr_t             eid_prefix;
    uint8_t	            prefix_length;
    lisp_addr_t             target_addr;
    uint8_t                 retries;
    struct timeval          last_sent;
    struct timeval          scheduled_to_send;
    request_type_e          type;
    struct datacache_elt_t_ *next;
} datacache_elt_t;

typedef struct datacache_t_ {
    datacache_elt_t *head;
    datacache_elt_t *tail;
} datacache_t;

// Unused currently. XXX
typedef struct {
    lisp_addr_t     eid_prefix;
    uint8_t         eid_prefix_length;
    lisp_addr_t     locator;
    char *	    locator_name;
    uint16_t        locator_afi;
    uint8_t         locator_type:2;
    uint8_t         negative:1;
    uint8_t	    reserved:4;
    uint8_t	    how_learned:1;	/* 1 --> static */
    uint8_t         priority;
    uint8_t         weight;
    uint8_t         mpriority;
    uint8_t         mweight;
    uint32_t	    ttl;
} lispd_map_cache_entry_t;

/*
 *	map-cache, static or otherwise
 */
typedef struct _lispd_map_cache_t {
    lispd_map_cache_entry_t	map_cache_entry;
    struct _lispd_map_cache_t	*next;
} lispd_map_cache_t;

/*
 *	new lisp database layout
 *
 *
 *  lispd_database {AF4_database,AF6_database}
 *    |
 *    | try_search_exact(AFn_database, AF_n, prefix/len);
 *    |
 *    v
 * patricia_node_t   patricia_node_t ...   patricia_node_t
 *    |                  |                        |
 *    |  data            | data                   | data  data contains a
 *    |                  |                        |       locator_chain_t
 *    |                  v                        v       per afi eid/n
 *    v             tail
 * locator_chain_t--------------------------------------+
 *    |                                                 |
 *    | head                                            |
 *    |                                                 |
 *    v                 next                      next  v
 *  locator_chain_elt_t ----> locator_chain_elt_t ----> ....
 *    |                       |
 *    | locator               | locator
 *    |                       |
 *    +--> loc_entry_t        +--> loc_entry_t
 */

/*
 *	locator_types
 */
#define	STATIC_LOCATOR			0
#define	DYNAMIC_LOCATOR			1
#define	FQDN_LOCATOR			2

/*
 * lispd locator entry. These are not shared
 * by chains (currently), but they do share
 * interface pointers, if applicable.
 */
typedef struct lispd_locator_chain_elt_t_ {
    lispd_if_t     *interface;     // If locally owned, this is non-NULL
    lisp_addr_t     locator_addr;
    uint16_t        locator_afi;  // *Only* for non-local locators
    uint8_t         locator_type:2;
    uint8_t	    reserved:6;
    char *	    locator_name;
    uint8_t         priority;
    uint8_t         weight;
    uint8_t         mpriority;
    uint8_t         mweight;
   struct lispd_locator_chain_elt_t_ *next;
} lispd_locator_chain_elt_t;

typedef struct {			/* chain per eid-prefix/len/afi */
    int		mrp_len;		/* map register packet length */
    uint32_t	timer;			/* send map_register w timer expires */
    uint16_t	locator_count;		/* number of mappings, 1 locator/per */
    lisp_addr_t eid_prefix;		/* eid_prefix for this chain */
    uint8_t	eid_prefix_length;	/* eid_prefix_length for this chain */
    char	*eid_name;		/* eid_prefix_afi for this chain */
    uint8_t	has_dynamic_locators:1;	/* append dynamic/fqdn to front */
    uint8_t	has_fqdn_locators:1;
    uint8_t	reserved:6;
    lispd_locator_chain_elt_t *head;	/* first entry in chain */
    lispd_locator_chain_elt_t *tail;	/* last entry in chain */
} lispd_locator_chain_t;

extern lispd_map_cache_t *lispd_map_cache;
extern patricia_tree_t   *AF4_database;
extern patricia_tree_t   *AF6_database;
extern datacache_t       *datacache;

int db_init(void);
int lookup_eid_in_db(uint16_t eid_afi, uint32_t eid, lispd_locator_chain_t **entry);
patricia_node_t *make_and_lookup(patricia_tree_t *tree,
                                 int afi, char *string);
int build_datacache_entry(lisp_addr_t *eid_prefix,
                       uint8_t eid_prefix_length,
                       lisp_addr_t *target,
                       uint64_t nonce,
                       request_type_e type);
void schedule_smr(lisp_cache_sample_msg_t *);
datacache_elt_t *find_eid_in_datacache(lisp_addr_t *eid_prefix,
                          uint8_t eid_prefix_length);
int remove_eid_from_datacache(uint64_t);
void build_rloc_probe_work_item(lisp_cache_sample_msg_t *sample);
rloc_probe_item_t *delete_item_from_rp_queue(rloc_probe_item_t *item);
rloc_probe_item_t *get_rp_queue_head(void);


