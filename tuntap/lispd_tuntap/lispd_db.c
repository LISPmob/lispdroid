/*
 * lispd_db.c
 *
 * Database management routines for lispd, includes
 * local copies of the mapping database, work
 * queues, etc.
 *
 * Author: Chris White
 * Copyright 2010-2011 Cisco Systems
 */
#include "lispd.h"
#include "lispd_config.h"
#include "lispd_db.h"
#include "lispd_timers.h"

/*
 *	database and static map cache
 */
lispd_map_cache_t *lispd_map_cache	= NULL;

/*
 *	Patricia tree based databases
 */
patricia_tree_t *AF4_database           = NULL;
patricia_tree_t *AF6_database           = NULL;

/*
 * work queues and caches
 */
datacache_t	  *datacache;
rloc_probe_item_t *rp_work_q;

int db_init(void) {
    AF4_database  = New_Patricia(sizeof(struct in_addr)  * 8);
    AF6_database  = New_Patricia(sizeof(struct in6_addr) * 8);

    if (!AF4_database || !AF6_database) {
        log_msg(INFO, "malloc (database): %s", strerror(errno));
        return(FALSE);
    }
    if ((datacache = malloc(sizeof(datacache_t))) == NULL){
        log_msg(INFO, "malloc (datacache): %s", strerror(errno));
        return(FALSE);
    }
    datacache->head = NULL;
    datacache->tail = NULL;

    rp_work_q = NULL;
    return(TRUE);
}


/*
 *	make_and_lookup for network format prefix
 */
patricia_node_t *make_and_lookup_network(int afi, void *addr, int mask_len)
{
    struct in_addr	*sin;
    struct in6_addr	*sin6;
    int			 bitlen;
    prefix_t		*prefix;
    patricia_node_t	*node;

    if ((node = malloc(sizeof(patricia_node_t))) == NULL) {
        log_msg(INFO, "can't allocate patrica_node_t");
        return(NULL);
    }

    switch(afi) {
    case AF_INET:
        sin = (struct in_addr *) addr;
        if ((prefix = New_Prefix(AF_INET, sin, mask_len)) == NULL) {
            log_msg(INFO, "couldn't alocate prefix_t for AF_INET");
            return(NULL);
        }
        node = patricia_lookup(AF4_database, prefix);
        break;
    case AF_INET6:
        sin6 = (struct in6_addr *)addr;
        if ((prefix = New_Prefix(AF_INET6, sin6, mask_len)) == NULL) {
            log_msg(INFO, "couldn't alocate prefix_t for AF_INET6");
            return(NULL);
        }
        node = patricia_lookup(AF6_database, prefix);
        break;
    default:
        free(node);
        free(prefix);
        log_msg(INFO, "Unknown afi (%d) when allocating prefix_t", afi);
        return(NULL);
    }
    Deref_Prefix(prefix);
    return(node);
}

/*
 * lookup_eid_in_db
 *
 * Look up a given ipv4 eid in the database, returning true and
 * filling in the entry pointer if found, or false if not found.
 */
int lookup_eid_in_db(uint16_t eid_afi, uint32_t eid, lispd_locator_chain_t **loc_chain)
{
  patricia_node_t *result;
  prefix_t prefix;

  if (eid_afi != AF_INET) {
      log_msg(INFO, "EID AF: %d, not supported currently");
      return(FALSE);
  }

  prefix.family = AF_INET;
  prefix.bitlen = 32;
  prefix.ref_count = 0;
  prefix.add.sin.s_addr = eid;

  result = patricia_search_best(AF4_database, &prefix);
  if (!result) {
    return(FALSE);
  }

  *loc_chain = (lispd_locator_chain_t *)(result->data);

  return(TRUE);
}

/*
 * find_eid_in_datacache
 *
 */
datacache_elt_t *find_eid_in_datacache(lisp_addr_t *eid_prefix,
                          uint8_t eid_prefix_length) // probably should include type here XXX
{
    datacache_elt_t *elt;
    char addrstr2[128];
    char addrstr1[128];

    elt = datacache->head;

    while (elt) {
        if ((elt->prefix_length == eid_prefix_length)
            && (elt->eid_prefix.afi == eid_prefix->afi)) {
            if (eid_prefix->afi == AF_INET) {
                if (!memcmp(&(eid_prefix->address.ip), &(elt->eid_prefix.address.ip), 4)) {
                    inet_ntop(AF_INET, &(eid_prefix->address), addrstr1, 32);
                    inet_ntop(AF_INET, &(elt->eid_prefix.address), addrstr2, 32);
                    log_msg(INFO, " Looking for %s found %s", addrstr1, addrstr2);
                    break;
                }
            } else if (eid_prefix->afi == AF_INET6) {
                if (memcmp(eid_prefix, &(elt->eid_prefix), 16) == 0) {
                    log_msg(INFO, " v6 entry found");
                    break;
                }
            }
        }
        elt = elt->next;
        continue;
    }
    if (elt) {
        return(elt);
    } else {
        return(NULL);
    }
}

/*
 * Used by lisp_print_nonce() only.
 */
static char lisp_nonce_str[2][30];
static char lisp_nonce_str_count = 0;

/*
 * lisp_print_nonce
 *
 * Print 64-bit nonce in 0x%08x-0x%08x format.
 */
char * lisp_print_nonce (uint64_t nonce)
{
  char  *str;
  unsigned long lower;
  unsigned long upper;

  str = lisp_nonce_str[(lisp_nonce_str_count & 1)];
  lisp_nonce_str_count++;

  lower = nonce & 0xffffffff;
  upper = (nonce >> 32) & 0xffffffff;
  snprintf(str, 25, "0x%08x-0x%08x", (uint) upper, (uint) lower);
  return(str);
}

/*
 * remove_eid_from_datacache()
 *
 * Checks for a matching nonce in the data cache. If an
 * entry exists, it gets removed from the cache.
 */
int remove_eid_from_datacache(uint64_t nonce)
{
    datacache_elt_t *elt, *prev;

    elt = datacache->head;
    prev = elt;
    while (elt) {
        if (elt->nonce == nonce) {

            // At the head
            if (prev == elt) {
                datacache->head = elt->next;
                datacache->tail = datacache->head;
                free(elt);
                return(TRUE);
            }

            if (elt == datacache->tail) {
                datacache->tail = prev;
            }

            // Otherwise relink
            prev->next = elt->next;
            free(elt);
            return(TRUE);
        }

        prev = elt;
        elt = elt->next;
    }
    return(FALSE);
}

/*
 *      build_datacache_entry --
 *
 * For normal requests, the target is the requested EID.
 * For SMRs the target is the locator we are soliciting the
 * request from (and target_prefix_length is unused).
 */
int build_datacache_entry(lisp_addr_t *eid_prefix,
                       uint8_t eid_prefix_length,
                       lisp_addr_t *target,
                       uint64_t nonce,
                       request_type_e type)
{
    struct timeval   nowtime;
    datacache_elt_t *elt;

    if ((elt = malloc(sizeof(datacache_elt_t))) == NULL) {
        log_msg(INFO,
               "malloc (build_datacache_entry): %s", strerror(errno));
        return(FALSE);
    }

    memset(elt, 0, sizeof(datacache_elt_t));

    elt->nonce             = nonce;
    elt->ttl               = DEFAULT_DATA_CACHE_TTL;

    if ((type == SMR) && target) {
        memcpy(&elt->target_addr, target, sizeof(lisp_addr_t));
    }

    memcpy(&elt->eid_prefix, eid_prefix, sizeof(lisp_addr_t));
    elt->prefix_length = eid_prefix_length;
    elt->retries           = lispd_config.map_request_retries + 1;
    elt->type              = type;
    elt->next              = NULL;

    gettimeofday(&nowtime, NULL);
    elt->scheduled_to_send.tv_sec = nowtime.tv_sec + 1; // Start initial retry at one second

    /* link up the entry */
    if (datacache->tail)
        (datacache->tail)->next = elt;
    else
        datacache->head = elt;
    datacache->tail = elt;

    return(TRUE);
}

/*
 * build_rloc_probe_work_item
 *
 * Create and add a new rloc-probe item to the
 * work queue. This will be used to issue new
 * probes when the master rloc-probe timer fires.
 */
void build_rloc_probe_work_item(lisp_cache_sample_msg_t *sample)
{
    rloc_probe_item_t *item;
    int rloc_idx = 0;
    char addr_str[128];

    /*
     * Check if this EID is already in the queue, replace if so (optimization, should
     * rarely occur) XXX
     */

    item = malloc(sizeof(rloc_probe_item_t) + sizeof(rloc_probe_rloc_t) * sample->num_locators);
    if (!item) {
        log_msg(INFO, "malloc() failed for rloc-probe work item");
        return;
    }
    memset(item, 0, sizeof(rloc_probe_item_t) + sizeof(rloc_probe_rloc_t) * sample->num_locators);
    item->msg_size = sizeof(lisp_cache_sample_msg_t) +
                     sizeof(lisp_addr_t) * sample->num_locators;
    item->msg = (lisp_cache_sample_msg_t *)malloc(item->msg_size);
    if (!item->msg) {
        free(item);
        log_msg(INFO, "malloc() failed for rloc-probe work item msg");
        return;
    }
    memcpy(item->msg, sample, item->msg_size);
    memcpy(&item->eid_prefix, &sample->eid, sizeof(lisp_addr_t));
    item->eid_prefix_length = sample->eid_prefix_length;
    item->locator_count = sample->num_locators;
    item->msg->status_bits = 0;
    log_msg(INFO, "Adding rloc-probe item for EID %s", inet_ntop(item->eid_prefix.afi,
                                                                      &item->eid_prefix.address,
                                                                      addr_str, 128));
    /*
     * Copy the locators
     */
    for (rloc_idx = 0; rloc_idx < item->locator_count; rloc_idx++) {
        memcpy(&(item->locators[rloc_idx].locator), &sample->locators[rloc_idx],
               sizeof(lisp_addr_t));
        item->locators[rloc_idx].status = WaitingForProbeResponse;
        item->locators[rloc_idx].last_sent.tv_sec = 0;
        item->locators[rloc_idx].last_sent.tv_usec = 0;
        log_msg(INFO,"      locator: %s", inet_ntop(item->locators[rloc_idx].locator.afi,
                                                         &item->locators[rloc_idx].locator.address,
                                                         addr_str, 128));
    }

    /*
     * add to the list
     */
    item->next = rp_work_q;
    rp_work_q = item;
}

/*
 * delete_item_from_rp_queue()
 *
 * delete's a work queue item from the rloc probe list.
 * Returns the pointer to the item's next sibling.
 */
rloc_probe_item_t *delete_item_from_rp_queue(rloc_probe_item_t *item)
{
    rloc_probe_item_t *tmp;

    if (item == rp_work_q) {
        rp_work_q = item->next;
        free(item->msg);
        free(item);
        return(NULL);
    }

    for (tmp = rp_work_q; tmp; tmp = tmp->next) {
        if (tmp->next == item) break;
    }
    if (!tmp) {
        log_msg(INFO, "Error: attempting to delete non-existent item from rp_work_q");
        return(item->next);
    }
    tmp->next =  item->next;
    free(item->msg);
    free(item);
    return(tmp->next);
}

rloc_probe_item_t *get_rp_queue_head(void)
{
    return rp_work_q;
}

/*
 * schedule_smr()
 *
 * For each locator in the list, add an entry
 * in the map-request work queue which will eventually
 * trigger the actual SMRs.
 */
void schedule_smr(lisp_cache_sample_msg_t *msg)
{
    int i;
    char addr_buf[128];

    log_msg(INFO, "Scheduling SMR for %s/%d",
            inet_ntop(msg->eid.afi, &msg->eid.address,
                      addr_buf, 128),
            msg->eid_prefix_length);

    /*
     * Build a data cache entry (request-list queue)
     * for each address in the list. These will not
     * be sent immediately like other map-requests,
     * but will depend on the regular map-request check
     * interval timer.
     */
    for (i = 0; i < msg->num_locators; i++) {
        build_datacache_entry(&msg->eid, msg->eid_prefix_length,
                              &msg->locators[i],
                              build_nonce((unsigned int) time (NULL)),
                              SMR);
    }

    schedule_map_requests();
}
