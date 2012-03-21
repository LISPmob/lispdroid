/*
 * lispd_map_reply.c
 *
 * Handle the processing of map-replies from the mapping
 * system. Adds map cache entries if required.
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems
 */

#include "lispd.h"
#include "lispd_packets.h"
#include "lispd_netlink.h"
#include "lispd_db.h"
#include "lispd_map_reply.h"
#include "lisp_ipc.h"       // Global lisp_mod/lispd header should consolidate XXX
#include "lispd_config.h"
#include "lispd_util.h"

/*
 * build_cache_msg_eid_portion()
 *
 * Copies the information from the map reply packet to
 * EID portion of the lisp_eid_map_msg_t.
 */
int build_cache_msg_locator_portion(lisp_eid_map_msg_t *msg,
                                    lispd_pkt_map_reply_locator_record_t *loc,
                                    lispd_pkt_map_reply_eid_prefix_record_t *eid_rec,
                                    int index)
{
    lisp_eid_map_msg_loc_t *msg_loc = (lisp_eid_map_msg_loc_t *)(msg->locators + sizeof(lisp_eid_map_msg_loc_t) * index);
    memset(msg_loc, 0, sizeof(lisp_eid_map_msg_loc_t));

    msg_loc->locator.afi  =  lisp2inetafi(ntohs(loc->loc_afi));
    msg_loc->priority =  loc->priority;
    msg_loc->weight   =  loc->weight;
    msg_loc->mpriority = loc->mpriority;
    msg_loc->mweight  =  loc->mweight;

    if (ntohs(loc->loc_afi) == LISP_AFI_IP) {
        memcpy(&msg_loc->locator.address.ip.s_addr,
               loc->locator, sizeof(struct in_addr));
    } else if (ntohs(loc->loc_afi) == LISP_AFI_IPV6) {
        memcpy(&msg_loc->locator.address.ipv6.s6_addr,
               loc->locator, sizeof(struct in6_addr));
    } else {
        log_msg(INFO, "  Unknown LOC AF: %d", loc->loc_afi);
        return(FALSE);
    } // All others unknown
    return(TRUE);
}

/*
 * process_map_reply_locator()
 *
 * Process a single locator record entry in an EID record.
 */
int process_map_reply_locator_records(lisp_eid_map_msg_t *msg,
                                      lispd_pkt_map_reply_locator_record_t *records,
                                      lispd_pkt_map_reply_eid_prefix_record_t *eid_rec,
                                      int count)
{
    char addr_buf[128];
    int loc_counter;
    int addr_offset = 0;
    lispd_pkt_map_reply_locator_record_t *curr_loc;

    for (loc_counter = 0; loc_counter < count; loc_counter++) {
        curr_loc = (lispd_pkt_map_reply_locator_record_t *)((uint8_t *)records +
                  (loc_counter * sizeof(lispd_pkt_map_reply_locator_record_t)) +
                   addr_offset);
        log_msg(INFO, "    Locator: %s, AFI: %d, p: %d, w: %d, local: %d, probe: %d, reach: %d",
               inet_ntop(AF_INET, curr_loc->locator, addr_buf, 128), ntohs(curr_loc->loc_afi), curr_loc->priority,
               curr_loc->weight, curr_loc->local, curr_loc->probe, curr_loc->reachable);

        if (ntohs(curr_loc->loc_afi) == LISP_AFI_IP) {
            addr_offset += sizeof(struct in_addr);
        } else if (ntohs(curr_loc->loc_afi) == LISP_AFI_IPV6) {
            addr_offset += sizeof(struct in6_addr);
        }
        build_cache_msg_locator_portion(msg, curr_loc, eid_rec, loc_counter);
    }
    return(addr_offset);
}

/*
 * build_cache_msg_eid_portion()
 *
 * Copies the information from the map reply packet to
 * EID portion of the lisp_eid_map_msg_t.
 */
int build_cache_msg_eid_portion(lisp_eid_map_msg_t *msg, lispd_pkt_map_reply_eid_prefix_record_t *eid_rec,
                                uint16_t eid_afi, uchar *eid_prefix)
{
    memset(msg, 0, sizeof(lisp_eid_map_msg_t));

    msg->sampling_interval = lispd_config.rloc_probe_interval;

    if (eid_afi == LISP_AFI_IP) {
        memcpy(&msg->eid_prefix.address.ip.s_addr,
               eid_prefix, sizeof(struct in_addr));
    }
    else if (eid_afi == LISP_AFI_IPV6) {
        memcpy(&msg->eid_prefix.address.ipv6.s6_addr,
               eid_prefix, sizeof(struct in6_addr));
    } else {
        log_msg(INFO, "  Unknown EID AF: %d", eid_afi);
        return(FALSE);
    } // All others unknown

    msg->eid_prefix.afi = lisp2inetafi(eid_afi);
    msg->eid_prefix_length = eid_rec->eid_masklen;
    msg->count = eid_rec->loc_count;
    msg->ttl = ntohl(eid_rec->ttl);
    msg->how_learned = 1; // dynamic

    if (!msg->count) {

        // Negative cache entry
        msg->actions = eid_rec->act;
    }
    return(TRUE);
}

/*
 * add_petr_to_cache_msg
 *
 * For negative cache entries, we use the Map-server (hopefully a petr)
 * as the RLOC.
 */
lisp_eid_map_msg_t *add_petr_to_cache_msg(lisp_eid_map_msg_t *old_msg)
{
    lisp_eid_map_msg_t *new_msg;
    lisp_eid_map_msg_loc_t *msg_loc;

    new_msg = (lisp_eid_map_msg_t *)malloc(sizeof(lisp_eid_map_msg_t) +
                                                 sizeof(lisp_eid_map_msg_loc_t));
    memcpy(new_msg, old_msg, sizeof(lisp_eid_map_msg_t));

    msg_loc = (lisp_eid_map_msg_loc_t *)(new_msg->locators);
    memset(msg_loc, 0, sizeof(lisp_eid_map_msg_loc_t));

    msg_loc->locator.afi =  AF_INET;
    msg_loc->priority =  1;
    msg_loc->weight   =  100;
    msg_loc->mpriority = 1;
    msg_loc->mweight  =  100;
    new_msg->count = 1;

    /*
     * Use only the first map server for now. XXX
     */
    if (lispd_config.use_ms_as_petr) {
        msg_loc->locator.address.ip.s_addr =
                lispd_config.map_servers->address->address.ip.s_addr;
    } else {
        msg_loc->locator.address.ip.s_addr =
                lispd_config.petr_addr.address.ip.s_addr;
    }
    free(old_msg);
    return(new_msg);
}

/*
 * process_map_reply_eid_record()
 *
 * Process a single eid record entry in a map reply.
 * Individual locators are handled by lispd_process_map_reply_locator()
 */
int process_map_reply_eid_records(lispd_pkt_map_reply_eid_prefix_record_t *records, int count)
{
    int eid_counter = 0;
    int eid_addr_offset = 0;
    int eid_afi = 0;
    int total_addr_offset = 0;
    lispd_pkt_map_reply_eid_prefix_record_t *curr_eid = records;
    lisp_eid_map_msg_t *cache_msg;
    lispd_pkt_lcaf_t *lcaf;
    lispd_pkt_lcaf_addr_t *lcaf_addr;
    lispd_pkt_instance_lcaf_t *instance_lcaf;
    uchar *curr_eid_addr_ptr;
    char addr_buf[128];
    int i;

    for (eid_counter = 0; eid_counter < count; eid_counter++) {

        curr_eid = (lispd_pkt_map_reply_eid_prefix_record_t *)((uint8_t *)records +
                  (eid_counter * sizeof(lispd_pkt_map_reply_eid_prefix_record_t)) +
                   total_addr_offset); // XXX what about locator sizes? Not sure this works with > 1 eid XXX

        eid_afi = ntohs(curr_eid->eid_afi);

        log_msg(INFO, "  EID: %s/%d, ttl %u, act: %d auth: %d, locators: %d",
               inet_ntop(lisp2inetafi(eid_afi), curr_eid->eid_prefix, addr_buf, 128), curr_eid->eid_masklen,
               ntohl(curr_eid->ttl), curr_eid->act, curr_eid->authoritative, curr_eid->loc_count);

        /*
         * Are we expecting instance ID?
         */
        if (lispd_config.use_instance_id) {
            if (eid_afi != LISP_AFI_LCAF) {
                log_msg(INFO, "  expected LCAF (instance ID is configured) EID, found normal, skipping.");
                break;
            }

            lcaf = (lispd_pkt_lcaf_t *)&(curr_eid->eid_afi);
            if (ntohs(lcaf->afi) != LISP_LCAF_INSTANCE) {
                log_msg(INFO, "  unknown LCAF type %d in EID", ntohs(lcaf->afi));
                break;
            }

            instance_lcaf = (lispd_pkt_instance_lcaf_t *)lcaf->address;
            if (instance_lcaf->instance != htonl(lispd_config.instance_id)) {
                log_msg(INFO, "  instance-id %d does no match our configured id %d",
                        ntohl(instance_lcaf->instance), lispd_config.instance_id);
                break;
            }
            lcaf_addr = (lispd_pkt_lcaf_addr_t *)instance_lcaf->address;

            eid_afi = htons(lcaf_addr->afi);
            curr_eid_addr_ptr = (uchar *)&lcaf_addr->address;
            eid_addr_offset += sizeof(lispd_pkt_lcaf_t) + sizeof(lispd_pkt_lcaf_addr_t) +
                    sizeof(lispd_pkt_instance_lcaf_t); // Account for LCAF sizes. EID address sizes accounted below
        } else {
            curr_eid_addr_ptr = (uchar *)&curr_eid->eid_prefix;
        }

        if (eid_afi == LISP_AFI_IP) {
            eid_addr_offset += sizeof(struct in_addr);
        } else if (eid_afi == LISP_AFI_IPV6) {
            eid_addr_offset += sizeof(struct in6_addr);
        } else {
            log_msg(INFO, "    Unknown LISP AFI %d in EID entry, skipping", eid_afi);
            break;
        }

        // Grab a message buffer of appropriate size
        cache_msg = (lisp_eid_map_msg_t *)malloc(sizeof(lisp_eid_map_msg_t) +
                                                 curr_eid->loc_count * sizeof(lisp_eid_map_msg_loc_t));

        if (!cache_msg) {
            log_msg(INFO, "Out of memory allocating map message");
            return(FALSE);
        }

        memset(cache_msg, 0, sizeof(lisp_eid_map_msg_t) +
               curr_eid->loc_count * sizeof(lisp_eid_map_msg_loc_t));

        if (!build_cache_msg_eid_portion(cache_msg, curr_eid, eid_afi, curr_eid_addr_ptr)) {
            free(cache_msg);
            cache_msg = NULL;

            // Going to assume the rest of the map-reply is garbage
            return(FALSE);
        }

        if (!curr_eid->loc_count) {
            log_msg(INFO, "    Negative cache entry.");
            total_addr_offset += eid_addr_offset;

            if (lispd_config.use_ms_as_petr || lispd_config.petr_addr_is_set) {

                // Reallocate and write the petr as RLOC
                cache_msg = add_petr_to_cache_msg(cache_msg);
                total_addr_offset += sizeof(struct in_addr);
                log_msg(INFO, "      Using petr as RLOC");
            }
            install_map_cache_entry(cache_msg, 1);
            free(cache_msg);
            continue;
        }

        // Must account for all the variable length EID's and Locator Addresses.
        total_addr_offset += process_map_reply_locator_records(
                cache_msg,
                (lispd_pkt_map_reply_locator_record_t *)(curr_eid->eid_prefix + eid_addr_offset),
                curr_eid,
                curr_eid->loc_count) + eid_addr_offset;
        install_map_cache_entry(cache_msg, curr_eid->loc_count);
        free(cache_msg);
    }
    return(TRUE);
}

/*
 * handle_rloc_probe_reply()
 *
 * Process and take action on a map-reply containing the probe
 * bit. Look through our set of outstanding requests, and update
 * them accordingly.
 */
int handle_rloc_probe_reply(lispd_pkt_map_reply_t *pkt)
{
    rloc_probe_item_t *iterator = get_rp_queue_head();
    int rloc_idx;
    int mask = 1;
    uchar found = FALSE;
    rloc_probe_rloc_t *rloc;

    /*
     * Match the nonce
     */
    while (iterator) {

        /*
         * Search for the rloc with the right nonce
         */
        for (rloc_idx = 0; rloc_idx < iterator->locator_count; rloc_idx++) {
            rloc = &iterator->locators[rloc_idx];
            if (rloc->status == WaitingForProbeResponse) {
                if (pkt->nonce == rloc->nonce) {
                    log_msg(INFO, "  matching nonce found.");
                    found = TRUE;
                    break;
                }
            }
        }
        if (found) {
            break;
        }
        iterator = iterator->next;
    }
    if (iterator == NULL) {
        log_msg(INFO, "  no matching nonce found.");
        return(FALSE);
    } else {

        /*
         * This is a reply to our probe request. Mark it up.
         * Note: we are not examining the contents of the reply
         * here. The assumption is that the receipt of a probe-reply
         * with our nonce indicates that the RLOC is up.
         */
        rloc->status = ProbeResponseReceived;

        /*
         * Set the status bit accordingly
         */
        mask = mask << rloc_idx;
        iterator->msg->status_bits |= mask;
    }
    return(TRUE);
}


/*
 * process_map_reply()
 *
 * High-level processing of map-reply messages. Individual
 * EIDs are handled by lispd_process_map_reply_eid_record()
 */
int process_map_reply(lispd_pkt_map_reply_t *pkt)
{
    int record_count = 0;
    lispd_pkt_map_reply_eid_prefix_record_t *eid_rec;

    /*
     * Sanity
     */
    if (!(pkt->type == LISP_MAP_REPLY)) {
       log_msg(INFO, "lispd_process_map_reply: wrong type %d",
              pkt->type);
       return(FALSE);
   }

    /*
     * Process flags
     */
    if (pkt->echononce) {
        log_msg(INFO, "map-reply echo-nonce set, unsupported.");
    }

    if (pkt->probe) {
        log_msg(INFO, "map-reply probe set, checking for outstanding request.");
        if (!handle_rloc_probe_reply(pkt)) {
            log_msg(INFO, "Unsolicitied probe map-reply, ignoring");
            return(FALSE);
        }
        return(TRUE);
    } else {

        /*
         * Check for matching regular request, we should only do this after
         * process_map_reply succeeds probably... XXX
         */
        if (!remove_eid_from_datacache(pkt->nonce)) {
            log_msg(INFO, " Unable to find matching nonce in request-list.");
            return(FALSE);
        } else {
            log_msg(INFO, " Found matching request.");
        }
    }
    log_msg(INFO, "map-reply contains %d records", pkt->count);

    /*
     * Run through the entries
     */
    process_map_reply_eid_records((lispd_pkt_map_reply_eid_prefix_record_t *)pkt->records,
                                       pkt->count);
    return(TRUE);
}

/*
 * build_map_reply()
 *
 * Create the response packet given a locator chain and
 * destination address.
 */
lispd_pkt_map_reply_t *build_map_reply(uint32_t probe_source, int probe,
                                       lispd_locator_chain_t *loc_chain,
                                       char *nonce,
                                       int *len)
{
    lispd_pkt_map_reply_t     *reply_pkt;
    lispd_pkt_map_reply_eid_prefix_record_t *eid_rec;
    lispd_pkt_map_reply_locator_record_t *loc_rec;
    lisp_addr_t               loc_addr;
    lispd_locator_chain_elt_t *locator_chain_elt;
    lispd_if_t                *intf;
    int                        total_loc_length   = 0;
    int                        eid_afi           = 0;
    int                        pkt_length        = 0;
    int                        addr_len          = 0;
    int                        afi_len           = 0;
    int                        loc_count         = 0;
    int                        loc_afi           = 0;

    /*
     * Like in map registers, assume one record with
     * several locators.
     */
    locator_chain_elt = loc_chain->head;
    total_loc_length = get_locator_length_and_count(locator_chain_elt, &loc_count);

    eid_afi = get_lisp_afi(loc_chain->eid_prefix.afi, &afi_len);

    pkt_length = sizeof(lispd_pkt_map_reply_t) +
                 sizeof(lispd_pkt_map_reply_eid_prefix_record_t) +  // XXX Just one for now
                 afi_len +
                 (loc_count *
                  sizeof(lispd_pkt_map_reply_locator_record_t)) +
                 total_loc_length;

    if ((reply_pkt = (lispd_pkt_map_reply_t *)malloc(pkt_length)) == NULL) {
        log_msg(INFO, "malloc (map-reply packet): %s", strerror(errno));
        return NULL;
    }

    memset(reply_pkt, 0, pkt_length);

    reply_pkt->type = LISP_MAP_REPLY;
    reply_pkt->probe = probe;
    reply_pkt->echononce = 0;
    reply_pkt->count = 1;

    memcpy(&reply_pkt->nonce, nonce, sizeof(uint64_t));

    eid_rec = (lispd_pkt_map_reply_eid_prefix_record_t *)CO(reply_pkt,
                                                            sizeof(lispd_pkt_map_reply_t));

    eid_rec->act = 0;
    eid_rec->authoritative = 1;
    eid_rec->loc_count = loc_count;
    eid_rec->eid_afi = htons(eid_afi);
    eid_rec->eid_masklen = loc_chain->eid_prefix_length;
    eid_rec->ttl = htonl(DEFAULT_MAP_REGISTER_TIMEOUT); // Should be different for Map-replies?
    eid_rec->version = 0;

    /*
     * Advance to the prefix
     */
    if ((addr_len = copy_addr((void *)CO(eid_rec, sizeof(lispd_pkt_map_reply_eid_prefix_record_t)),
                              &(loc_chain->eid_prefix),
                              loc_chain->eid_prefix.afi,
                              0)) == 0) {
        log_msg(INFO, "eid prefix (%s) has an unknown afi (%d)",
               loc_chain->eid_name,
               loc_chain->eid_prefix.afi);
        return NULL;
    }

    /*
     * skip over the fixed part and eid prefix, and build
     * the locators
     */
    loc_rec = (lispd_pkt_mapping_record_locator_t *)
        CO(eid_rec,(sizeof(lispd_pkt_mapping_record_t) + addr_len));

    while (locator_chain_elt) {

        intf = locator_chain_elt->interface;

        /*
         * Check interface status and get the address
         */
        if (intf && (intf->flags & IFF_UP)) {
            if (intf->nat_type != NATOff) {
                if (is_nat_complete(intf)) { // Skip untranslated NAT interfaces
                    memcpy(&loc_addr, &intf->nat_address.address.ip.s_addr, sizeof(lisp_addr_t));
                } else {
                    locator_chain_elt = locator_chain_elt->next;
                    continue;
                }
            } else if (intf->address.address.ip.s_addr != 0) {  // IPV4 only and local interface only XXX
                memcpy(&loc_addr, &intf->address, sizeof(lisp_addr_t));
            } else {
                locator_chain_elt = locator_chain_elt->next;
                continue; // No address? Not included.
            }
        } else {
            locator_chain_elt = locator_chain_elt->next;
            continue;
        } // Need to handle non-local locators XXX

        loc_rec->priority    = locator_chain_elt->priority;
        loc_rec->weight      = locator_chain_elt->weight;
        loc_rec->mpriority   = locator_chain_elt->mpriority;
        loc_rec->mweight     = locator_chain_elt->mweight;
        loc_rec->reachable   = 1;
        loc_rec->probe       = probe;
        loc_rec->local       = 1;
        if (intf) {
            loc_afi = intf->address.afi;
        } else {
            loc_afi = locator_chain_elt->locator_afi;
        }
        loc_rec->loc_afi = htons(get_lisp_afi(loc_afi, NULL));

        /*
         * skip over the mapping record locator, and copy the locator
         * to that address...
         */
        if ((addr_len = copy_addr((void *)
                             CO(loc_rec,
                                sizeof(lispd_pkt_mapping_record_locator_t)),
                             &(loc_addr),
                             loc_afi,
                             0)) == 0) {
            log_msg(INFO, "locator (%s) has an unknown afi (%d)",
                   locator_chain_elt->locator_name,
                   locator_chain_elt->locator_afi);
            return NULL;
        }

        /*
         * get the next locator in the chain and wind
         * loc_rec to the right place
         */
        loc_rec = (lispd_pkt_mapping_record_locator_t *)
            CO(loc_rec, (sizeof(lispd_pkt_mapping_record_locator_t) + addr_len));

        locator_chain_elt = locator_chain_elt->next;
    }
    *len = pkt_length;
    return reply_pkt;
}

/*
 * send_map_reply()
 *
 * Send a map-reply to a querier.
 */
void send_map_reply(lispd_pkt_map_request_t *pkt,
                    struct sockaddr_in *source)
{
    lispd_pkt_map_request_eid_prefix_record_t *rec;
    lispd_pkt_map_request_itr_rloc_t *itr_rloc;
    lispd_locator_chain_t *loc_chain;
    lispd_pkt_map_reply_t *reply_pkt;
    struct ip *iphdr;
    struct udphdr *udphdr;
    lisp_addr_t eid_prefix;
    struct sockaddr_in dst;
    lispd_if_t *oif = get_primary_interface();
    char addr_buf[128];
    char *ptr;
    int offset, i, s, len, nbytes, udp_len;

    if (!oif) {
        log_msg(INFO, "No interfaces are available to source reply");
        return;
    }

    /*
     * Figure out what they are asking for, need to advance past
     * all the ITR-RLOCs in the packet. Sigh.
     */
    offset = sizeof(lispd_pkt_map_request_t);

    if (pkt->source_eid_afi != 0) {
        if (lisp2inetafi(ntohs(pkt->source_eid_afi)) == AF_INET) {
            offset += sizeof(struct in_addr);
        } else {
            offset += sizeof(struct in6_addr);
        }
    }

    itr_rloc = CO(pkt, offset);
    for (i = 0; i < pkt->additional_itr_rloc_count + 1; i++) {
        offset += sizeof(lispd_pkt_map_request_itr_rloc_t);
        if (lisp2inetafi(ntohs(itr_rloc->afi)) == AF_INET) {
            offset += sizeof(struct in_addr);
        } else {
            offset += sizeof(struct in6_addr);
        }
        itr_rloc = CO(pkt, offset);
    }

    rec = (lispd_pkt_map_request_eid_prefix_record_t *)CO(pkt, offset);
    ptr = CO(rec, sizeof(lispd_pkt_map_request_eid_prefix_record_t));
    memcpy(&eid_prefix.address.ip, ptr, sizeof(struct in_addr));

    if (lisp2inetafi(ntohs(rec->eid_prefix_afi)) != AF_INET) {
        log_msg(INFO, "     AF: %d unsupported currently.",
               lisp2inetafi(ntohs(rec->eid_prefix_afi)));
        return;
    }

    log_msg(INFO, " Request for EID: %s/%d", inet_ntop(AF_INET, &eid_prefix.address.ip.s_addr,
                                                          addr_buf, 128),
           rec->eid_prefix_mask_length);

    /*
     * Lookup in our local database
     */
    if (!lookup_eid_in_db(lisp2inetafi(ntohs(rec->eid_prefix_afi)),
                          eid_prefix.address.ip.s_addr, &loc_chain)) {
        log_msg(INFO, "   Unable to find entry in local database.");
        return;
    } else {
        log_msg(INFO, "   Found entry, building reply.");
    }

    reply_pkt = build_map_reply(source->sin_addr.s_addr, pkt->rloc_probe,
                                loc_chain, &pkt->nonce, &len);

    if (!reply_pkt) {
        log_msg(INFO,
               "Failed to build map reply");
        return;
    }

    /*
     * Build the outer IP header ourselves, this doesn't
     * go using LISP, so we don't want the EID used as the source.
     */
    iphdr = malloc(len + sizeof(struct ip) + sizeof(struct udphdr));
    udphdr = CO(iphdr, sizeof(struct ip));
    ptr = CO(udphdr, sizeof(struct udphdr));
    memcpy(ptr, (char *)reply_pkt, len);
    free(reply_pkt);

    udp_len = len + sizeof(struct udphdr);

    /*
     * AF_INET for now XXX
     */
    iphdr->ip_hl = 5;
    iphdr->ip_v = IPVERSION;
    iphdr->ip_tos        = 0;
    iphdr->ip_len        = htons(udp_len + sizeof(struct ip));
    iphdr->ip_id         = htons(54321);
    iphdr->ip_off        = 0;
    iphdr->ip_ttl        = 255;
    iphdr->ip_p          = IPPROTO_UDP;
    iphdr->ip_sum        = 0; // Raw socket handler does this for us.

    iphdr->ip_src.s_addr = oif->address.address.ip.s_addr; /// XXX Huh?
    iphdr->ip_dst.s_addr = source->sin_addr.s_addr;

    udphdr->source = htons(LISP_CONTROL_PORT);
    udphdr->dest = source->sin_port;
    udphdr->len = htons(udp_len);
    udphdr->check = 0;
    udphdr->check = udp_checksum(udphdr, udp_len, iphdr, AF_INET);

    /* XXX: assumes v4 transport */
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        log_msg(INFO, "socket (send_map_request): %s", strerror(errno));
        return;
    }

    memset((char *) &dst, 0, sizeof(dst));

    dst.sin_family      = AF_INET;	/* XXX: assume v4 transport */
    dst.sin_addr.s_addr = source->sin_addr.s_addr;

    if ((nbytes = sendto(s,
                         (const void *)iphdr,
                         len + sizeof(struct ip) + sizeof(struct udphdr),
                         0,
                         (struct sockaddr *)&dst,
                         sizeof(struct sockaddr))) < 0) {
        log_msg(INFO, "sendto (send_map_request): %s", strerror(errno));
        return;
    }

    if (nbytes != (len + sizeof(struct udphdr) + sizeof(struct ip))) {
        log_msg(INFO,
               "send_map_request: nbytes (%d) != packet_len (%d)\n",
               nbytes, len);
        return;
    }
#ifdef DEBUG_PACKETS
    dump_message(iphdr, len + sizeof(struct ip) + sizeof(struct udphdr));
#endif
    close(s);
    free(iphdr);
    return;
}

