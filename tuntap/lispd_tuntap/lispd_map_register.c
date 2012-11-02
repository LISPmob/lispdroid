/*
 *	Send registration messages for each database mapping to
 *	configured map-servers.
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *      Tue May 4 02:21:25 PDT 2010
 *	
 */

#include <signal.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "lispd_packets.h"
#include "lispd_config.h"
#include "lispd_db.h"
#include "lispd_util.h"
#include "lispd_map_request.h"
#include "lispd_map_register.h"
#include "lispd_timers.h"

extern int v4_receive_fd;

timer *map_register_timer = NULL;

/*
 *	get_locator_length
 *
 *	Compute the sum of the lengths of the locators
 *	in the chain so we can allocate a chunk of memory for
 *	the packet. Also return the count for inclusion in the packet.
 */
int get_locator_length_and_count(lispd_locator_chain_elt_t *locator_chain_elt, uint32_t *loc_count)
{
    int sum = 0;
    int count = 0;
    uint16_t afi;

    while (locator_chain_elt) {

        /*
         * Active interfaces only
         */
        if (!locator_chain_elt->interface || !(locator_chain_elt->interface->flags & IFF_UP)) {
            locator_chain_elt = locator_chain_elt->next;
            continue;
        } // Need to handle non-local locators XXX

        afi = locator_chain_elt->interface->address.afi;
        switch(afi) {
        case AF_INET:
            sum += sizeof(struct in_addr);
            count++;
            break;
        case AF_INET6:
            count++;
            sum += sizeof(struct in6_addr);
            break;
        default:
            log_msg(INFO, "Unknown AFI (%d) for %s",
                   afi,
                   locator_chain_elt->locator_name);
        }
        locator_chain_elt = locator_chain_elt->next;
    }
    *loc_count = count;

    /*
     * Account for the overhead of the NAT LCAF
     * address format, if configured
     */
    if (lispd_config.use_nat_lcaf) {

        // AFI is double counted in the locator_t and lcaf_t, hence
        // the subtract.
        sum += (count * (sizeof(lispd_pkt_nat_lcaf_t) + 3 * sizeof(lispd_pkt_lcaf_addr_t) +
                               (sizeof(lispd_pkt_lcaf_t) - sizeof(uint16_t))));
    }
    return(sum);
}

/*
 *	send_map_register
 *
 *	Assumes IPv4 transport for map-registers
 *
 */
int send_map_register(lispd_map_server_list_t  *ms,
                      lispd_pkt_map_register_t *mrp,
                      int	                mrp_len)
{

    lisp_addr_t        *addr;
    struct sockaddr_in   map_server;
    int			nbytes;
    unsigned  int	md_len;

    /*
     * Fill in proxy_reply and compute the HMAC with SHA-1. Have to
     * do this here since we need to know which map-server (since it
     * has the proxy_reply bit)
     *
     */
    mrp->proxy_reply = ms->proxy_reply;
    memset(mrp->auth_data, 0, LISP_SHA1_AUTH_DATA_LEN);	/* make sure */

    if (!HMAC((const EVP_MD *) EVP_sha1(),
              (const void *) ms->key,
              strlen(ms->key),
              (uchar *) mrp,
              mrp_len,
              (uchar *) mrp->auth_data,
              &md_len)) {
        log_msg(INFO, "HMAC failed for map-register");
        free(mrp);
        return(0);
    }

    /*
     * ok, now go send it...
     */
    memset((char *) &map_server, 0, sizeof(map_server));

    addr                       = ms->address;
    map_server.sin_family      = AF_INET;
    map_server.sin_addr.s_addr = addr->address.ip.s_addr;
    map_server.sin_port        = htons(LISP_CONTROL_PORT);

    if ((nbytes = sendto(v4_receive_fd,
                         (const void *)mrp,
                         mrp_len,
                         0,
                         (struct sockaddr *)&map_server,
                         sizeof(struct sockaddr))) < 0) {
        log_msg(INFO,"sendto (send_map_register): %s", strerror(errno));
        return(0);
    }

    if (nbytes != mrp_len) {
        log_msg(INFO,
                "send_map_register: nbytes (%d) != mrp_len (%d)\n",
                nbytes, mrp_len);  
        return(0);
    }
    return(1);
}

/*
 *	build_map_register_pkt
 *
 *	Build the map-register
 *
 */
lispd_pkt_map_register_t *build_map_register_pkt (lispd_locator_chain_t *locator_chain)
{

    lispd_locator_chain_elt_t	       *locator_chain_elt;
    lispd_pkt_map_register_t	       *mrp; 
    lispd_pkt_mapping_record_t	       *mr;
    lispd_pkt_lcaf_t                   *lcaf;
    lispd_pkt_lcaf_addr_t              *lcaf_addr;
    lispd_pkt_nat_lcaf_t               *nat_lcaf;
    lispd_pkt_mapping_record_locator_t *loc_ptr;
    lispd_if_t                          *intf;
    char                                addr_str[128];
    lisp_addr_t                         loc_addr;
    uint32_t                            mrp_len    = 0;
    uint32_t                            loc_len    = 0;
    uint32_t                            loc_count  = 0;
    uint32_t	         	        len        = 0;
    uint16_t	            		eid_afi    = 0;
    uint32_t			        afi_len    = 0;
    uint16_t                            loc_afi    = 0;

    /*
     *	assume 1 record with locator_chain->locator_count locators
     *
     *  XXX: This will need more work to support multiple db entries.
     *	walk the locator_chain_elt to get the locators
     *
     */
    locator_chain_elt = locator_chain->head;	
    loc_len           = get_locator_length_and_count(locator_chain_elt, &loc_count);

    /* get the length of the eid prefix and map to LISP_AFI types*/
    eid_afi = get_lisp_afi(locator_chain->eid_prefix.afi, &afi_len);

    /* compute space needed for the whole packet */
    mrp_len = sizeof(lispd_pkt_map_register_t)	    +
	sizeof(lispd_pkt_mapping_record_t)          +	/* XXX 1 record */
	afi_len                                     +	/* length of the eid prefix */
        (loc_count              *	/* locator_count mapping records */
	sizeof(lispd_pkt_mapping_record_locator_t)) +
	loc_len;					/* sum of the lengths of the 
                                                         * locator_chain->locator_count
							 * locators
                                                         */
    /*
     * Account for optional encodings
     */
    if (lispd_config.use_instance_id) {
        mrp_len += 2 * (sizeof(lispd_pkt_lcaf_t) + sizeof(lispd_pkt_instance_lcaf_t));
    }

    if ((mrp = (lispd_pkt_map_register_t *)malloc(mrp_len)) == NULL) {
        log_msg(INFO, "malloc (map-register packet): %s", strerror(errno));
	return(0);
    }
   
    memset(mrp, 0, mrp_len);
    locator_chain->mrp_len = mrp_len;

    /*
     *	build the packet
     *
     *	Fill in mrp->proxy_reply and compute the HMAC in 
     *	send_map_register()
     *
     */
    mrp->lisp_type        = LISP_MAP_REGISTER;
    mrp->mobile_node      = !!(lispd_config.use_nat_lcaf);
    mrp->map_notify       = 0;
    mrp->nonce            = 0;
    mrp->record_count     = 1;				/* XXX  > 1 ? */
    mrp->auth_data_len    = htons(LISP_SHA1_AUTH_DATA_LEN);

    /* skip over the fixed part,  assume one record (mr) */
    mr                    = (lispd_pkt_mapping_record_t *)
	                     CO(mrp, sizeof(lispd_pkt_map_register_t));
    mr->ttl	          = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    mr->locator_count     = loc_count;
    mr->eid_prefix_length = locator_chain->eid_prefix_length;
    mr->authoritative     = 1;
    mr->action            = 0;
    mr->version_hi        = 0;
    mr->version_low       = 0;

    if (!(loc_ptr =
            (lispd_pkt_mapping_record_locator_t *)encode_eid_for_map_record((char *)&mr->eid_prefix_afi,
                                                                            locator_chain->eid_prefix,
                                                                            eid_afi,
                                                                            afi_len))) {
        log_msg(ERROR, "   failed to encode EID in mapping record.");
        free(mrp);
        return(0);
    }
	
    while (locator_chain_elt) {

        intf = locator_chain_elt->interface;

        /*
         * Check interface status and get the address
         */
        if (intf && (intf->flags & IFF_UP)) {
            if (intf->nat_type != NATOff) {
                if (is_nat_complete(intf)) {
                    memcpy(&loc_addr, &intf->nat_address.address.ip.s_addr, sizeof(lisp_addr_t));
                } else {
                    log_msg(INFO, "Interface %s has incomplete NAT translation address",
                           intf->name);
                    locator_chain_elt = locator_chain_elt->next;
                    continue;
                }
            } else if (intf->address.address.ip.s_addr != 0) {  // IPV4 only and local interface only XXX
                memcpy(&loc_addr, &intf->address, sizeof(lisp_addr_t));
            } else {
                log_msg(INFO, "Interface %s has no address", intf->name);
                locator_chain_elt = locator_chain_elt->next;
                continue; // No address? Not included.
            }
        } else {
            locator_chain_elt = locator_chain_elt->next;
            continue;
        } // Need to handle non-local locators XXX

        loc_ptr->priority    = locator_chain_elt->priority;
        loc_ptr->weight      = locator_chain_elt->weight;
        loc_ptr->mpriority   = locator_chain_elt->mpriority;
        loc_ptr->mweight     = locator_chain_elt->mweight;
	loc_ptr->reachable   = 1;		/* XXX should be computed */
        loc_ptr->probed      = 0;		/* XXX */

        if (intf) {
            loc_afi = intf->address.afi;
        } else {
            loc_afi = locator_chain_elt->locator_afi;
        }

        /*
         * If using NAT traversal we must convey the port number
         * along with the locator address.
         */
        if (lispd_config.use_nat_lcaf) {
            lcaf = (lispd_pkt_lcaf_t *)((char *)loc_ptr + offsetof(lispd_pkt_mapping_record_locator_t, locator_afi));

            lcaf->afi  = htons(LISP_AFI_LCAF);
            lcaf->type = LISP_LCAF_NAT;
            lcaf->length = 4 + 3 * sizeof(uint16_t);
            if (loc_addr.afi == AF_INET) {
                lcaf->length += sizeof(struct in_addr);
            } else if (loc_addr.afi == AF_INET6) {
                lcaf->length += sizeof(struct in6_addr);
            } else {
                log_msg(ERROR, "Unknown address family %d in locator",
                        loc_addr.afi);
                return(FALSE);
            }
            lcaf->length = htons(lcaf->length);
            nat_lcaf = (lispd_pkt_nat_lcaf_t *)lcaf->address;
            nat_lcaf->port = htons(intf->translated_encap_port);
            lcaf_addr = (lispd_pkt_lcaf_addr_t *)nat_lcaf->addresses;
            lcaf_addr->afi =  htons(get_lisp_afi(loc_afi, NULL));
            if ((len = copy_addr(lcaf_addr->address,
                                 &(loc_addr),
                                 loc_afi, 0)) == 0) {
                log_msg(INFO, "locator (%s) has an unknown afi (%d)",
                        locator_chain_elt->locator_name,
                        ntohs(loc_ptr->locator_afi));
                return(FALSE);
            }

            /*
             * NULL the private and NTR RLOC fields.
             */
            lcaf_addr = (lispd_pkt_lcaf_addr_t *)CO(lcaf_addr, sizeof(uint16_t) + len);
            lcaf_addr->afi = 0;
            lcaf_addr = (lispd_pkt_lcaf_addr_t *)CO(lcaf_addr, sizeof(uint16_t));
            lcaf_addr->afi = 0;
            len += 2 * sizeof(uint16_t);

            if (lispd_config.use_nat_lcaf) {
                log_msg(INFO, "   Using NAT LCAF with translated port %d for locator",
                        ntohs(nat_lcaf->port));
            }
        } else {
            loc_ptr->locator_afi = htons(get_lisp_afi(loc_afi, NULL));
            if ((len = copy_addr((void *)CO(loc_ptr, sizeof(lispd_pkt_mapping_record_locator_t)),
                                 &(loc_addr),
                                 loc_afi, 0)) == 0) {
                log_msg(INFO, "locator (%s) has an unknown afi (%d)",
                        locator_chain_elt->locator_name,
                        ntohs(loc_ptr->locator_afi));
                return(FALSE);
            }
        }
        log_msg(INFO, "Added %s with addr %s to map register",
               locator_chain_elt->locator_name,
               inet_ntop(loc_afi, &loc_addr.address.ip.s_addr, addr_str, 128));

	/*
	 * get the next locator in the chain and wind
	 * loc_ptr to the right place 
         */
	loc_ptr           = (lispd_pkt_mapping_record_locator_t *)
	    CO(loc_ptr, (sizeof(lispd_pkt_mapping_record_locator_t) + len));

        locator_chain_elt = locator_chain_elt->next;
    }
    return(mrp);
}

/*
 *	map_server_register (tree)
 *
 */
int map_register(timer *t, void *arg)
{

    patricia_tree_t           *all_afi_dbs[2] = { AF4_database,
                                                  AF6_database };
    patricia_tree_t           *tree = NULL;
    lispd_map_server_list_t   *ms;
    lispd_pkt_map_register_t  *map_register_pkt;
    patricia_node_t	      *node;
    lispd_locator_chain_t     *locator_chain;
    int                        afi_count = 0;

    /*
     * Make sure even if we fail, we come back again.
     */
    if (!map_register_timer) {
        map_register_timer = create_timer("Map register");
    }
    start_timer(map_register_timer, REGISTER_INTERVAL, map_register,
                NULL);

    if (!lispd_config.map_servers) {
        log_msg(INFO, "No Map Servers conifgured!");
        return(0);
    }

    while (afi_count < 2) {
        tree = all_afi_dbs[afi_count];
        PATRICIA_WALK(tree->head, node) {
            locator_chain = ((lispd_locator_chain_t *)(node->data));
            if (locator_chain) {
                if ((map_register_pkt =
                     build_map_register_pkt(locator_chain)) == NULL) {
                    log_msg(INFO, "Couldn't build map register packet");
                    return(0);
                }

                /*
                 * for each map server, send a register, and if verify
                 * send a map-request for our eid prefix
                 */
                ms = lispd_config.map_servers;

                while (ms) {
                    map_register_pkt->key_id = htons(ms->key_type);
                    if (!send_map_register(ms,
                                           map_register_pkt,
                                           locator_chain->mrp_len)) {
                        log_msg(INFO,
                                "Couldn't send map-register for %s",
                                locator_chain->eid_name);
                    }
                    ms = ms->next;
                }
                free(map_register_pkt);
            }
        } PATRICIA_WALK_END;
        afi_count++;
    }

    log_msg(INFO, "Map-register sent, interval reset");
    return(0);
}
