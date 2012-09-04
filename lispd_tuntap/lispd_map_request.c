/*
 * lispd_map_request.c
 *
 * Declarations for map request packet functions.
 *
 * Author: David Meyer and Chris White
 * Copyright 2010, Cisco Systems
 */

#include "cksum.h"
#include "lispd_config.h"
#include "lispd_util.h"
#include "lispd_timers.h"
#include "lispd_db.h"
#include "lispd_map_request.h"
#include "lispd_map_reply.h"
#include "lispd_netlink.h"

extern int v4_receive_fd;

timer *rloc_probe_timer = NULL;
timer *map_request_retry_timer = NULL;
timer *start_smr_timer = NULL;

/*
 *	Send a map-request
 *
 *	Send this packet on UDP 4342
 *
 *
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |                   Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *	Next is the inner IP header, either struct ip6_hdr or struct
 *	iphdr. 
 *
 *	This is follwed by a UDP header, random source port, 4342 
 *	dest port.
 *
 *	Followed by a struct lisp_pkt_map_request_t:
 *
 * Map-Request Message Format
 *   
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=1 |A|M|P|S|      Reserved       |   IRC   | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         Source-EID-AFI        |    Source EID Address  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                        EID-prefix ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                      Mappping Record ...                      |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *	<source EID address>
 *	IRC = 0 --> one source rloc
 *      lisp_pkt_map_request_eid_prefix_record_t
 *      EID
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *      Mon May 17 12:25:35 PDT 2010
 *	
 */

#include "lispd_packets.h"

/*
 * encapsulate_control_msg()
 *
 * Add a LISP encapsulated control message header
 * to the front of the given packet, targeted to the
 * mapping system.
 */
uint8_t *encapsulate_control_msg(uint8_t *original_msg,
                                int msg_len,
                                int *new_len)
{
    uint8_t					*packet;
    lispd_pkt_encapsulated_control_t		*ecm;
    void					*cur_ptr;
    int						packet_len = 0;

    /*
     * caclulate sizes of interest
     */
    packet_len = sizeof(lispd_pkt_encapsulated_control_t) + msg_len;
    *new_len       = packet_len;

    if ((packet = (uint8_t *)malloc(packet_len)) == NULL) {
        log_msg(INFO,"malloc(packet_len): %s", strerror(errno));
        return(0);
    }
    memset(packet,0,packet_len);

    /*
     *	build the encapsulated control message header
     */
    ecm       = (lispd_pkt_encapsulated_control_t *) packet;
    ecm->type = LISP_ENCAP_CONTROL_TYPE;

    /*
     * point cur_ptr at the start of the inner message
     */
    cur_ptr   = CO(ecm, sizeof(lispd_pkt_encapsulated_control_t));

    /*
     * Copy the passed in message
     */
    memcpy(cur_ptr, original_msg, msg_len);
    return(packet);
}

int choose_request_addresses(request_type_e type,
                             lisp_addr_t *eid_prefix,
                             lisp_addr_t **src_addr,
                             lisp_addr_t **src_eid,
                             lisp_addr_t *target,
                             lisp_addr_t **rloc_addr,
                             lisp_addr_t  *receiver)
{
    lispd_if_t                                  *curr_if;

    curr_if = get_primary_interface();

    if (!curr_if) {
        log_msg(INFO, "Can't send map request, no configured lisp interface!");
        return(FALSE);
    }

    switch (type) {

        /*
         * Normal requests are destined to be encapsulated, so
         * use our RLOC address as the IP source, and the EID
         * prefix as the destination
         */
    case NormalRequest:

        /*
         * If NAT is enabled use it for both the locator and
         * source address.
         */
        if (curr_if->nat_type == NATOff) {
            *rloc_addr = &curr_if->address;
        } else {
            if (is_nat_complete(curr_if)) {
               *rloc_addr = &curr_if->nat_address;
            } else {
                log_msg(INFO, "Can't send ecm map-request: interface %s has incomplete NAT translation",
                        curr_if->name);
                return(FALSE);
            }
        }

        if (eid_prefix->afi == AF_INET) {
            *src_addr = &lispd_config.eid_address_v4;
            *src_eid  = &lispd_config.eid_address_v4;
        } else if (eid_prefix->afi == AF_INET6) {
            *src_addr = &lispd_config.eid_address_v6;
            *src_eid  = &lispd_config.eid_address_v6;
        } else {
            log_msg(ERROR, "Can't send map-request: unknown EID AFI %d", eid_prefix->afi);
            return(FALSE);
        }
        copy_addr(target, eid_prefix, eid_prefix->afi, 0);
        break;

   case SMR:
   case RLOCProbe:

        /*
         * Don't use the mapping system, go native.
         */
        *src_addr = &curr_if->address;
        if (eid_prefix->afi == AF_INET) {
            *src_eid  = &lispd_config.eid_address_v4;
        } else if (eid_prefix->afi == AF_INET6) {
            *src_eid  = &lispd_config.eid_address_v6;
        } else {
            log_msg(ERROR, "Can't send SMR/RP map-request: unknown EID AFI %d", eid_prefix->afi);
            return(FALSE);
        }

        /*
         * If nat is enabled, use the global locator, not the interface address.
         */
        if ((curr_if->nat_type != NATOff) && is_nat_complete(curr_if)) {
            *rloc_addr = &curr_if->nat_address;
        } else {
            *rloc_addr = *src_addr; // Should we do anyting if NAT is incomplete? XXX
        }
        memcpy(target, receiver, sizeof(lisp_addr_t));
        break;

    default:
        log_msg(ERROR, "choose_request_addresses: Unknown map-request type %d", type);
        return(FALSE);
        break;
    }
    return(TRUE);
}

// This function is too big, needs to be split up. XXX
uint8_t *build_map_request_pkt(lisp_addr_t              *eid_prefix,
                               uint8_t                   eid_prefix_length,
                               int                      *len,	                /* return length here */
                               uint64_t                 *nonce,			/* return nonce here */
                               request_type_e            type,
                               lisp_addr_t              *receiver) /* only if type == RLOCProbe or SMR */
{
    struct udphdr				*udph;
    lisp_addr_t				        *src_addr;
    lisp_addr_t                                 *src_eid;
    uint16_t                                     src_eid_afi;
    lispd_pkt_lcaf_t                            *lcaf;
    lispd_pkt_lcaf_addr_t                       *lcaf_addr;
    lispd_pkt_instance_lcaf_t                   *instance_lcaf;
    lisp_addr_t                                 *rloc_addr;
    lisp_addr_t                                  target;
    uint8_t				        *tmp, *packet;
    lispd_pkt_map_request_t			*mrp;
    lispd_pkt_map_request_itr_rloc_t		*itr_rloc;
    lispd_pkt_map_request_eid_prefix_record_t   *eid_rec;
    void					*cur_ptr;
    void					*iphptr;	/* v4 or v6 */

    uint16_t					udpsum              = 0;
    uint16_t					eid_afi             = 0;
    int                                         src_eid_len         = 0;
    int						packet_len          = 0;
    int						eid_len             = 0;
    int						ip_len              = 0;
    int						udp_len             = 0;
    int						ip_header_len       = 0;
    int						my_addr_len         = 0;
    int						alen                = 0;

    eid_afi = get_lisp_afi(eid_prefix->afi, &eid_len);

    if (!choose_request_addresses(type, eid_prefix,
                                  &src_addr, &src_eid, &target,
                                  &rloc_addr, receiver)) {
        log_msg(ERROR, "Unable to choose source/rloc/target addresses for request.");
        return(0);
    }

    src_eid_afi = get_lisp_afi(src_eid->afi, &src_eid_len);

    /*
     * caclulate sizes of interest
     */
    if ((my_addr_len = get_addr_len(rloc_addr->afi)) == 0) {
        log_msg(ERROR, "Failed to determine address length for ITR-rloc addr");
        return(0);
    }

    if ((ip_header_len = get_ip_header_len(src_addr->afi)) == 0) {
        log_msg(ERROR, "Failed to determine IP header length given source addr");
        return(0);
    }

    udp_len = sizeof(struct udphdr)                       + /* udp header */
        sizeof(lispd_pkt_map_request_t)                   + /* map request */
        src_eid_len                                       + /* len of source EID */
        sizeof(lispd_pkt_map_request_itr_rloc_t)          + /* IRC = 1 */
        my_addr_len                                       + /* len of ITR RLOC */
        sizeof(lispd_pkt_map_request_eid_prefix_record_t) +
        eid_len;					    /* len of EID prefix */

    /*
     * Account for optional encodings
     */
    if (lispd_config.use_instance_id) {
        udp_len += 2 * (sizeof(lispd_pkt_lcaf_t) + sizeof(lispd_pkt_instance_lcaf_t));
    }

    ip_len     = ip_header_len + udp_len;
    packet_len = ip_len;
    *len       = packet_len;				    /* return this */

    if ((packet = (uint8_t *)malloc(packet_len)) == NULL) {
        log_msg(INFO,"malloc(packet_len): %s", strerror(errno));
        return(0);
    }

    memset(packet, 0, packet_len);
    iphptr = packet;				/* save for ip checksum */

    /*
     *	build IPvX header
     */
    if ((udph = build_ip_header(packet,
                                src_addr,
                                &target,
				ip_len)) == 0) {
        log_msg(INFO,"Can't build IP header (unknown AFI %d)",
               src_addr->afi);
	return(0);
    }

    /*
     * fill in the UDP header. checksum later.
     *
     */
    if ((type == NormalRequest) && lispd_config.use_nat_lcaf) {
        udph->source = htons(lispd_config.translated_control_port);
    } else {
        udph->source = htons(lispd_config.local_control_port);
    }
    udph->dest   = htons(lispd_config.control_port);
    udph->len    = htons(udp_len);
    udph->check  = 0;

    /*
     * build the map request
     */

    /*
     * first, point mrp at map-request packet
     */
    mrp = (lispd_pkt_map_request_t *) CO(udph,sizeof(struct udphdr));

    mrp->type                      = LISP_MAP_REQUEST;
    mrp->authoritative             = (type == SMR);
    mrp->map_data_present          = 0;
    mrp->rloc_probe                = (type == RLOCProbe);
    mrp->solicit_map_request       = (type == SMR);
    mrp->d_bit                     = (type == SMR);
    mrp->mn_bit                    = !!(lispd_config.use_nat_lcaf);
    mrp->additional_itr_rloc_count = 0;		/* 0 means 1, yes really. */
    mrp->record_count              = 1;		/* XXX: assume 1 record */
    mrp->nonce                     = build_nonce((unsigned int)time(NULL));
    *nonce                         = mrp->nonce;

    if (!(itr_rloc = (lispd_pkt_map_request_itr_rloc_t *)encode_eid_for_map_record((char *)&(mrp->source_eid_afi), *src_eid, src_eid_afi, src_eid_len))) {
        log_msg(ERROR, "   failed to encode source EID in request mapping record.");
        free(mrp);
        return(0);
    }

    itr_rloc->afi = htons(get_lisp_afi(rloc_addr->afi, NULL));
    cur_ptr = CO(itr_rloc, sizeof(lispd_pkt_map_request_itr_rloc_t));
    if ((alen = copy_addr(cur_ptr,
                          rloc_addr,
                          rloc_addr->afi,
			  0)) == 0) {
        free(packet);
	return(0);
    }

    /* 
     * finally, the requested EID prefix, wrap in instance ID LCAF if
     * necessary.
     */
    eid_rec = (lispd_pkt_map_request_eid_prefix_record_t *)CO(cur_ptr, alen);
    eid_rec->eid_prefix_mask_length = eid_prefix_length;
    if (!encode_eid_for_map_record((char *)&(eid_rec->eid_prefix_afi), *eid_prefix, eid_afi, eid_len)) {
        log_msg(ERROR, "   failed to encode request EID in request mapping record.");
        free(mrp);
        return(0);
    }

    /*
     * now compute the checksums...
     */
    if (src_addr->afi == AF_INET)
        ((struct ip *) iphptr)->ip_sum = ip_checksum(iphptr, ip_header_len);

    if ((udpsum = udp_checksum(udph, udp_len, iphptr, src_addr->afi)) == 0) {
	return(0);
    }

    udpsum(udph) = udpsum;

    /*
     * optionally encapsulate: regular requests go to map server, everything
     * else is native.
     */
    if (type == NormalRequest) {
        tmp = encapsulate_control_msg(packet, ip_len, len);
        free(packet);
    } else {
        tmp = packet;
    }
    return(tmp);
}

/*
 *	send_map_request
 *
 */
int send_map_request(uint8_t *packet,
                     int	packet_len,
                     lisp_addr_t *resolver,
		     uint64_t nonce)
{
    struct sockaddr_in   map_resolver;
    int			nbytes = 0;
    char                addr_buf[128];

    /* XXX: assume v4 transport */

    memset((char *) &map_resolver, 0, sizeof(map_resolver));

    map_resolver.sin_family      = AF_INET;	/* XXX: assume v4 transport */
    map_resolver.sin_addr.s_addr = resolver->address.ip.s_addr;
    map_resolver.sin_port        = htons(lispd_config.control_port);

    if ((nbytes = sendto(v4_receive_fd,
                         (const void *)packet,
			 packet_len,
			 0,
			 (struct sockaddr *)&map_resolver,
			 sizeof(struct sockaddr))) < 0) {
        log_msg(INFO, "sendto (send_map_request): %s", strerror(errno));
        free(packet);
	return(0);
    }

    if (nbytes != packet_len) {
        log_msg(INFO,
	       "send_map_request: nbytes (%d) != packet_len (%d)\n",
               nbytes, packet_len);
        free(packet);
	return(0);
    }
    log_msg(INFO, "  Map request sent to %s",
           inet_ntop(AF_INET, &map_resolver.sin_addr, addr_buf, 128));

    free(packet);
    return(1);
}

/*
 *	build_and_send_map_request --
 *
 *	Put a wrapper around build_map_request_pkt and send_map_request. Returns
 *      nonce if successful, 0 otherwise.
 *
 */
uint64_t build_and_send_map_request(lisp_addr_t              *eid_prefix,
                                    uint8_t                   eid_prefix_length)
{
    uint8_t *packet;
    uint64_t nonce;
    int      len;				/* return the length here */
    int      retry_time_in_sec;
    char     addr_buf[128];
    datacache_elt_t *elt;

    log_msg(INFO, "In build_and_send_map_request()");

    packet = build_map_request_pkt(eid_prefix,
				   eid_prefix_length,
				   &len,
                                   &nonce,
                                   NormalRequest,
                                   NULL);

    if (!packet) {
        inet_ntop(eid_prefix->afi, &eid_prefix->address, addr_buf, sizeof(addr_buf));
        log_msg(INFO,
               "Could not build map-request packet for %s/%d",
               addr_buf,
	       eid_prefix_length);
        return(0);
    }

    // Use first map-resolver for now. XXX
    if (!send_map_request(packet, len, lispd_config.map_resolvers->address, nonce)) {
        inet_ntop(eid_prefix->afi, &eid_prefix->address, addr_buf, sizeof(addr_buf));
        log_msg(INFO,
	       "Could not send map-request for %s/%d",
               addr_buf,
	       eid_prefix_length);
        return(0);
    }

    // Keep track for retries
    elt = find_eid_in_datacache(eid_prefix, eid_prefix_length);
    if (elt == NULL) {
        if (!build_datacache_entry(eid_prefix,
                                   eid_prefix_length,
                                   NULL,
                                   nonce,
                                   NormalRequest)) {
            log_msg(INFO, "Couldn't build datacache_entry");
            return(0);
        }

        log_msg(INFO, "Request entry not found in queue, added new entry.");
    } else {
        retry_time_in_sec = 2 << (lispd_config.map_request_retries - elt->retries);
        if (retry_time_in_sec == 0) {
            retry_time_in_sec = 1;
        }
        gettimeofday(&elt->scheduled_to_send, NULL);
        elt->scheduled_to_send.tv_sec += retry_time_in_sec;
        log_msg(INFO, "Found entry already in queue, setting retry timer to %d sec from now",
                retry_time_in_sec);
    }

    // Start the timer if it's not already running
    if (!map_request_retry_timer) {
        map_request_retry_timer = create_timer("Map Request retry");
    }
    start_timer(map_request_retry_timer, REQUEST_INTERVAL,  &retry_map_requests,
                NULL);
    return(nonce);
}

/*
 * build_and_send_rloc_probe
 *
 * Construct an rloc-probe packet, and send it to the given rloc
 */
uint64_t build_and_send_rloc_probe(lisp_addr_t          *target,
                                   lisp_addr_t          *eid_prefix,
                                   uint8_t               eid_prefix_length)
{
    uint8_t *packet;
    uint64_t nonce;
    int      len;
    char     addr_str1[128];
    char     addr_str2[128];
    struct sockaddr_in dst;
    int      s, nbytes;

    log_msg(INFO, "Building RLOC Probe for %s/%d at %s",
           inet_ntop(eid_prefix->afi, &eid_prefix->address, addr_str1, 128),
           eid_prefix_length,
           inet_ntop(target->afi, &target->address, addr_str2, 128));

    packet = build_map_request_pkt(eid_prefix, eid_prefix_length, &len, &nonce,
                                   RLOCProbe, target);
    if (!packet) {
        log_msg(INFO, "  Failed to construct packet.");
        return(0);
    }

    /* XXX: assumes v4 transport */
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        log_msg(INFO, "socket (send_map_request): %s", strerror(errno));
        return(0);
    }

    memset((char *) &dst, 0, sizeof(dst));

    dst.sin_family      = AF_INET;	/* XXX: assume v4 transport */
    dst.sin_addr.s_addr = target->address.ip.s_addr;

    if ((nbytes = sendto(s,
                         (const void *)packet,
                         len,
                         0,
                         (struct sockaddr *)&dst,
                         sizeof(struct sockaddr))) < 0) {
        log_msg(INFO, "sendto (send_rloc_probe): %s", strerror(errno));
        return(0);
    }

    if (nbytes != len) {
        log_msg(INFO,
               "send_rloc_probe: nbytes (%d) != packet_len (%d)\n",
               nbytes, len);
        return(0);
    }
    close(s);
    free(packet);
    return(nonce);
}

/*
 * build_and_send_smr
 *
 * Construct a solicit-map-request packet, and send it to the given target
 * address.
 */
uint64_t build_and_send_smr(lisp_addr_t *target, lisp_addr_t *eid_prefix,
                            int eid_prefix_length)
{
    uint8_t *packet;
    patricia_node_t *node;
    lispd_locator_chain_t *locator_chain;
    uint64_t nonce;
    int      len;
    char     addr_str1[128];
    char     addr_str2[128];
    struct sockaddr_in dst;
    int      s, nbytes;

    if (target->afi != AF_INET) {
        log_msg(WARNING, "IPv6 unsupported, skipping SMR to %s",
                inet_ntop(target->afi, &target->address,
                          addr_str1, 128));
        return(0);
    }

    /* XXX: assumes v4 transport */
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        log_msg(INFO, "socket (send_map_request): %s", strerror(errno));
        return(0);
    }

    /*
     * Build an SMR packet for each entry in the
     * database. V4 only for now XXX.
     */
    PATRICIA_WALK(AF4_database->head, node) {

        locator_chain = ((lispd_locator_chain_t *)(node->data));
        log_msg(INFO, "Building SMR for %s/%d to %s",
                inet_ntop(locator_chain->eid_prefix.afi, &locator_chain->eid_prefix.address, addr_str1, 128),
                locator_chain->eid_prefix_length,
                inet_ntop(target->afi, &target->address, addr_str2, 128));

        packet = build_map_request_pkt(eid_prefix,
                                       eid_prefix_length, &len, &nonce,
                                       SMR, target);

        log_msg(INFO, "  nonce: %0xd-%0xd", nonce >> 32,
                nonce & 0xFFFFFFFF);

        if (!packet) {
            log_msg(INFO, "  Failed to construct packet.");
            close(s);
            return(0);
        }

        memset((char *) &dst, 0, sizeof(dst));

        dst.sin_family      = AF_INET;	/* XXX: assume v4 transport */
        dst.sin_addr.s_addr = target->address.ip.s_addr;

        if ((nbytes = sendto(s,
                             (const void *)packet,
                             len,
                             0,
                             (struct sockaddr *)&dst,
                             sizeof(struct sockaddr))) < 0) {
            log_msg(INFO, "sendto (send_smr): %s", strerror(errno));
            close(s);
            return(0);
        }

        if (nbytes != len) {
            log_msg(INFO,
                    "send_smr: nbytes (%d) != packet_len (%d)\n",
                    nbytes, len);
            close(s);
            return(0);
        }
        free(packet);
    } PATRICIA_WALK_END;
    close(s);
    return(nonce);
}

/*
 * handle_incoming_smr()
 *
 * Deal with an SMR map-request from an ETR.
 *
 * Lookup the EID prefix to make sure if we should
 * respond, and schedule a request if so.
 */
void handle_incoming_smr(lispd_pkt_map_request_t *pkt,
                         struct sockaddr_in *sa)
{
    lisp_addr_t eid_prefix;
    lispd_pkt_map_request_eid_prefix_record_t *eid_rec;
    char *addr_ptr;
    int  afi;
    char addr_buf[128];

    if (pkt->record_count > 1) {
        log_msg(INFO, "SMR has more than one EID, unexpected.");
        return;
    }

    // Right place to get this? XXX
    eid_rec = (lispd_pkt_map_request_eid_prefix_record_t *)CO(pkt, sizeof(lispd_pkt_map_request_t));
    addr_ptr = CO(eid_rec, sizeof(lispd_pkt_map_request_eid_prefix_record_t));

    afi = lisp2inetafi(ntohs(eid_rec->eid_prefix_afi));
    switch (afi) {
        case AF_INET:
            memcpy(&eid_prefix.address, addr_ptr, sizeof(struct in_addr));
            break;
        case AF_INET6:
            memcpy(&eid_prefix.address, addr_ptr, sizeof(struct in6_addr));
            break;
        default:
            log_msg(INFO, "Unknown AFI in SMR packet %d",
                   afi);
            return;
            break;
    }
    eid_prefix.afi = afi;

    /*
     * Do a cache lookup to verify we are even interested. XXX Check source locator
     * is in our list as well. Security issue.
     */
    if (!map_cache_entry_exists(eid_prefix, eid_rec->eid_prefix_mask_length)) {
        log_msg(INFO, "SMR for prefix %s/%d, not found in map cache, ignoring.",
               inet_ntop(afi, &eid_prefix.address, addr_buf, 128));

        // XXX Section 6.6.2 now says to send the map-request to the mapping system
        // with EID destination if the source locator is not present.
        return;
    }

    build_and_send_map_request(&eid_prefix,
                               eid_rec->eid_prefix_mask_length);
}


/*
 * retry_map_requests()
 *
 * Run through the request cache and send map requests for any
 * elements that still remain.
 */
void retry_map_requests(timer *tptr, void *arg)
{
    datacache_elt_t *elt;
    struct timeval   nowtime;
    uint64_t         nonce = 0;

    elt = datacache->head;

    while (elt) {

        // Check if it's time to send it.
        gettimeofday(&nowtime, NULL);
        if (elt->scheduled_to_send.tv_sec > nowtime.tv_sec) {
            elt = elt->next;
            continue;
        }

        if (!elt->retries) { // It's done

            log_msg(INFO, "No response after %d retries, removing request from queue",
                   lispd_config.map_request_retries);
            elt->nonce = 0;   // Mark for deletion
            elt = elt->next;
            remove_eid_from_datacache(0); // Delete
            continue;
        }

        if (elt->type == SMR) {
            nonce = build_and_send_smr(&elt->target_addr, &elt->eid_prefix,
                                       elt->prefix_length);
        } else {
            nonce = build_and_send_map_request(&elt->eid_prefix,
                                               elt->prefix_length);
        }

        if (nonce == 0) {
            log_msg(WARNING, "Failed to send map-request (expected for ipv6)");
        } else {
            log_msg(INFO, "Map-request sent.");
            gettimeofday(&nowtime, NULL);
            elt->last_sent.tv_sec = nowtime.tv_sec;
            elt->last_sent.tv_usec = 0;
            elt->nonce = nonce;
        }
        elt->retries--;
        elt = elt->next;
    }

    if (datacache->head == NULL) {
        stop_timer(map_request_retry_timer);
    }
    return;    
}

/*
 * process_map_request()
 *
 * Process an incoming map request. For now, this is only meant to
 * handle incoming SMR's and RLOC Probes.
 */
void process_map_request(lispd_pkt_map_request_t *pkt,
                         struct sockaddr_in *sa)
{
    char addr_buf[128];

    if ((!pkt->type == LISP_MAP_REQUEST)) {
        log_msg(INFO, "lispd_process_map_request: wrong type %d",
               pkt->type);
        return;
    }

    log_msg(INFO, "  From: %s",
           inet_ntop(AF_INET, &sa->sin_addr.s_addr, addr_buf,
                     128));

    log_msg(INFO, "   Flags: a: %d, map_data: %d, rp: %d, smr: %d, nonce %0xd\-%0xd",
           pkt->authoritative, pkt->map_data_present,
           pkt->rloc_probe, pkt->solicit_map_request,
           pkt->nonce >> 32,
           pkt->nonce & 0xFFFFFFFF);

    if (pkt->rloc_probe && pkt->solicit_map_request) {
        log_msg(INFO, "    Both smr and rloc-probe set, dropping!");
        return;
    }

    /*
     * This request is really an SMR.
     */
    if (pkt->solicit_map_request) {
        handle_incoming_smr(pkt, sa);
    }

    /*
     * Check for an outstanding request in the data cache
     * if it's an SMR-invoked request
     */
    if (!pkt->rloc_probe) {
        if (!remove_eid_from_datacache(pkt->nonce) &&
            !pkt->rloc_probe) {
            log_msg(INFO, "   Received an SMR-invoked request without a matching nonce.");
        }
    }

    /*
     * Send the reply.
     */
    send_map_reply(pkt, sa);
    return;
}

/*
 * issue_rloc_probes()
 *
 * Go through the current list of pending RLOC-probes and check
 * for expired (non-responsive) entries, and send out any that
 * are still outstanding.
 */
void issue_rloc_probes(timer *probe_timer, void *arg)
{
    rloc_probe_item_t *iterator = get_rp_queue_head();
    rloc_probe_rloc_t *rloc;
    uint8_t requests_outstanding = FALSE;
    int rloc_idx;
    uint64_t nonce;
    char addr_str[128];
    char addr_str2[128];

    while (iterator) {

        /*
         * Build and send a map-request with the probe
         * bit set for each unreplied locator in the entry
         */
        for (rloc_idx = 0; rloc_idx < iterator->locator_count; rloc_idx++) {
            rloc = &iterator->locators[rloc_idx];

            if (rloc->probes_sent >= lispd_config.rloc_probe_retries) {
                rloc->status = ProbedDown;
                log_msg(INFO, "RLOC: %s for EID: %s/%d marked down: no response.",
                       inet_ntop(rloc->locator.afi,
                                 &rloc->locator.address,
                                 addr_str2,
                                 128),
                       inet_ntop(iterator->eid_prefix.afi,
                                 &iterator->eid_prefix.address, addr_str, 128),
                       iterator->eid_prefix_length);
            }
            if (rloc->status == WaitingForProbeResponse) {
                nonce = build_and_send_rloc_probe(&rloc->locator, &iterator->eid_prefix,
                                           iterator->eid_prefix_length);

                /*
                 * Update the item's nonce.
                 */
                rloc->nonce = nonce;
                rloc->probes_sent++;
                requests_outstanding = TRUE;
            }
        }

        if (!requests_outstanding) {

            /*
             * All RLOC's have either replied or timed-out,
             * update the kernel, and remove the work item from
             * the queue. Even if we refreshed the cache entry
             * with the contents of map-replies from other RLOC's,
             * the status here is valid since this step is done last
             * and when all RLOC's are (un)accounted for.
             */
            update_locator_status(iterator);
            iterator = delete_item_from_rp_queue(iterator);
            continue;
        }
        iterator = iterator->next;
    }

    // Restart the timer
    start_timer(rloc_probe_timer, RLOC_PROBE_CHECK_INTERVAL,
                 issue_rloc_probes, NULL);
}

/*
 * setup_probe_timer()
 *
 * Create and start the RLOC probe timer
 */
void setup_probe_timer()
{
    rloc_probe_timer = create_timer("RLOC Probe");
    start_timer(rloc_probe_timer, RLOC_PROBE_CHECK_INTERVAL,
                 issue_rloc_probes, NULL);
}

/*
 * schedule_solicit_map_requests()
 *
 * After a change in the database, get ready to sound out SMR's.
 * SMR's will be sent as soon as this function has *not* been
 * called for SMR_HOLDOFF_PERIOD seconds, suppress uncessary
 * solicitations during interface flapping.
 */
void schedule_solicit_map_requests(void)
{
    if (start_smr_timer) {
        stop_timer(start_smr_timer);
    } else {
        start_smr_timer = create_timer("SMR");
    }

    log_msg(INFO, "Schedule start of SMR process in %d seconds", SMR_HOLDOFF_TIME);
    start_timer(start_smr_timer, SMR_HOLDOFF_TIME,  &start_smr_traffic_monitor,
                NULL);
}

/*
 * decapsulate_ecm_packet()
 *
 * We've received an encapsulated control message. In all likelihood
 * it's a map-request (SMR response or other). Decapsulate it, check
 * it's type and pass to the appropriate handler.
 */
uint8_t *decapsulate_ecm_packet(uint8_t *packet)
{
    uint8_t *inner_header;

    /*
     * Advance the packet pointer to the inner lisp header XXX V4 only for now,
     * need to detect inner header AFI since this could by 6 in 4 or something...
     *
     * TBD: Also need to verify the inner ip header/udp header, etc. XXX
     */
    inner_header = packet + sizeof(lispd_pkt_encapsulated_control_t) + sizeof(struct ip) +
                   sizeof(struct udphdr);

    return(inner_header);
}


