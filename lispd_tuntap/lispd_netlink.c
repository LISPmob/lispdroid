/*
 *	lispd_kernel.c
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

#include "lispd.h"
#include "lispd_config.h"
#include "lispd_netlink.h"
#include "lispd_db.h"
#include "lispd_util.h"
#include "lispd_timers.h"
#include "lisp_ipc.h" // From lisp_mod directory, need to harmonize this XXX
#include "lispd_map_request.h"
#include "tables.h"

struct  sockaddr_nl dst_addr;
struct  sockaddr_nl src_addr;

extern int netlink_fd;

int send_command(lisp_cmd_t *cmd, int length)
{

    struct nlmsghdr *nlh;
    struct iovec    iov;
    struct msghdr   kmsg;
    int		    retval = 0;

    if ((nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_MSG_LENGTH))) == 0)
        return(0);

    /*
     *	make sure these are clean
     */

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&iov,      0, sizeof(struct iovec));
    memset(&kmsg,     0, sizeof(struct msghdr));
    memset(nlh,       0, sizeof(struct nlmsghdr));

    /* Fill the netlink message header */

    nlh->nlmsg_len   = length + sizeof(struct nlmsghdr);
    nlh->nlmsg_pid   = 0;  /* To kernel */
    nlh->nlmsg_flags = 0;

    /* Fill in the netlink message payload */

    memcpy(NLMSG_DATA(nlh), (char *)cmd, length);

    iov.iov_base     = (void *)nlh;
    iov.iov_len      = nlh->nlmsg_len;
    kmsg.msg_name    = (void *)&dst_addr;
    kmsg.msg_namelen = sizeof(dst_addr);
    kmsg.msg_iov     = &iov;
    kmsg.msg_iovlen  = 1;

    retval = sendmsg(netlink_fd, &kmsg, 0);
    free(nlh);
    return(retval);
}

/*
 * rcv_command
 *
 * receive a command from the kernel. The socket file
 * descriptor is included as a parameter, since some
 * users may want their own for synchronous operations.
 */
int rcv_command(lisp_cmd_t *cmd_buf, int sock_fd)
{
    struct nlmsghdr *nlh = malloc(NLMSG_SPACE(MAX_MSG_LENGTH));
    lisp_cmd_t *cmd;
    struct iovec iov;
    struct msghdr msg;
    struct sockaddr_nl nladdr;
    int retval;

    iov.iov_base    = (void *)nlh;
    iov.iov_len     = MAX_MSG_LENGTH;
    msg.msg_name    = (void *)&(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    if (!nlh) {
        log_msg(INFO, "malloc: (rcv_command) %s", strerror(errno));
        return FALSE;
    }

    retval = recvmsg(sock_fd, &msg, 0);
    if (retval < 0) {
        log_msg(INFO, "recvmsg: (rcv_command) %s", strerror(errno));
        free(nlh);
        return FALSE;
    }

    cmd = NLMSG_DATA(nlh);
    memcpy(cmd_buf, cmd, sizeof(lisp_cmd_t) + cmd->length);
    free(nlh);
    return TRUE;
}

/*
 *	install_database_mapping --
 *
 *	Install a single database mapping entry in the kernel
 *
 */
int install_database_mapping(lispd_locator_chain_t *chain)
{

    int                         cmd_length = sizeof(lisp_cmd_t) +
                                     sizeof(lisp_db_add_msg_t) +
                                     chain->locator_count * sizeof(lisp_db_add_msg_loc_t);
    int                         retval = 0;
    lisp_db_add_msg_t          *map_msg;
    lisp_cmd_t                 *cmd;
    lispd_locator_chain_elt_t  *locator = chain->head;
    lisp_db_add_msg_loc_t      *msg_loc;
    int                         loc_count = 0;
 
    if (!(cmd = (lisp_cmd_t *) malloc(cmd_length)))
	return(0);

    memset((char *) cmd, 0, cmd_length);

    cmd->type   = LispDatabaseAdd;
    cmd->length = sizeof(lisp_db_add_msg_t) + chain->locator_count * sizeof(lisp_db_add_msg_loc_t);

    map_msg = (lisp_db_add_msg_t *)cmd->val;
    map_msg->eid_prefix_length = chain->eid_prefix_length;
    map_msg->eid_prefix.afi           = chain->eid_prefix.afi;
    if (chain->eid_prefix.afi == AF_INET) {
        map_msg->eid_prefix.address.ip.s_addr =
            chain->eid_prefix.address.ip.s_addr;
    }
    else {					/* assume AF_INET6 */
        memcpy(map_msg->eid_prefix.address.ipv6.s6_addr,
               chain->eid_prefix.address.ipv6.s6_addr,
	       sizeof(struct in6_addr));
    }

    while (locator) {
        msg_loc = &(map_msg->locators[loc_count]);

        /*
         * Is this interface configured?
         */
        if (!locator->interface || !(locator->interface->flags & IFF_UP) ||
                (locator->interface->address.address.ip.s_addr == 0)) {
            log_msg(INFO, "Skipping locator %s, down or unconfigured.",
                   locator->interface ? locator->locator_name : "?");
            locator = locator->next;
            continue;
        }

        if (locator->interface->nat_type == NATOff) {
            copy_lisp_addr_t(&(msg_loc->locator),
                             &(locator->interface->address),
                             locator->interface->address.afi, 0);
        } else if (is_nat_complete(locator->interface)) {
            copy_lisp_addr_t(&(msg_loc->locator),
                             &(locator->interface->nat_address),
                             locator->interface->address.afi, 0);
        } // NAT not complete will be 0.0.0.0 address.

        if (locator->interface) {
            msg_loc->locator.afi = locator->interface->address.afi;
        } else {
            msg_loc->locator.afi = locator->locator_afi;
        }
        msg_loc->priority = locator->priority;
        msg_loc->weight   = locator->weight;
        msg_loc->mpriority = locator->mpriority;
        msg_loc->mweight = locator->mweight;
        loc_count++;
        locator = locator->next;
    }
    map_msg->count = loc_count;

    add_eid_db_entry(map_msg);
    log_msg(INFO, "here...");
 //   retval = send_command(cmd, cmd_length);
    free(cmd);
    return(retval);
}

/*
 *	install_database_mappings_afi --
 *
 *	Install per_afi database mappings into the kernel
 *
 */
int install_database_mappings_afi(patricia_tree_t *tree)
{
    patricia_node_t		*node;
    lispd_locator_chain_t	*locator_chain;
    int			        retval = 1;
   
    if (!tree)
	return(0);

    PATRICIA_WALK(tree->head, node) {
        locator_chain     = ((lispd_locator_chain_t *)(node->data));

        if (install_database_mapping(locator_chain) < 0) {
            log_msg(INFO,
                   " Could not install database mapping %s/%d",
                   locator_chain->eid_name,
                   locator_chain->eid_prefix_length);
		retval = 0;			/* something wrong */
	    } 
#ifdef	DEBUG
            else {
            debug_installed_database_entry(db_entry, locator_chain);
	    }
#endif
    } PATRICIA_WALK_END;
    return(retval);
}

/*
 *	install_database_mappings --
 *
 *	Install database mappings into the kernel
 *
 */
int install_database_mappings(void)
{

    log_msg(INFO, "installing database-mappings:");
    if (!install_database_mappings_afi(AF4_database)) {
	return(0);
    }
    if (!install_database_mappings_afi(AF6_database)) {
	return(0);
    }

    dump_info_file();
    schedule_solicit_map_requests();
    return(1);
}

/*
 * map_cache_entry_exists()
 *
 * Lookup a map cache entry in the kernel tables. This is a synchronous
 * operation that blocks. We open a new netlink socket temporarily for this purpose.
 * For now this is a check operation: return true if the entry exists, false
 * otherwise. Can be extended to return the whole entry when/if necessary, just
 * need to copy the response into an appropriate structure.
 */
int map_cache_entry_exists(lisp_addr_t eid_prefix, int prefix_length)
{
    lisp_lookup_msg_t lu_msg;
    lisp_cmd_t        *cmd;
    lisp_cache_response_msg_t *map_msg = NULL;
    int cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_lookup_msg_t);
    int tmp_nl_sock;
    int retval;
    int done = 0;
    struct timeval timeout;

    tmp_nl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_LISP);
    if (tmp_nl_sock < 0) {
        log_msg(INFO, "socket: (map_cache_entry_exists) %s", strerror(errno));
        return FALSE;
    }

    timeout.tv_sec = 10;
    if (setsockopt(tmp_nl_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
        log_msg(INFO, "setsockopt: (map_cache_entry_exists) %s", strerror(errno));
        return FALSE;
    }

    if (bind(tmp_nl_sock, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        log_msg(INFO, "bind: (map_cache_entry_exists) %s", strerror(errno));
        return FALSE;
    }

    cmd = (lisp_cmd_t *)malloc(cmd_length);
    if (!cmd) {
        log_msg(INFO, "malloc: (map_cache_entry_exists) %s", strerror(errno));
        return FALSE;
    }

    cmd->type = LispMapCacheLookup;
    cmd->length = sizeof(lisp_lookup_msg_t);
    memset((char *)&lu_msg, 0, sizeof(lisp_lookup_msg_t));
    lu_msg.prefix_length = prefix_length;
    lu_msg.exact_match = TRUE;
    memcpy(&lu_msg.prefix.address, &eid_prefix.address, sizeof(lisp_addr_t));
    memcpy(cmd->val, (char *)&lu_msg, sizeof(lisp_lookup_msg_t));

    retval = send_command(cmd, cmd_length);
    free(cmd);

    /*
     * Wait for the response
     */
    cmd = malloc(MAX_MSG_LENGTH);
    if (!cmd) {
         log_msg(INFO, "malloc: (map_cache_entry_exists) %s", strerror(errno));
        return FALSE;
    }

    while (!done) {
        if (!rcv_command(cmd, tmp_nl_sock)) {
            log_msg(INFO, "Failed to receive lookup response from the kernel");
            return FALSE;
        }

        switch (cmd->type) {
            case LispOk:
                done = TRUE;
                break;
            case LispMapCacheLookup:
                map_msg = (lisp_cache_response_msg_t *)cmd->val;
                break;
            default:
                log_msg(INFO, "Unknown command type from kernel (map_cache_entry_exists) %d",
                       cmd->type);
                break;
            }
    }
    return(map_msg != NULL);
}

/*
 *	install_map_cache_entry()
 *
 *	Install a single map_cache entry in the kernel.
 */
int install_map_cache_entry(lisp_eid_map_msg_t *map_msg, int loc_count)
{

    int			cmd_length = sizeof(lisp_cmd_t) +
                                     sizeof(lisp_eid_map_msg_t) +
                                     sizeof(lisp_eid_map_msg_loc_t) * loc_count;
    int			retval	   = 0;
    char                addr_str[128];
    lisp_cmd_t		*cmd;

    if (!(cmd = (lisp_cmd_t *)malloc(cmd_length))) {
        log_msg(INFO, "install_map_cache_entry(): unable to allocate cache msg");
        return(0);
    }

    /*
     *  Build the message
     */
    memset((char *) cmd, 0, sizeof(lisp_cmd_t));

    log_msg(INFO, "building netlink message with EID: %s, AF: %d, count: %d, ttl: %d",
           inet_ntop(AF_INET, &map_msg->eid_prefix.address.ip.s_addr, addr_str, 128),
           map_msg->eid_prefix.afi, loc_count, map_msg->ttl);

    cmd->type   = LispMapCacheAdd;
    cmd->length = sizeof(lisp_eid_map_msg_t) + sizeof(lisp_eid_map_msg_loc_t) * loc_count;
    memcpy(cmd->val, (char *)map_msg, cmd->length);
    retval = send_command(cmd, cmd_length);
    free(cmd);
    return(retval);
}

#ifdef DEPRECATED
/*
 *	install_map-cache_entries
 *
 *	Install static map-cache entries into the kernel
 *
 */
int install_map_cache_entries()
{
    lispd_map_cache_t		*map_cache_entry;
    lispd_map_cache_entry_t	*mc_entry;
    int				afi; 
    int				retval = 1;
    char			eid[128];
    char			rloc[128];
    char			buf[128];

    if (!lispd_map_cache)
	return(0);

    log_msg(INFO, "installing static map-cache entries:");

    map_cache_entry = lispd_map_cache;
    while (map_cache_entry) {
	mc_entry = &(map_cache_entry->map_cache_entry);
	afi      = mc_entry->eid_prefix_afi;
	inet_ntop(afi,
		  &(mc_entry->eid_prefix.address),
		  eid,
		  128);
        if (install_map_cache_entry(mc_entry, 1) < 0) {
            log_msg(INFO, " Could not install map-cache entry %s/%d->%s",
		    eid,
		    mc_entry->eid_prefix_length,
		    mc_entry->locator_name);
	    retval = 0;
	} else {
	    inet_ntop(mc_entry->locator_afi,
		      &(mc_entry->locator.address),
		      rloc, 128);
#ifdef DEBUG
	    if (mc_entry->locator_type == STATIC_LOCATOR)
		sprintf(buf, "%s", rloc);
	    else
		sprintf(buf, "%s (%s)", mc_entry->locator_name, rloc);
            log_msg(INFO, " installed %s lisp %s/%d %s p %d w %d",
		    (afi == AF_INET) ? "ip":"ipv6",
		    eid,
		    mc_entry->eid_prefix_length, 
		    buf,
		    mc_entry->priority,
		    mc_entry->weight);
#endif
	    retval = 1;
	}
	map_cache_entry = map_cache_entry->next;
    }
    return(retval);
}
#endif

/*
 * handle_cache_miss
 *
 * Take the action required when a packet's EID
 * is not in the cache.
 */
void handle_cache_miss(lisp_addr_t eid)
{
    int eid_prefix_len = 0;
    char addrstr[128];

    /*
     * Look up in the data cache, see if we have an outstanding request in the queue
     *
     */
    if (eid.afi == AF_INET6) {
        eid_prefix_len = 128;
    } else {
        eid_prefix_len = 32;
    }
    if (!find_eid_in_datacache(&eid, eid_prefix_len)) {
        if (!build_and_send_map_request(&eid, eid_prefix_len)) { // Always /32 or /128? XXX
            log_msg(INFO,"handle_cache_miss_msg:couldn't build/send map_request");
        }
        inet_ntop(eid.afi, &eid.address, addrstr, 128);
        log_msg(INFO, "built and send map request for %s", addrstr);
    } else {
#ifdef DEBUG_CACHE_MISS
        log_msg(INFO,"map request already outstanding for this EID");
#endif
    }
}


/*
 * handle_cache_miss_msg
 *
 * Deal with a cache miss notification from the kernel
 */
void handle_cache_miss_msg(lisp_cmd_t *cmd)
{
    char addrstr[128];
    int  eid_prefix_len;
    lisp_cache_sample_msg_t *miss_msg = (lisp_cache_sample_msg_t *)cmd->val;

    if (cmd->length < sizeof(lisp_cache_sample_msg_t)) {
        log_msg(INFO, "Malformed cache miss msg received");
        return;
    }

    handle_cache_miss(miss_msg->eid);
}

/*
 *	set up the netlink socket and bind to it.
 */
int setup_netlink(void)
{
    if ((netlink_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_LISP)) <  0) 
	return(0);

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = getpid();       /* self pid */
    src_addr.nl_groups = 0;              /* not in mcast groups */

    if (bind(netlink_fd,
	     (struct sockaddr *) &src_addr, sizeof(src_addr)) == -1) 
	return(0);

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid    = 0;              /* For Linux Kernel */
    dst_addr.nl_groups = 0;              /* unicast */
    return(1);
}


/*
 * Receive a command or other message
 * from the kernel.
 */
int recv_command(lisp_cmd_t *cmd)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_MSG_LENGTH));
    struct msghdr    msg;
    struct iovec     iov;
    struct sockaddr_nl nladdr;
    int              retval;
    lisp_cmd_t      *lisp_cmd;

    if (!nlh) {
        log_msg(INFO, "Memory allocation failure in recv_command");
        return(-1);
    }

    iov.iov_base    = (void *)nlh;
    iov.iov_len     = MAX_MSG_LENGTH;
    msg.msg_name    = (void *)&(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    retval = recvmsg(netlink_fd, &msg, 0);

    if (retval < 0) {
        log_msg(INFO, "failure in recvmsg to netlink socket");
        return(-1);
    }

    lisp_cmd = NLMSG_DATA(nlh);

    memcpy(cmd, NLMSG_DATA(nlh), lisp_cmd->length + sizeof(lisp_cmd_t));
    free(nlh);

    return(0);
}

/*
 * process_kernel_msg
 *
 * Handle a notification from the kernel
 */
int process_kernel_msg(void)
{
    int length;
    lisp_cmd_t *cmd = (lisp_cmd_t *)malloc(MAX_MSG_LENGTH);
    lisp_cache_sample_msg_t *sample = NULL;

    length = recv_command(cmd);

    if (length < 0) {
        log_msg(INFO, "  failed to receive kernel IPC message");
        return(FALSE);
    }

    switch (cmd->type) {
    case LispCacheSample:
        sample = (lisp_cache_sample_msg_t *)cmd->val;

        switch (sample->reason) {
        case SMRSample:
            schedule_smr(sample);
            break;
        case ProbeSample:
            build_rloc_probe_work_item(sample);
            break;
        case CacheMiss:
            handle_cache_miss_msg(cmd);
            break;
        default:
            log_msg(WARNING, "Unknown cache sample reason code %d from kernel",
                    sample->reason);
            break;
        }
        break;
    default:
        log_msg(WARNING, "No handler for kernel message type %d", cmd->type);
        break;
    }

    free(cmd);
    return(TRUE);
}

/*
 * update_locator_status()
 *
 * Send back a cache sample message with the reachability
 * of the given locators set in the bitfield. Driven
 * by RLOC probing, for example.
 */
int update_locator_status(rloc_probe_item_t *item)
{
    lisp_cmd_t *cmd;
    int retval = 0;

    if ((cmd = malloc(sizeof(lisp_cmd_t) + item->msg_size)) == 0) {
        log_msg(INFO, "register_lispd_process -- malloc failed");
        return(0);
    }
    memset(cmd, 0, sizeof(lisp_cmd_t) + item->msg_size);

    cmd->type = LispCacheSample;
    cmd->length = item->msg_size;
    memcpy(cmd->val, item->msg, item->msg_size);

    retval = send_command(cmd, sizeof(lisp_cmd_t) + item->msg_size);
    free(cmd);
    return(retval);
}


/*
 *	register the lispd process with the kernel
 */
int register_lispd_process(void)
{
    lisp_cmd_t *cmd;
    int retval = 0;

    if ((cmd = malloc(sizeof(lisp_cmd_t))) == 0) {
        log_msg(INFO, "register_lispd_process -- malloc failed");
	return(0);
    }
    memset(cmd, 0, sizeof(lisp_cmd_t));

    cmd->type = LispDaemonRegister;
    cmd->length = 0;
    retval = send_command(cmd, sizeof(lisp_cmd_t));
    free(cmd);

    /*
     * Convey our personal UDP encap port to the kernel,
     * if necessary. TBD: Is this the best place to do this?
     */
    if (lispd_config.use_nat_lcaf) {
        set_udp_ports();
    }
    return(retval);
} 

/*
 * start_smr_traffic_monitor()
 *
 * Ask the kernel to begin monitoring traffic for
 * all entries in the map-cache. At the end
 * of the traffic monitoring period, the kernel
 * sends a list of all RLOCs within the EIDs
 * that had traffic.
 */
int start_smr_traffic_monitor(void)
{
    lisp_cmd_t *cmd;
    int retval = 0;

    if ((cmd = malloc(sizeof(lisp_cmd_t))) == 0) {
        log_msg(INFO, "request_rloc_list -- malloc failed");
        return(0);
    }
    memset(cmd, 0, sizeof(lisp_cmd_t));

    cmd->type = LispTrafficMonStart;
    cmd->length = 0;
    retval = send_command(cmd, sizeof(lisp_cmd_t));
    free(cmd);

    stop_timer(StartSMRs);

    log_msg(INFO, "Requested start of kernel traffic monitoring for SMRs");
    return(retval);
}

/*
 * set_udp_encap_port()
 *
 * Tell the kernel module what UDP ports to use for
 * encapsulation and control. This is primarily for NAT traversal
 * purposes, when the port may differ from the canonical
 * 4341/4342.
 */
int set_udp_ports(void) {
    lisp_cmd_t *cmd;
    lisp_set_ports_msg_t *msg;
    int retval = 0;

    if ((cmd = malloc(sizeof(lisp_cmd_t))) == 0) {
        log_msg(INFO, "set_udp_encap_port -- malloc failed");
        return(0);
    }
    memset(cmd, 0, sizeof(lisp_cmd_t));

    cmd->type         = LispSetUDPPorts;
    cmd->length       = sizeof(lisp_set_ports_msg_t);
    msg               = (lisp_set_ports_msg_t *)cmd->val;
    msg->data_port    = lispd_config.local_data_port;
    msg->control_port = lispd_config.local_control_port;

    retval = send_command(cmd, sizeof(lisp_cmd_t) + sizeof(*msg));
    free(cmd);

    log_msg(INFO, "Informed kernel of UDP ports %d/%d", lispd_config.local_data_port,
            lispd_config.local_control_port);
    return(retval);
}

