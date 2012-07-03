/*
 *	Handle lispd command line and config file
 *
 *	Parse command line args using gengetopt.
 *	Handle config file wiht libconfuse.
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Fri Apr 16 13:38:35 2010
 *
 *	$Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */
#include "lispd_packets.h"
#include "lispd_config.h"
#include "lispd_util.h"
#include "lispd_if.h"
#include "lispd_tuntap.h"

lispd_config_t lispd_config;

int set_petr_addr(char *);

/*
 *	handle_lispd_command_line --
 *
 *	Get command line args and set up whatever is needed
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Wed Apr 21 13:31:00 2010
 *
 *	$Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */
int handle_lispd_command_line(int argc, char **argv) 
{
    struct gengetopt_args_info args_info;

    if (cmdline_parser(argc, argv, &args_info) != 0) 
	exit(0);

    if (args_info.nodaemonize_given) {
        lispd_config.daemonize = 0;
    }
    if (args_info.config_file_given) {
        lispd_config.config_file = strdup(args_info.config_file_arg);
    }
    return(0);
}

/*
 *	handle_lispd_config_file --
 *
 *	Parse config file and set up whatever is needed
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Wed Apr 21 13:31:00 2010
 *
 *	$Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */
int handle_lispd_config_file(void)
{
    cfg_t		*cfg   = 0;
    unsigned int	i      = 0;
    unsigned		n      = 0;
    int			ret    = 0;

    static cfg_opt_t map_server_opts[] = {
	CFG_STR("address",		0, CFGF_NONE),
	CFG_INT("key-type",		0, CFGF_NONE),
	CFG_STR("key",			0, CFGF_NONE),
	CFG_BOOL("proxy-reply",		cfg_false, CFGF_NONE),
	CFG_BOOL("verify",		cfg_false, CFGF_NONE),
	CFG_END()
    };

    static cfg_opt_t mapping_opts[] = {
        CFG_STR("eid-prefix",		0, CFGF_NONE),
        CFG_BOOL("local",        cfg_true, CFGF_NONE),
        CFG_STR("rloc",                 0, CFGF_NONE),
        CFG_INT("priority",             1, CFGF_NONE),
        CFG_INT("weight",             100, CFGF_NONE),
	CFG_END()
    };

    cfg_opt_t if_opts[] = {
        CFG_STR("name", 0, CFGF_NONE),
        CFG_BOOL("detect-nat", 0, CFGF_NONE),
        CFG_STR("nat-global-address", 0, CFGF_NONE),
        CFG_INT("device-priority", 1, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opts[] = {
        CFG_BOOL("use-nat-tunneling", 0, CFGF_NONE),
	CFG_SEC("database-mapping",	mapping_opts, CFGF_MULTI),
	CFG_SEC("static-map-cache",	mapping_opts, CFGF_MULTI),
	CFG_SEC("map-server",		map_server_opts, CFGF_MULTI),
        CFG_INT("map-request-retries",	1, CFGF_NONE),
        CFG_INT("rloc-probe-retries", DEFAULT_PROBE_RETRIES, CFGF_NONE),
        CFG_INT("rloc-probe-interval", DEFAULT_PROBE_INTERVAL, CFGF_NONE),
	CFG_INT("control-port",		0, CFGF_NONE),
	CFG_BOOL("debug",		cfg_false, CFGF_NONE),
	CFG_STR("map-resolver",		0, CFGF_NONE),
        CFG_BOOL("use-ms-as-petr",      cfg_false, CFGF_NONE),
        CFG_STR("petr-address",         0, CFGF_NONE),
        CFG_STR("eid-interface",        "lo:1", CFGF_NONE),
        CFG_STR("eid-address-ipv4",          0, CFGF_NONE),
        CFG_STR("eid-address-ipv6",          0, CFGF_NONE),
        CFG_SEC("interface", if_opts, CFGF_MULTI),
        CFG_STR("override-dns-primary",         0, CFGF_NONE),
        CFG_STR("override-dns-secondary",       0, CFGF_NONE),
        CFG_STR("instance-id",                 0, CFGF_NONE),
        CFG_INT("tun-mtu", TUN_OVERRIDE_MTU, CFGF_NONE),
	CFG_END()
    };

    /*
     *	parse config_file
     */
    cfg = cfg_init(opts, CFGF_NOCASE);
    ret = cfg_parse(cfg, lispd_config.config_file);

    if (ret == CFG_FILE_ERROR) {
        log_msg(INFO, "Couldn't find config file (%s)", lispd_config.config_file);
        return 1;
    } else if(ret == CFG_PARSE_ERROR) {
        log_msg(INFO, "Parse error (%s)", lispd_config.config_file);
        return 2;
    }
    
    setup_log();

    /*
     *	lispd config options
     */
    if ((ret = cfg_getint(cfg, "tun-mtu")))
        lispd_config.tun_mtu = ret;
    if ((ret = cfg_getint(cfg, "map-request-retries")))
        lispd_config.map_request_retries = ret;
    if ((ret = cfg_getint(cfg, "rloc-probe-retries")))
        lispd_config.rloc_probe_retries = ret;
    if ((ret = cfg_getint(cfg, "rloc-probe-interval")))
        lispd_config.rloc_probe_interval = ret;
    if ((ret = cfg_getint(cfg, "use-nat-tunneling"))) {
        lispd_config.use_nat_lcaf = TRUE;
        lispd_config.local_control_port = LISP_LOCAL_CONTROL_PORT;
        log_msg(INFO, "Will use NAT tunneling LCAF format with local port %d",
                lispd_config.local_control_port);
    } else {
        lispd_config.use_nat_lcaf = FALSE;
        lispd_config.local_control_port = LISP_CONTROL_PORT;
        log_msg(INFO, "Not using NAT tunneling, control port is %d",
                lispd_config.local_control_port);
    }

    cfg_getbool(cfg, "debug") ? (lispd_config.debug = 1) : (lispd_config.debug = 0);

    /*
     *	handle map-server config
     */
    if ((n = cfg_size(cfg, "map-server"))) {
        for(i = 0; i < n; i++) {
            cfg_t *ms = cfg_getnsec(cfg, "map-server", i);
            if (!add_map_server(cfg_getstr(ms, "address"),
                                cfg_getint(ms, "key-type"),
                                cfg_getstr(ms, "key"),
                                (cfg_getbool(ms, "proxy-reply") ? 1:0),
                                (cfg_getbool(ms, "verify")      ? 1:0)))

                return(0);
        }
    }

    /*
     * Which interfaces do we consider as "locators". These
     * will be watched for changes.
     */
    if ((n = cfg_size(cfg, "interface"))) {
        for (i = 0; i < n; i++) {
            cfg_t *if_cfg = cfg_getnsec(cfg, "interface", i);
            if (!add_lisp_interface(if_cfg)) {
                log_msg(INFO, "Can't add interface %s",
                       cfg_getstr(if_cfg, "name"));
            }
        }
    } else {
        log_msg(INFO, "At least one interface must be specificed for LISP");
        return(0);
    }

    /*
     *	LISP config options
     */
    cfg_getbool(cfg, "use-ms-as-petr") ? (lispd_config.use_ms_as_petr = 1) : (lispd_config.use_ms_as_petr = 0);

    if (set_petr_addr(cfg_getstr(cfg, "petr-address"))) {
        if (lispd_config.use_ms_as_petr) {
            log_msg(INFO, "use-ms-as-petr cannot be set when petr-address is specified, disabling");
            lispd_config.use_ms_as_petr = FALSE;
        }
        lispd_config.petr_addr_is_set = TRUE;
    }

    /*
     * Override the system DNS? This can be useful in cases where
     * the DNS server provided by DHCP filters based on source address,
     * or fails uRPF.
     */
    lispd_config.use_dns_override = set_dns_override(cfg_getstr(cfg, "override-dns-primary"),
                                                     cfg_getstr(cfg, "override-dns-secondary"));

    /*
     * Use an instance ID?
     */
    lispd_config.use_instance_id = set_instance_id(cfg_getstr(cfg, "instance-id"));

    /*
     *	handle map-resolver config XXX should check for multiples, none
     */
    lispd_config.map_resolver_name = cfg_getstr(cfg, "map-resolver");
    if (!add_map_resolver(lispd_config.map_resolver_name)) {
        log_msg(INFO, "No map resolver configured!");
	return(0); 
    }

    /*
     * Chooses current best interface, sets up NAT and kernel
     * setup. Also called when an interface changes.
     */
    setup_eid(cfg);
    reconfigure_lisp_interfaces();

    /*
     *	handle database-mapping config
     */
    if ((n = cfg_size(cfg, "database-mapping"))) {
	for(i = 0; i < n; i++) {
	    cfg_t *dm = cfg_getnsec(cfg, "database-mapping", i);
            if (!add_database_mapping(dm)) {
                log_msg(INFO, "Can't add database-mapping %d (%s)",
		       i,
                       cfg_getstr(dm, "eid-prefix"));
	    }
	}
    }

    /*
     *	handle static-map-cache config
     */
    if ((n = cfg_size(cfg, "static-map-cache"))) {
	for(i = 0; i < n; i++) {
	    cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);
            if (!add_static_map_cache_entry(smc)) {
                log_msg(INFO,"Can't add static-map-cache %d (%s->%s)",
		       i,
		       cfg_getstr(smc, "eid-prefix"),
		       cfg_getstr(smc, "rloc"));
	    }
	}
    }

#if (DEBUG > 3)
    dump_tree(AF_INET,AF4_database);
    dump_tree(AF_INET6,AF6_database);
    dump_database();
    dump_map_servers();
    dump_map_resolvers();
    dump_map_cache();
#endif

    return(0);
}

/*
 * set_petr_addr
 *
 * Parse and set the petr address if given
 */
int set_petr_addr(char *petr_addr_str)
{
    uint afi;

    if (!petr_addr_str) {
        return(FALSE);
    }
    afi = get_afi(petr_addr_str);
    if (afi == AF_INET6) {
        log_msg(INFO, "IPv6 petr address not supported at this time, not using a petr");
        return(FALSE);
    }
    lispd_config.petr_addr.afi = afi;
    if (inet_pton(afi, petr_addr_str, &lispd_config.petr_addr.address.ip) != 1) {
        log_msg(INFO, "inet_pton: %s", strerror(errno));
        return(FALSE);
    }
    return(TRUE);
}

/*
 * set_instance_id
 *
 * Parse and set the instance-id if given.
 */
int set_instance_id(char *instance_str)
{
    lisp_cmd_t              *cmd;
    lisp_set_instance_msg_t *msg;
    int                      cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_set_instance_msg_t);


    if (!instance_str) {
        log_msg(INFO, "No instance ID configuration present.");
        return(FALSE);
    }

    lispd_config.instance_id = atoi(instance_str);

    if (!(cmd = (lisp_cmd_t *)malloc(sizeof(lisp_cmd_t) + sizeof(lisp_set_instance_msg_t)))) {
        log_msg(ERROR, "Failed to allocate IPC message buffer for set instance id message");
        return FALSE;
    }

    memset(cmd, 0, cmd_length);
    msg = (lisp_set_instance_msg_t *)cmd->val;
    msg->enable = TRUE;
    msg->id = lispd_config.instance_id;
    cmd->type = LispSetInstanceID;
    cmd->length = sizeof(lisp_set_instance_msg_t);
    if (send_command(cmd, cmd_length)) {
        free(cmd);
        log_msg(INFO, "Setting instance id to %d", lispd_config.instance_id);
        return TRUE;
    } else {
        free(cmd);
        log_msg(ERROR, "Failed to send set instance-id message to kernel");
        return FALSE;
    }
}

/*
 * set_dns_override
 *
 * Change the default DNS resolver address to something specified in the configuration
 * file. This uses the Android system properties, so may need to change based on version.
 */
int set_dns_override(char *dns_server1, char *dns_server2)
{

    char value1[128];
    char def_value1[128];

    char value2[128];
    char def_value2[128];

    char secondary_is_set = FALSE;

#ifndef ANDROID
    log_msg(ERROR, "DNS override is only supported on Android, option ignored.");
    return(FALSE);
#endif

    memset(value1, 0, 128);
    memset(value2, 0, 128);
    if (dns_server2 && !dns_server1) {
        log_msg(ERROR, "Secondary DNS server cannot be specified without a primary.");
        return(FALSE);
    }
    if (!dns_server1) {
        return(FALSE);
    }

    property_get("net.dns1", value1, 0);
    property_get("net.dns2", value2, 0);

    secondary_is_set = (strlen(value2) != 0);

    log_msg(INFO, "Current DNS Primary Address is %s", value1);

    if (secondary_is_set != 0) {
        log_msg(INFO, "Current DNS Secondary Address is %s ", value2);
    }

    lispd_config.original_dns_address1.afi = AF_INET;
    if (!inet_pton(AF_INET, value1, (void *)&lispd_config.original_dns_address1.address.ip)) {
        log_msg(ERROR, "Unable to store original primary DNS resolver address");
        return(FALSE);
    }

    if (secondary_is_set) {
        lispd_config.original_dns_address2.afi = AF_INET;
        if (!inet_pton(AF_INET, value2, (void *)&lispd_config.original_dns_address2.address.ip)) {
            log_msg(ERROR, "Unable to store original secondary DNS resolver address");
            return(FALSE);
        }
    } else {
        memset(&lispd_config.original_dns_address2, 0, sizeof(lisp_addr_t));
    }

    if (!inet_pton(AF_INET, dns_server1, (void *)&lispd_config.dns_override_address1.address.ip)) {
        log_msg(ERROR, "Unable to parse override primary DNS resolver address, check config");
        return(FALSE);
    }

    if (dns_server2) {
        if (!inet_pton(AF_INET, dns_server2, (void *)&lispd_config.dns_override_address2.address.ip)) {
            log_msg(ERROR, "Unable to parse override secondary DNS resolver address, check config");
            return(FALSE);
        }
    }

    property_set("net.dns1", dns_server1);

    if (dns_server2) {
        property_set("net.dns2", dns_server2);
        log_msg(INFO, "Set secondary DNS override.");
    }
    return(TRUE);
}

/*
 * restore_dns_servers
 *
 * Restore the original DNS resolver on exit, if we can.
 */
int restore_dns_servers(void)
{
    char server_str1[128];
    char server_str2[128];

#ifndef ANDROID
    log_msg(ERROR, "DNS override is only supported on Android");
    return(FALSE);
#endif

    if (!lispd_config.use_dns_override) {
        log_msg(INFO, "No DNS override set.");
        return(FALSE);
    }

    if (!inet_ntop(AF_INET, &lispd_config.original_dns_address1.address.ip,
                   server_str1, 128)) {
        log_msg(ERROR, "Unable to parse original DNS server string.");
        return(FALSE);
    } else {
        log_msg(INFO, "DNS Primary is now %s", server_str1);
    }

    if (lispd_config.original_dns_address2.address.ip.s_addr != 0) {
        if (!inet_ntop(AF_INET, &lispd_config.original_dns_address2.address.ip,
                       server_str2, 128)) {
            log_msg(ERROR, "Unable to parse original secondary DNS server string.");
        }
        property_set("net.dns2", server_str2);
        log_msg(INFO, "DNS Secondary is now %s", server_str2);
    } else {
        property_set("net.dns2", "");
    }
    property_set("net.dns1", server_str1);
    return(TRUE);
}

/*
 * set_kernel_rloc()
 *
 * Set the address the kernel uses for sourcing encapsulated packets.
 */
int set_kernel_rloc(lisp_addr_t *addr)
{
    lisp_set_rloc_msg_t  *rloc_msg;
    lisp_cmd_t           *cmd;
    int                   cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_set_rloc_msg_t) +
            sizeof(rloc_t);
    rloc_t               *rloc;

    if (!addr) {
        return FALSE;
    }

    if (!(cmd = (lisp_cmd_t *)malloc(cmd_length))) {
       return FALSE;
    }

    memset(cmd, 0, cmd_length);
    rloc_msg = (lisp_set_rloc_msg_t *)cmd->val;

    rloc = (rloc_t *)rloc_msg->rlocs;
    memcpy(&rloc->addr, addr, sizeof(lisp_addr_t));

    rloc->if_index = 0;
    rloc_msg->count = 1;
    cmd->type = LispSetRLOC;
    cmd->length = sizeof(lisp_set_rloc_msg_t) + sizeof(rloc_t);
    if (send_command(cmd, cmd_length)) {
        free(cmd);
        return TRUE;
    } else {
        free(cmd);
        return FALSE;
    }
}

/*
 *	add a map-resolver to the list
 */
int add_map_resolver(char *map_resolver)
{

    uint		afi;
    lisp_addr_t	*addr;
    lispd_addr_list_t  *list_elt;

    if (!map_resolver) {
        return(0);
    }

    if ((addr = (lisp_addr_t *) malloc(sizeof(lisp_addr_t))) == NULL) {
        log_msg(INFO, "malloc(sizeof(lisp_addr_t)): %s", strerror(errno));
	return(0);
    }
    memset(addr, 0, sizeof(lisp_addr_t));

    afi = get_afi(map_resolver);
    addr->afi = afi;

    if (inet_pton(afi, map_resolver, &(addr->address)) != 1) {
        log_msg(INFO, "inet_pton: %s", strerror(errno));
        free(addr);
	return(0);
    }

    if ((list_elt =
	 (lispd_addr_list_t *) malloc(sizeof(lispd_addr_list_t))) == NULL) {
        log_msg(INFO, "malloc(sizeof(lispd_addr_list_t)): %s", strerror(errno));
	free(addr);
	return(0);
    }
    memset(list_elt,0,sizeof(lispd_addr_list_t));

    list_elt->address = addr;

    /*
     * hook this one to the front of the list
     */

    if (lispd_config.map_resolvers) {
        list_elt->next = lispd_config.map_resolvers;
        lispd_config.map_resolvers = list_elt;
    } else 
        lispd_config.map_resolvers = list_elt;
    return(1);
}

/*
 *	add_map_server to map_servers
 */
int add_map_server(char *map_server, int key_type, char *key, uint8_t proxy_reply, uint8_t verify)
{
    int			     flags;
    lisp_addr_t	    *addr;
    lispd_map_server_list_t *list_elt;
    struct hostent	    *hptr;
    char                     debug_msg[128];

    if ((addr = (lisp_addr_t *) malloc(sizeof(lisp_addr_t))) == NULL) {
        log_msg(INFO, "malloc(sizeof(lisp_addr_t)): %s", strerror(errno));
	return(0);
    }

    /*
     *	make sure this is clean
     */

    memset(addr,0,sizeof(lisp_addr_t));

    if (((hptr = gethostbyname2(map_server,AF_INET))  == NULL) &&
	((hptr = gethostbyname2(map_server,AF_INET6)) == NULL)) {
        log_msg(INFO,
	       "can gethostbyname2 for map_server (%s)", map_server);
        free(addr);
	return(0);
    }

    memcpy((void *) &(addr->address),
	   (void *) *(hptr->h_addr_list), sizeof(lisp_addr_t));
    addr->afi = hptr->h_addrtype;

    if ((list_elt = (lispd_map_server_list_t *)
	 malloc(sizeof(lispd_map_server_list_t))) == NULL) {
        sprintf(debug_msg,"malloc(sizeof(lispd_map_server_list_t)) failed");
        log_msg(INFO, "%s", debug_msg);
	free(addr);
	return(0);
    }

    memset(list_elt,0,sizeof(lispd_map_server_list_t));

    list_elt->address     = addr;
    list_elt->key_type    = key_type;
    list_elt->key	  = strdup(key);
    list_elt->verify      = verify;
    list_elt->proxy_reply = proxy_reply;

    /*
     * hook this one to the front of the list
     */
    if (lispd_config.map_servers) {
        list_elt->next = lispd_config.map_servers;
        lispd_config.map_servers = list_elt;
    } else {
        lispd_config.map_servers = list_elt;
    }

    /*
     * install a host route for this server
     */
    return(1);
}

/*
 *	add_database_mapping
 *
 *	Add a single database mapping. Walks the interface list and adds a locator
 *      for each entry in the list.
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Wed Apr 21 13:31:00 2010
 *
 *	$Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */
int add_database_mapping(cfg_t	*dm)
{
    char			*token = NULL;
    char			*eid;		/* save the eid_prefix here */
    int				afi;
    uint32_t			flags = 0;
    patricia_node_t	        *node = NULL;
    lispd_locator_chain_t	*locator_chain;
    lispd_locator_chain_elt_t	*locator_chain_elt;
    lispd_if_t                  *ifp;
    char                         addr_buf[128];
    char   *eid_prefix        = cfg_getstr(dm, "eid-prefix");

    if (!eid_prefix) {
        log_msg(INFO, "EID prefix not specified in database mapping, skipping.");
        return(FALSE);
    }

    if (!cfg_getbool(dm, "local")) {
        log_msg(INFO, "Non-local database mappings not supported, skipping.");
        return(FALSE);
    }

    eid = eid_prefix;		/* save this for later */

    afi = get_afi(eid);

    /*
     *	find or make the node correspoding to the eid_prefix/length
     */
    switch(afi) {
    case AF_INET:
        node = make_and_lookup(AF4_database, AF_INET, eid);
        break;
    case AF_INET6:
        node = make_and_lookup(AF6_database, AF_INET6, eid);
        break;
    default:
        log_msg(INFO, "Unknown AFI (%d) for %s", afi, eid);
    }

    if (node == NULL) {
        log_msg(INFO, "Couldn't allocate patricia node");
        return(0);
    }

    if (node->data == NULL) {		/* it's a new node */
        if ((locator_chain = malloc(sizeof(lispd_locator_chain_t))) == NULL) {
            log_msg(INFO, "Can't malloc(sizeof(lispd_locator_chain_t))");
            return(0);
        }
        memset(locator_chain, 0, sizeof(lispd_locator_chain_t));

        node->data = (lispd_locator_chain_t *)locator_chain;	/* set up chain */

        if ((token = strtok(eid_prefix, "/")) == NULL) {
            log_msg(INFO,"eid prefix not of the form prefix/length");
            free(locator_chain);

            // Delete pt entry? XXX
            return(FALSE);
        }

        /*
         * put the eid_prefix information into the locator_chain
         */
        if (inet_pton(afi, token, &(locator_chain->eid_prefix.address)) != 1) {
            log_msg(INFO, "inet_pton: %s", strerror(errno));
            free(locator_chain);

            // Delete pt entry? XXX
            return(FALSE);
        }

        /*
         *	get the prefix length into token
         */
        if ((token = strtok(NULL,"/")) == NULL) {
            log_msg(INFO, "strtok: %s", strerror(errno));
            free(locator_chain);

            // Delete pt entry? XXX
            return(FALSE);
        }

        locator_chain->eid_prefix_length    = atoi(token);
        locator_chain->eid_prefix.afi       = afi;
        locator_chain->eid_name             = strdup(eid);
        locator_chain->has_dynamic_locators = flags;
        locator_chain->timer                = DEFAULT_MAP_REGISTER_TIMEOUT;
    } else {				/* there's an existing locator_chain */
        locator_chain = (lispd_locator_chain_t *)node->data;	/* have one */
    }

    /*
     * Walk the interface list
     */
    ifp = get_interface_list();
    if (!ifp) {
        log_msg(INFO, "No interfaces configured, skipping database entry.");
        return(FALSE);
    }

    while (ifp) {

        if ((locator_chain_elt = (lispd_locator_chain_elt_t *)
            malloc(sizeof(lispd_locator_chain_elt_t))) == NULL) {
            log_msg(INFO,"malloc(sizeof(lispd_locator_chain_elt_t)): %s", strerror(errno));
            return(0);
        }
        memset(locator_chain_elt, 0, sizeof(lispd_locator_chain_elt_t));
        locator_chain_elt->interface = ifp;
        locator_chain_elt->priority = 1;    // XXX hard coded single priority domain for now
        locator_chain_elt->locator_afi = 0; // Local locator, afi is in the interface struct
        locator_chain_elt->weight = 100; // Needs to be recomputed when interface count changes XXX
        locator_chain_elt->mpriority = 1;
        locator_chain_elt->mweight = locator_chain_elt->weight;
        locator_chain_elt->locator_type = STATIC_LOCATOR; //
        locator_chain_elt->locator_name = ifp->name; // Convenience
        afi = get_afi(eid_prefix);

        if ((token = strtok(eid_prefix, "/")) == NULL) {
            log_msg(INFO,"eid prefix not of the form prefix/length");
            free(locator_chain_elt);
            return(0);
        }

        /*
         * connect up the locator_chain and locator_chain_elt
         */
        switch(locator_chain_elt->locator_type) {
        case FQDN_LOCATOR:				/* splice on front of chain */
        case DYNAMIC_LOCATOR:
            if (locator_chain->head == NULL) {
                locator_chain->head = locator_chain_elt;
                locator_chain->tail = locator_chain_elt;
            } else {
                locator_chain_elt->next = locator_chain->head;
                locator_chain->head     = locator_chain_elt;
            }
            break;
        case STATIC_LOCATOR:			/* hook to the end of chain */
        default:
            if (locator_chain->head == NULL) {
                locator_chain->head = locator_chain_elt;
                locator_chain->tail = locator_chain_elt;
            } else {
                locator_chain->tail->next = locator_chain_elt;
                locator_chain->tail       = locator_chain_elt;
            }
        }
        ifp = ifp->next_if;
        locator_chain->locator_count++;
    }
    log_msg(INFO, "Added database entry for EID %s/%d with %d locators",
           inet_ntop(locator_chain->eid_prefix.afi,
                     &locator_chain->eid_prefix.address,
                     addr_buf, 128),
           locator_chain->eid_prefix_length,
           locator_chain->locator_count);
    return(TRUE);
}

/*
 *	add_static_map_cache_entry --
 *
 *	Get a single static mapping
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Wed Apr 21 13:31:00 2010
 *
 *	$Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */
int add_static_map_cache_entry(cfg_t *smc)
{

    lisp_addr_t	        *rloc_ptr;
    lispd_map_cache_t		*map_cache;
    lispd_map_cache_entry_t     *map_cache_entry;

    char			*token;
    int				afi;
    uint32_t			flags = 0;
    char                        debug_msg[128];

    char   *eid_prefix  = cfg_getstr(smc, "eid-prefix");
    char   *rloc        = cfg_getstr(smc, "rloc");
    int    priority     = cfg_getint(smc, "priority");
    int    weight       = cfg_getint(smc, "weight");

    if ((rloc_ptr = (lisp_addr_t *) malloc(sizeof(lisp_addr_t))) == NULL) {
        log_msg(INFO, "malloc(sizeof(lisp_addr_t)): %s", strerror(errno));
        return(0);
    }
    if ((map_cache = (lispd_map_cache_t *)
         malloc(sizeof(lispd_map_cache_t))) == NULL) {
        log_msg(INFO, "malloc(sizeof(lispd_map_cache_t)): %s", strerror(errno));
        return(0);
    }
    memset(rloc_ptr, 0,sizeof(lisp_addr_t));
    memset(map_cache,0,sizeof(lispd_map_cache_t));

    map_cache_entry = &(map_cache->map_cache_entry);

    if (!lispd_get_address(rloc, rloc_ptr, &flags)) {
        free(rloc_ptr);
        free(map_cache);
        return(0);
    }

    /*
     *	store the locator address and afi
     */
    memcpy((void *) &(map_cache_entry->locator.address),
           (void *) &(rloc_ptr->address),
           sizeof(lisp_addr_t));
    map_cache_entry->locator_afi  = rloc_ptr->afi;
    map_cache_entry->ttl          = 255;	/*shouldn't matter */
    map_cache_entry->locator_name = strdup(rloc);
    map_cache_entry->locator_type = flags;

    map_cache_entry->how_learned  = STATIC_MAP_CACHE_ENTRY;

    afi = get_afi(eid_prefix);

    if ((token = strtok(eid_prefix, "/")) == NULL) {
        sprintf(debug_msg,"eid prefix not of the form prefix/length ");
        log_msg(INFO, "%s", debug_msg);
        free(rloc_ptr);
        free(map_cache);
        return(0);
    }

    /*
     *	get the EID prefix into the right place/format
     */
    if (inet_pton(afi, token, &(map_cache_entry->eid_prefix.address)) != 1) {
        log_msg(INFO, "inet_pton: %s (%s)", strerror(errno), token);
        free(rloc_ptr);
        free(map_cache);
        return(0);
    }

    /*
     *	get the prefix length into token
     */
    if ((token = strtok(NULL,"/")) == NULL) {
        log_msg(INFO,"strtok: %s", strerror(errno));
        free(rloc_ptr);
        free(map_cache);
        return(0);
    }

    map_cache_entry->eid_prefix_length = atoi(token);
    map_cache_entry->priority          = priority;
    map_cache_entry->weight            = weight;

    if (lispd_map_cache)
        map_cache->next = lispd_map_cache;
    else
        map_cache->next = NULL;
    lispd_map_cache = map_cache;

    free(rloc_ptr);
    return(1);
}
