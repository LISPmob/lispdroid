/*
 * lispd_if.c
 *
 * Interface property change handling for lispd. Owner
 * of the rtnetlink socket.
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems
 */

#include <cutils/properties.h>
#include <sys/system_properties.h>
#include <fcntl.h>
#include "lispd.h"
#include "lispd_if.h"
#include "lispd_config.h"
#include "lispd_map_register.h"
#include "lispd_db.h"
#include "lispd_packets.h"
#include "lispd_timers.h"
#include "lispd_netlink.h"
#include "lispd_util.h"
#include "lispd_tuntap.h"

extern int v4_receive_fd;
extern int rtnetlink_fd;
struct sockaddr_nl dst_addr, src_addr;

lispd_if_t *if_list = NULL;
lispd_if_t *primary_interface = NULL;

timer *default_gw_check_timer = NULL;
timer *nat_detect_retry_timer = NULL;

/*
 * is_nat_complete()
 *
 * Return whether NAT translation has completed for this interface
 */
inline int is_nat_complete(lispd_if_t *intf) {
    if (lispd_config.use_nat_lcaf) {
        return (intf->nat_complete == NAT_TRAVERSAL_COMPLETE);
    } else {
        return (intf->nat_complete == NAT_HAS_ADDR);
    }
}

/*
 * populate_ifaddr_entry()
 *
 * Fill in the ifaddr data structure with the info from
 * the rtnetlink message.
 */
int populate_ifaddr_entry(ifaddrs *ifaddr, int family, void *data, int ifindex, size_t count)
{
    char buf[IFNAMSIZ];
    char *name;
    void *dst;
    int   sockfd;
    struct ifreq ifr;
    int   retval;

    if (!((family == AF_INET) || (family == AF_INET6))) {
        log_msg(INFO, "Unsupported address family on interface");
        return -1;
    }
    name = if_indextoname(ifindex, buf);
    if (name == NULL) {
        log_msg(INFO, "Unable to convert index to interface name");
        return -1;
    }
    ifaddr->ifa_name = malloc(strlen(name) + 1);   // Must free elsewhere XXX
    strcpy(ifaddr->ifa_name, name);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        free(ifaddr->ifa_name);
        log_msg(INFO, "Socket error when trying to read interface flags");
        close(sockfd);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, name);

    retval = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    if (retval == -1) {
        log_msg(INFO, "ioctl error when trying to read interface flags");
        free(ifaddr->ifa_name);
        close(sockfd);
        return -1;

    }
    ifaddr->ifa_flags = ifr.ifr_flags;
    ifaddr->ifa_index = ifindex;
    ifaddr->ifa_addr = malloc(sizeof(struct sockaddr));
    ifaddr->ifa_addr->sa_family = family;

    dst = &((struct sockaddr_in *)(ifaddr->ifa_addr))->sin_addr;
    memcpy(dst, data, count);

    close(sockfd);
    return 0;
}

/*
 * getifaddrs()
 *
 * Android (and other) compatible getifaddrs function, using
 * rtnetlink. Enumerates all interfaces on the device.
 */
int getifaddrs(ifaddrs **addrlist) {
    request_struct        req;
    struct ifaddrmsg     *addr;
    ifaddrs              *prev;
    struct rtattr        *rta;
    int                   afi;
    size_t                msglen;
    int                   sockfd;
    char                  rcvbuf[4096];
    int                   readlen;
    int                   retval;
    struct nlmsghdr      *rcvhdr;

    *addrlist = NULL;

    /*
     * We open a separate socket here so the response can
     * be synchronous
     */
    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        log_msg(INFO, "Failed to connect to netlink socket for getifaddrs()");
        return -1;
    }

    /*
     * Construct the request
     */
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request_struct)));
    req.rtmsg.rtgen_family = AF_UNSPEC;

    /*
     * Send it
     */
    retval = send(sockfd, &req, req.nlh.nlmsg_len, 0);

    if (retval <= 0) {
        close(sockfd);
        return -1;
    }

    /*
     * Receive the responses from the kernel
     */
    while ((readlen = read(sockfd, rcvbuf, 4096)) > 0) {
        rcvhdr = (struct nlmsghdr *)rcvbuf;

        /*
         * Walk through everything it sent us
         */
        for (; NLMSG_OK(rcvhdr, readlen); rcvhdr = NLMSG_NEXT(rcvhdr, readlen)) {
            switch (rcvhdr->nlmsg_type) {
            case NLMSG_DONE:
                close(sockfd);
                return 0;
            case NLMSG_ERROR:
                close(sockfd);
                return -1;
            case RTM_NEWADDR:

                addr = (struct ifaddrmsg *)NLMSG_DATA(rcvhdr);
                rta = IFA_RTA(addr);
                msglen = IFA_PAYLOAD(rcvhdr);

                while (RTA_OK(rta, msglen)) {

                    /*
                     * Only care about local addresses of our interfaces
                     */
                    if (rta->rta_type == IFA_LOCAL) {
                        afi = addr->ifa_family;
                        if ((afi == AF_INET) || (afi == AF_INET6)) {

                            if (*addrlist) {
                                prev = *addrlist;
                            } else {
                                prev = NULL;
                            }
                            *addrlist = malloc(sizeof(ifaddrs));  // Must free elsewhere XXX
                            memset(*addrlist, 0, sizeof(ifaddrs));
                            (*addrlist)->ifa_next = prev;
                            populate_ifaddr_entry(*addrlist, afi, RTA_DATA(rta), addr->ifa_index, RTA_PAYLOAD(rta));
                        }
                    }
                    rta = RTA_NEXT(rta, msglen);
                }
                break;
            default:
                break;
            }

        }
    }
    close(sockfd);
    return 0;
}

/*
 * populate_interface_info()
 *
 * Given an ifname, get everything about it's current state
 * and place in the interface structure.
 */
int populate_interface_info(lispd_if_t *ifp, int afi)
{
    lisp_addr_t        *addr;
    struct ifaddrs      *ifaddr;
    struct ifaddrs      *ifa;
    struct sockaddr_in  *s4;
    struct sockaddr_in6 *s6;

    if ((addr = malloc(sizeof(lisp_addr_t))) == NULL) {
        log_msg(INFO, "malloc (populate_interface_info): %s", strerror(errno));
        return(0);
    }

    memset(addr,0,sizeof(lisp_addr_t));

    if (getifaddrs(&ifaddr) !=0) {
        log_msg(INFO, "getifaddrs (populate_interface_info): %s", strerror(errno));
        free(addr);
        return(0);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr             == NULL) ||
            (ifa->ifa_addr->sa_family  != afi)  ||
            strcmp(ifa->ifa_name, ifp->name))
            continue;
        switch(ifa->ifa_addr->sa_family) {
        case AF_INET:
            s4 = (struct sockaddr_in *)(ifa->ifa_addr);
            memcpy((void *)&(ifp->address),
                   (void *)&(s4->sin_addr), sizeof(struct sockaddr_in));

            ifp->address.afi = (ifa->ifa_addr)->sa_family;
            ifp->flags = ifa->ifa_flags;
            ifp->if_index = ifa->ifa_index;
            free(addr);
            return(TRUE);
        case AF_INET6: // Unsupported XXX
            free(addr);
            return(FALSE);
        default:
            continue;                   /* keep looking */
        }
    }
    free(addr);
 // freeaddrlist(ifaddr); XXX
    return(FALSE);                          /* no luck */
}

/*
 * add_lisp_interface()
 *
 * Add an interface to our list of watched interfaces.
 */
int add_lisp_interface(cfg_t *if_cfg) {

    char *ifname;
    char *nat_addr;
    char *gw_addr;
    lispd_if_t *ifp;
    char  detect_nat = FALSE;

    if (!(ifname = cfg_getstr(if_cfg, "name"))) {
        log_msg(INFO, "Config syntax error: no interface name specified");
        return(FALSE);
    }

    nat_addr = cfg_getstr(if_cfg, "nat-global-address");
    log_msg(INFO, "Adding %s as LISP interface", ifname);
    if (nat_addr) {
        log_msg(INFO, "   with NAT addr: %s", nat_addr);
    };

    detect_nat = cfg_getbool(if_cfg, "detect-nat");
    if (detect_nat && nat_addr) {
        log_msg(INFO, "Syntax error in config for %s: both detect-nat and nat-global-address specified",
               ifname);
        return(FALSE);
    }   

    ifp = (lispd_if_t *)malloc(sizeof(lispd_if_t));
    if (!ifp) {
        log_msg(INFO, "malloc: (lispd_if_t) %s", strerror(errno));
        return(FALSE);
    }
    memset(ifp, 0, sizeof(lispd_if_t));

    ifp->name = malloc(strlen(ifname));
    strcpy(ifp->name, ifname);
    ifp->dev_prio = cfg_getint(if_cfg, "device-priority");

    if (!populate_interface_info(ifp, AF_INET)) {
            log_msg(INFO, "Interface %s is currently not configured will watch for later appearance.", ifname);
    }

    /*
     * Two nat options: static config, or determine dynamically using
     * LISP echo.
     */
    ifp->nat_type = NATOff;
    if (nat_addr) {
       ifp->nat_type = NATStatic;
       ifp->nat_complete |= NAT_HAS_ADDR; // Static NAT

       // Write the interface NAT address
       inet_pton(AF_INET, nat_addr, (void *)&ifp->nat_address.address.ip);
       ifp->nat_address.afi = AF_INET;
    }

    /*
     * Dynamic mode
     */
    if (detect_nat) {
        ifp->nat_type = NATDynamic;
        ifp->nat_complete = NAT_INCOMPLETE;
    }

    if (!if_list) {
        if_list = ifp;
    } else {
        if_list->next_if = ifp;
    }
    return(TRUE);
}

/*
 * get_best_interface()
 *
 * Get the current highest priority, up interface in the list.
 * This is used for sourcing packets.
 */
lispd_if_t *get_best_interface(void)
{
    lispd_if_t *best = NULL;
    lispd_if_t *current = if_list;
    int best_prio = -1;
    int checkflags;

    while (current) {
        checkflags = current->flags & (IFF_UP | IFF_RUNNING);
        log_msg(INFO, "Checking on %s as candidate best interface, flags 0x%x",
               current->name, current->flags);
        if ((checkflags == (IFF_UP | IFF_RUNNING)) && (current->address.address.ip.s_addr != 0)) { // V4 XXX
            if ((best_prio == -1) || (best_prio > current->dev_prio)) {
                best_prio = current->dev_prio;
                best = current;
            } // First of given priority is what gets returned. May want to prefer wifi type?
        } else {
            log_msg(INFO, "   %s fails availability check", current->name);
        }
        current = current->next_if;
    }
    return(best);
}

/*
 * get_primary_interface()
 *
 * Return the current best interface
 */
lispd_if_t *get_primary_interface(void)
{
    return primary_interface;
}

/*
 * get_current_default_gw()
 *
 * Queries the Android property list to get the
 * current default gatweay for an interface.
 *
 * Returns TRUE if there has been a change to the gateway,
 * false otherwise (or if no gateway).
 *
 * THIS IS ANDROID ONLY.
 */
unsigned int get_current_default_gw(lispd_if_t *intf)
{
    char prop_name[128];
    char value[128];
    char def_value[128];
    lisp_addr_t old_gateway = intf->default_gw;

#ifndef ANDROID
    log_msg(ERR, "Cannot get default gateway on non-Android systems at this time");
    return(FALSE);
#endif
    sprintf(prop_name, "net.%s.gw", intf->name);
    property_get(prop_name, value, def_value);

    if (!inet_pton(AF_INET, value, (void *)&intf->default_gw.address.ip)) {
        log_msg(INFO, "Unable to set default gateway on interface using net.*, trying dhcp.*");
        sprintf(prop_name, "dhcp.%s.gateway", intf->name);
        property_get(prop_name, value, def_value);
         if (!inet_pton(AF_INET, value, (void *)&intf->default_gw.address.ip)) {
             log_msg(INFO, "  ... Failed.");
             return FALSE;
         }
    }
    log_msg(INFO, "Detected default gateway on %s is %s", intf->name,
           value);
    if (old_gateway.address.ip.s_addr == intf->default_gw.address.ip.s_addr) {
        log_msg(INFO, "   No change from before.");
        return FALSE;
    }
    return TRUE;
}

/*
 * reconfigure_lisp_interfaces()
 *
 * Due to config or status change, reevaluate the new best
 * interface and update the kernel as necessary
 */
void reconfigure_lisp_interfaces(void)
{
    primary_interface = get_best_interface();

    /*
     * Earliest opportunity to create this timer. Move to an
     * init function? XXX
     */
    if (!nat_detect_retry_timer) {
        nat_detect_retry_timer = create_timer("NAT Detect");
    }
    if (primary_interface == NULL) {
        log_msg(INFO, "No active interfaces");
        return;
    }
    log_msg(INFO, "Primary interface is now %s", primary_interface->name);

    /*
     * Set the MTU to account for LISP header. XXX Remove when fragmentation works
     */
    set_interface_mtu(primary_interface);

    if (!is_nat_complete(primary_interface) && (primary_interface->nat_type != NATOff)) {
        setup_nat(primary_interface);
    } else {
        set_kernel_rloc(&primary_interface->address);
    }

    /*
     * Always check to see if we need to reset default routes
     */
    check_default_gateway(default_gw_check_timer, NULL);

    if (!default_gw_check_timer) {
        default_gw_check_timer = create_timer("GW Check");
    }
    start_timer(default_gw_check_timer, GATEWAY_DETECT_TIME,
                check_default_gateway, NULL);
}

/*
 * check_default_gateway
 *
 * Detect if the default gateway has changed. If so, update our
 * special routes.
 */
void check_default_gateway(timer *t, void *arg)
{
    if (primary_interface && get_current_default_gw(primary_interface)) {
        tuntap_install_default_routes();
        update_map_server_routes();
    }
    stop_timer(t);
}

/*
 * setup_rtnetlink()
 *
 * Set up the route netlink socket and bind to it
 */
int setup_rtnetlink(void)
{
    int flags;

    if ((rtnetlink_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        return(FALSE);
    }

    // Set to non-blocking
    flags = fcntl(rtnetlink_fd, F_GETFL, 0);

    if (flags & O_NONBLOCK) {
        log_msg(INFO, "  odd, non-blocking was already set!");
    } else {
        flags = fcntl(rtnetlink_fd, F_SETFL,
                      flags | O_NONBLOCK);
    }
    if (flags == -1) {
        log_msg(INFO, "  failed to set rtnetlink socket to non-blocking");
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_LINK | RTMGRP_IPV4_ROUTE;
                       //  RTMGRP_; // Link status changes and IPv4 addr/route changes

    if (bind(rtnetlink_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) == -1) {
        return(FALSE);
    }

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;
    return(TRUE);
}

/*
 * find_lisp_interface()
 *
 * Given an interface name, find a corresponding
 * lisp interface structure (if any).
 */
lispd_if_t *find_lisp_interface(char *name)
{
    lispd_if_t *intf = if_list;

    if (!name) {
        return(NULL);
    }
    while (intf) {
        if (!strcmp(intf->name, name)) {
            return(intf);
        }
        intf = intf->next_if;
    }
    return(NULL);
}

/*
 * handle_if_status_change()
 *
 * Deal with a notification of interface status (link status)
 */
void handle_if_status_change(struct ifinfomsg *ifi)
{
    lispd_if_t *intf;
    char name[IFNAMSIZ];

    if ((intf = find_lisp_interface(if_indextoname(ifi->ifi_index, name))) == NULL) {
        log_msg(INFO, "Interface not managed by lispd, ignoring.");
        return;
    }

    /*
     * Update index if necessary
     */
    intf->if_index = ifi->ifi_index;

    /*
     * Check for flag change
     */
    if (intf->flags == ifi->ifi_flags) {
        return;
    }

    log_msg(INFO, "Interface %s status changed, old flags 0x%x, new flags 0x%x",
           intf->name, intf->flags, ifi->ifi_flags);

    intf->flags = ifi->ifi_flags;

    /*
     * Clear the ip address, NAT Status and default gateway if down.
     */
    if (!((intf->flags & IFF_UP) || (intf->flags & IFF_RUNNING))) {
        intf->default_gw.address.ip.s_addr = 0;
        intf->address.address.ip.s_addr = 0;
        intf->nat_complete = NAT_INCOMPLETE;
        intf->translated_encap_port = 0;
    }

    /*
     * Check for NAT status change, update the kernel if necessary.
     */
    reconfigure_lisp_interfaces();

    /*
     * Update our mappings
     */
    install_database_mappings();
    map_register(NULL, NULL);
}

/*
 * handle_ip_address_change()
 *
 * Deal with a notification of address change
 */
void handle_ip_address_change(struct ifaddrmsg *ifa, uint32_t addr)
{
    lispd_if_t *intf;
    char addr_buf[128];
    char addr_buf2[128];
    char name[IFNAMSIZ];

    if ((intf = find_lisp_interface(if_indextoname(ifa->ifa_index, name))) == NULL) {
        log_msg(INFO, "Interface not managed by lispd, ignoring.");
        return;
    }

    /*
     * V4 only for now XXX
     */
    log_msg(INFO, "Interface %s owned by lispd, addr %s, new addr %s",
           intf->name, inet_ntop(intf->address.afi, &intf->address,
                                 addr_buf, 128),
           inet_ntop(AF_INET, &addr, addr_buf2, 128));
    intf->address.afi = AF_INET;
    memcpy(&intf->address, &addr, sizeof(struct in_addr));

    // The kernel gives us network byte order for these
    intf->address.address.ip.s_addr = ntohl(intf->address.address.ip.s_addr);

    /*
     * Clear NAT status, if applicable
     */
    if (intf->nat_type == NATDynamic) {
        intf->nat_complete = NAT_INCOMPLETE;
        intf->translated_encap_port = 0;
        lispd_config.translated_control_port = 0;
        log_msg(INFO, "   Clearing NAT traversal configuration.");
    }

    reconfigure_lisp_interfaces();

    /*
     * Update our mappings
     */
    install_database_mappings();
    map_register(NULL, NULL);
}

/*
 * handle_route_change()
 *
 * Someone else has changed one of our routes. This is probably due
 * to a DHCP change after an interface status change. Since this
 * can occur long after we got the interface notification, we have
 * to deal with it, because the default router may have not been
 * reset until later.
 */
#define RTA_ADDR(_x) (struct in_addr *)((char *)_x + sizeof(struct rtattr))

void handle_route_change(struct rtmsg *rtm, unsigned int msg_len)
{
    struct rtattr* rta = NULL;
    struct in_addr *dst = NULL;
    struct in_addr *gw  = NULL;
    struct in_addr *pref_src = NULL;
    char is_default         = TRUE;
    char src_is_set         = FALSE;
    unsigned int  oif_index = 0;

    /*
     * Check if anything has happened to the default
     * route. If it has, it's likely the default gateway
     * just changed. Update the routes with our versions.
     */
    log_msg(INFO, "RTM Prot: %d, scope: %d, type: %d, flags: %d",
            rtm->rtm_protocol, rtm->rtm_scope, rtm->rtm_type,
            rtm->rtm_flags);

    rta = RTM_RTA(rtm);

    for (; msg_len && RTA_OK(rta, msg_len); rta = RTA_NEXT(rta, msg_len))
    {

        switch (rta->rta_type) {

        case RTA_GATEWAY:
            gw = RTA_ADDR(rta);
            break;
        case RTA_DST:
            dst = RTA_ADDR(rta);
            if (dst->s_addr != 0) {
                is_default = FALSE;
            }
            break;
        case RTA_PREFSRC:
            pref_src = RTA_ADDR(rta);
            src_is_set = TRUE;
            break;
        case RTA_OIF:
            oif_index = *(unsigned int *)(((char *)rta) + sizeof(struct rtattr));
            break;
        default:
            break;
        }
    }

    /*
     * We only care about changes to default
     */
    if (!is_default) {
        log_msg(INFO, "Route change not for default, ignoring.");
        return;
    }

    /*
     * See if this is really a change. It's possible this is a notification
     * about our own change earlier, in which case, ignore it.
     */
    if (gw && (gw->s_addr != primary_interface->default_gw.address.ip.s_addr) ||
            (primary_interface && (oif_index != primary_interface->if_index)) ||
            !src_is_set ||
            (pref_src && (pref_src->s_addr != lispd_config.eid_address_v4.address.ip.s_addr))) {

        log_msg(INFO, "Default route has changed (possibly by DHCP), overriding.");

        delete_default_route_v4(primary_interface);
        update_map_server_routes();

#ifndef TUNTAP
        install_default_routes(primary_interface, FALSE);
#endif
    } else {
        log_msg(INFO, "Default route has not changed, ignoring.");
    }
    log_msg(INFO, "Out");
}

/*
 * process_interface_notification()
 *
 * Deal with an interface status change notification from the kernel
 */
void process_interface_notification(void)
{
    char buffer[IF_MSG_SIZE];
    int  len, payload_len;
    struct nlmsghdr *nlh;
    struct ifaddrmsg *ifa;
    struct ifinfomsg *ifi;
    struct rtattr    *rta;

    nlh = (struct nlmsghdr *)buffer;
    while ((len = recv(rtnetlink_fd, nlh, IF_MSG_SIZE, 0)) > 0)
    {
        for (;(NLMSG_OK (nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE); nlh = NLMSG_NEXT(nlh, len))
        {
            switch (nlh->nlmsg_type) {
            case RTM_NEWADDR:

                log_msg(INFO, "Got interface address change notification.");

                ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
                rta = IFA_RTA(ifa);
                payload_len = IFA_PAYLOAD(nlh);
                for (; payload_len && RTA_OK(rta, payload_len); rta = RTA_NEXT(rta, payload_len))
                {
                    char name[IFNAMSIZ];
                    uint32_t ipaddr;

                    if (rta->rta_type != IFA_LOCAL) continue;

                    ipaddr = *((uint32_t *)RTA_DATA(rta));
                    ipaddr = htonl(ipaddr);

                    log_msg(INFO, "Received IP status change for: %s",
                           if_indextoname(ifa->ifa_index, name));
                    handle_ip_address_change(ifa, ipaddr);  // Simple for now: interface and new (v4) address XXX
                }

                break;

            case RTM_NEWLINK:

                ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);

                /* No friendly macros help here */
                rta = ((struct rtattr *)(((char *)(ifi) + NLMSG_ALIGN(sizeof(struct ifinfomsg)))));
                payload_len = NLMSG_PAYLOAD(nlh, sizeof(struct ifinfomsg));;

                handle_if_status_change(ifi); // Interface and status change
                break;

            case RTM_NEWROUTE:
                log_msg(INFO, "Got new route change/added notification.");
                handle_route_change((struct rtmsg *)NLMSG_DATA(nlh), RTM_PAYLOAD(nlh));
                break;
            case RTM_DELROUTE:
                log_msg(INFO, "Got route deletion notification.");
                break;

            default:
                log_msg(INFO, "Unknown message type from kernel on rtnetlink: 0x%x",
                        nlh->nlmsg_type);
                break;
            }

        }
    }
}

/*
 * get_interface_list()
 *
 * Return a pointer to the current interface list
 */
lispd_if_t *get_interface_list(void)
{
    return(if_list);
}

/*
 * get_live_interface_count()
 *
 * Returns the number of configured and active interfaces
 */
int get_live_interface_count(void)
{
    lispd_if_t  *ifp = if_list;
    int count = 0;

    while (ifp) {
        if ((ifp->flags & IFF_UP) && (ifp->address.address.ip.s_addr != 0)) { // IPV4 only
            count++;
        }
        ifp = ifp->next_if;
    }
    return(count);
}

/*
 * get_configured interface_count()
 *
 * Returns the number of configured interface, up or down.
 */
int get_configured_interface_count(void)
{
    lispd_if_t  *ifp = if_list;
    int count = 0;

    while (ifp) {
        count++;
        ifp = ifp->next_if;
    }
    return(count);
}

/*
 * set_interface_mtu()
 *
 * Set the mtu for a given interface to the override value.
 * Uses the ioctl interface for simplicity, but could be done
 * with netlink.
 */
int set_interface_mtu(lispd_if_t *intf)
{
    struct ifreq ifr;
    int    netsock;

    netsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (netsock < 0) {
        log_msg(INFO, "set_interface_mtu: socket() %s", strerror(errno));
        return(FALSE);
    }

   /*
    * Fill in the request
    */
    strcpy(ifr.ifr_name, intf->name);
    ifr.ifr_ifru.ifru_mtu = OVERRIDE_MTU;

    // Set the address
    ioctl(netsock, SIOCSIFMTU, &ifr);
    close(netsock);
    return(TRUE);
}

/*
 * cleanup_routes()
 *
 * Restore the original routes used before LISP was enabled.
 */
void cleanup_routes() {

    if (tuntap_restore_default_routes()) {
        log_msg(INFO, "Restored default routes.");
    } else {
        log_msg(ERROR, "Failed to restore default routes.");
    }
}

/*
 * setup_eid()
 *
 * Tell the kernel routing table to source all connections
 * from the loopback associated with lisp.
 */
int setup_eid(cfg_t *cfg)
{
    lisp_addr_t *addr;
    char        *v4_eid_str;
    char        *v6_eid_str;
    char         addr_buf[128];


    v4_eid_str = cfg_getstr(cfg, "eid-address-ipv4");
    v6_eid_str = cfg_getstr(cfg, "eid-address-ipv6");

    if (!(v6_eid_str || v4_eid_str)) {
        log_msg(ERROR, "Configuration error: at least one ipv4 or ipv6 EID must be specified.");
        return(FALSE);
    }

    if (v4_eid_str) {
        if (!inet_pton(AF_INET, v4_eid_str, &lispd_config.eid_address_v4.address.ip)) {
            log_msg(ERROR, "Configuration error: cannot parse the specified ipv4 EID");
            return(FALSE);
        }
        lispd_config.eid_address_v4.afi = AF_INET;
    }

    if (v6_eid_str) {
        if (!inet_pton(AF_INET6, v6_eid_str, lispd_config.eid_address_v6.address.ipv6.s6_addr)) {
            log_msg(ERROR, "Configuration error: cannot parse the specified ipv6 EID");
            return(FALSE);
        }
        lispd_config.eid_address_v6.afi = AF_INET6;
    }

    return(TRUE);
}

/*
 * add_loopback_address_v6
 *
 * Installs a host route to the specified interface. This
 * is specifically for ipv6, since we can have many
 * loopback addresses hanging off lo without creating
 * a new one.
 */
int add_loopback_address_v6(lisp_addr_t *addr)
{
    unsigned int         loindex;
    struct rtattr       *rta;
    struct ifaddrmsg    *ifa;
    struct nlmsghdr     *nlh;
    char                 sndbuf[4096];
    int                  retval;
    int                  sockfd;

    if (!addr) {
        return(FALSE);
    }

    loindex = if_nametoindex("lo");

    if (loindex == 0) {
        log_msg(ERROR, "add_loopback_address_v6: unable to proceed, cannot find index for interface lo");
        return(FALSE);
    }

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
          log_msg(INFO, "Failed to connect to netlink socket for install_host_route()");
        return(FALSE);
    }

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);
    nlh = (struct nlmsghdr *)sndbuf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg) + sizeof(struct rtattr) +
                                  sizeof(struct in6_addr));
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_type = RTM_NEWADDR;
    ifa = sndbuf + sizeof(struct nlmsghdr);

    ifa->ifa_prefixlen = 128;
    ifa->ifa_family = AF_INET6;
    ifa->ifa_index  = loindex;
    ifa->ifa_scope = RT_SCOPE_HOST;
    rta = sndbuf + sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg);
    rta->rta_type = IFA_LOCAL;

    rta->rta_len = sizeof(struct rtattr) + sizeof(struct in6_addr);
    memcpy(((char *)rta) + sizeof(struct rtattr), addr->address.ipv6.s6_addr,
           sizeof(struct in6_addr));

    retval = send(sockfd, sndbuf, nlh->nlmsg_len, 0);

    if (retval < 0) {
        log_msg(INFO, "add_loopback_address_v6: send() failed %s", strerror(errno));
        close(sockfd);
        return(FALSE);
    }

    log_msg(INFO, "added ipv6 EID to loopback.");
    close(sockfd);
    return(TRUE);
}

/*
 * install_host_route()
 *
 * Installs a host route through the specified interface.
 */
int install_host_route(lisp_addr_t *host, lispd_if_t *intf)
{
    struct sockaddr_nl nladdr;
    struct nlmsghdr *nlh;
    struct rtmsg    *rtm;
    struct rtattr  *rta;
    int             rta_len = 0;
    char   sndbuf[4096];
    int    readlen;
    int    retval;
    struct nlmsghdr *rcvhdr;
    int    sockfd;

    if (!intf) {
        return(FALSE);
    }

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
          log_msg(INFO, "Failed to connect to netlink socket for install_host_route()");
        return(FALSE);
    }

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);

    nlh = (struct nlmsghdr *)sndbuf;
    rtm = (struct rtmsg *)(sndbuf + sizeof(struct nlmsghdr));

    rta_len = sizeof(struct rtmsg);

    /*
     * Add the destination
     */
    rta = (struct rtattr*)((char *)rtm + sizeof(struct rtmsg));
    rta->rta_type = RTA_DST;
    rta->rta_len = sizeof(struct rtattr) + sizeof(host->address.ip);
    memcpy(((char *)rta) + sizeof(struct rtattr), &host->address.ip,
           sizeof(host->address.ip));
    rta_len += rta->rta_len;

    /*
     * Add the outgoing interface
     */
    rta = (struct rtattr *)(((char *)rta) + rta->rta_len);
    rta->rta_type = RTA_OIF;
    rta->rta_len = sizeof(struct rtattr) + sizeof(intf->if_index); // if_index
    memcpy(((char *)rta) + sizeof(struct rtattr), &intf->if_index,
           sizeof(intf->if_index));
    rta_len += rta->rta_len;

    /*
     * Add the gateway
     */
    rta = (struct rtattr *)(((char *)rta) + rta->rta_len);
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len = sizeof(struct rtattr) + sizeof(intf->default_gw.address.ip); // if_index
    memcpy(((char *)rta) + sizeof(struct rtattr), &intf->default_gw.address.ip,
           sizeof(intf->default_gw.address.ip));
    rta_len += rta->rta_len;

    nlh->nlmsg_len =   NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE;
    nlh->nlmsg_type =  RTM_NEWROUTE;

    rtm->rtm_family = AF_INET;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_dst_len = 32;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    retval = send(sockfd, sndbuf, NLMSG_LENGTH(rta_len), 0); // XXXX FIXME: Length looks wrong

    if (retval < 0) {
        log_msg(INFO, "install_hostroute: send() failed %s", strerror(errno));
        close(sockfd);
        return(FALSE);
    }
    close(sockfd);
    return(TRUE);
}

/*
 * setup_nat()
 *
 * Set the nat global address and enable NAT fixups
 */
int setup_nat(lispd_if_t *intf)
{
    uint afi;
    lisp_addr_t        *local_addr;
    char               *interface = intf->name;
    char                addr_str[128];

    if (!intf) {
        return(FALSE);
    }

    afi = intf->address.afi;
    if (afi == AF_INET6) {
        log_msg(INFO, "IPv6 nat source not supported at this time, using non-nat mode (may not work!)");
        return(FALSE);
    }

    /*
     * Always use the local interface address as the source "rloc" in the kernel,
     * so it will be translated.
     */
    if (!set_kernel_rloc(&intf->address)) {
        log_msg(INFO, "Failed to set kernel RLOC to local address");
        return(FALSE);
    }

    if (!is_nat_complete(intf)) {
        start_timer(nat_detect_retry_timer, NAT_QUICK_CHECK_TIME, check_nat_status,
                    NULL);
        send_lisp_echo_request(intf);
        log_msg(INFO, "NAT enabled, determining global address...");
    } else {
        log_msg(INFO, "NAT enabled, using global address of %s",
                         inet_ntop(intf->nat_address.afi,
                         &intf->nat_address.address.ip,
                         addr_str, 128));
    }
    return(FALSE);
}

/*
 * update_map_server_routes()
 *
 * Update the host routes to the map servers if
 * the primary interface changed.
 */
void update_map_server_routes(void)
{
    lispd_map_server_list_t *ms = lispd_config.map_servers;

    if (!primary_interface) {
        return;
    }

    /*
     * Install one for each map server
     */
    while (ms) {
        install_host_route(ms->address, primary_interface);
        ms = ms->next;
    }

    /*
     * And one for the map resolver
     */
    install_host_route(lispd_config.map_resolvers->address,
                       primary_interface);
}

/*
 * check_nat_status()
 *
 * Run the NAT detect process for any interfaces
 * that have NAT enabled. Currently this process
 * only works on the primary interface. If
 * we're multi-homing, we may want to do this
 * continously on all interfaces (how to force
 * packets out one or the other?)
 *
 * To fix: make per interface timers or flags for
 * this process XXX
 */
void check_nat_status(timer *t, void *arg)
{
    lispd_if_t *intf = if_list;
    char requests_out = FALSE;

    while (intf) {
        if (intf != primary_interface) { // Only do this process for the primary interface.
            intf = intf->next_if;
            continue;
        }
        log_msg(INFO, "Rechecking NAT status for interface %s", intf->name);
        if ((intf->nat_type == NATDynamic)) {
            send_lisp_echo_request(intf);
            requests_out = TRUE;
        }
        intf = intf->next_if;
    }
    if (requests_out) {
        start_timer(nat_detect_retry_timer, NAT_QUICK_CHECK_TIME,  check_nat_status,
                    NULL);
    } else {
        log_msg(INFO, "Starting periodic NAT detection timer.");
        stop_timer(nat_detect_retry_timer);
        start_timer(nat_detect_retry_timer, NAT_PERIODIC_CHECK_TIME,  check_nat_status,
                    NULL);
    }
}

/*
 * nat_should_change()
 *
 * Determine if the response values in a lisp echo indicate
 * we should change the nat configuration on this interface.
 * This could be due to a global address change, or a translated
 * port change.
 */
int nat_should_change(lispd_if_t *intf, uint32_t reply_addr, uint16_t translated_port,
                      uint16_t sport)
{

    if (!is_nat_complete(intf)) {
        return TRUE;
    }

    /*
     * Globa IP changed
     */
    if (memcmp(&intf->nat_address.address.ip,
               &reply_addr, sizeof(struct in_addr))) {
        return TRUE;
    }

    /*
     * Source port is data port? Check if translated
     * data port should change.
     */
    if (sport == lispd_config.data_port) {
        if (intf->translated_encap_port != translated_port) {
            return TRUE;
        }
    }

    /*
     * Source port is control port? Check if translated
     * control port should change.
     */
    if (sport == lispd_config.control_port) {
        if (lispd_config.translated_control_port != translated_port) {
            return TRUE;
        }
    }

    /*
     * Nothing changed
     */
    return FALSE;

}

/*
 * process_lisp_echo_reply()
 *
 * Check if an incoming LISP echo packet matches an outstanding
 * request, if so, set the interface's NAT address from the
 * global address in the packet.
 */
int process_lisp_echo_reply(lispd_pkt_echo_t *pkt, uint16_t sport)
{
    lispd_pkt_echo_reply_t *reply;
    lispd_pkt_nat_lcaf_t   *nat_lcaf;
    lispd_pkt_lcaf_addr_t  *lcaf_addr;
    lispd_pkt_lcaf_t       *lcaf;
    lispd_if_t             *intf = if_list;
    uint16_t                translated_port = 0;
    uint16_t                afi;
    uint32_t                reply_addr;     // V4 Only for now
    char                    addr_buf[128];

    reply = pkt->data;

    if (!pkt->echo_reply) {
        log_msg(INFO, "  Echo requests not supported");
        return(FALSE);
    }
    afi = ntohs(reply->afi);

    switch (afi) {
    case LISP_AFI_IP:

        memcpy(&reply_addr, reply->address, sizeof(struct in_addr));
        break;
    case LISP_AFI_LCAF:

        lcaf = (lispd_pkt_lcaf_t *)reply;
        log_msg(INFO, "    Echo reply contains LCAF %d, type %d",
                afi, lcaf->type);
        if (lcaf->type != LISP_LCAF_NAT) {
            log_msg(ERROR, "    Unsupported LISP LCAF type %d", lcaf->type);
            dump_message(reply, (sizeof(lispd_pkt_echo_reply_t) + sizeof(lispd_pkt_lcaf_t)
                         + sizeof(lispd_pkt_nat_lcaf_t)) * 2);
            return(FALSE);
        }
        nat_lcaf = (lispd_pkt_nat_lcaf_t *)lcaf->address;

        log_msg(INFO, "    Translated LCAF-NAT port %d, ours was %d or %d",
                    ntohs(nat_lcaf->port), lispd_config.local_control_port,
                    lispd_config.local_data_port);

        translated_port = ntohs(nat_lcaf->port);
        lcaf_addr = (lispd_pkt_lcaf_addr_t *)nat_lcaf->addresses;

        if (ntohs(lcaf_addr->afi) == LISP_AFI_IP) {
            memcpy(&reply_addr, lcaf_addr->address, sizeof(struct in_addr));
        } else {
            log_msg(ERROR, "    Unsupported LISP AFI %d in LISP LCAF", ntohs(lcaf_addr->afi));
            return(FALSE);
        }
        break;
    default:

        log_msg(ERROR, "    Unsupported LISP AFI %d in LISP echo-reply",
                ntohs(reply->afi));
        return(FALSE);
        break;
    }

    /*
     * Walk the interface list and see
     * if any are NAT and waiting for completion or, if
     * our public address has changed.
     */
    while (intf) {
        if (intf->nat_type == NATDynamic) {
            if (intf->nat_request_nonce == pkt->nonce) { // Keep track of two nonces for NAT? XXX
                if (nat_should_change(intf, reply_addr, translated_port, ntohs(sport))) {

                    intf->nat_address.afi = AF_INET; // XXX V4 only for now
                    intf->nat_complete |= NAT_HAS_ADDR;
                    memcpy(&intf->nat_address.address.ip, &reply_addr,
                           sizeof(struct in_addr));
                     log_msg(INFO, "Setting global interface address for %s to %s",
                            intf->name,
                            inet_ntop(AF_INET, &intf->nat_address.address.ip,
                                      addr_buf, 128));

                    if (lispd_config.use_nat_lcaf) {
                        if ((ntohs(sport) == lispd_config.data_port)) {
                            intf->translated_encap_port = translated_port;
                            intf->nat_complete |= NAT_HAS_ENCAP;
                            log_msg(INFO, "     Set translated data port to %d", intf->translated_encap_port);
                        } else if (ntohs(sport) == lispd_config.control_port) {
                            lispd_config.translated_control_port = translated_port;
                            intf->nat_complete |= NAT_HAS_CONTROL;
                            log_msg(INFO, "     Set translated control port to %d", lispd_config.translated_control_port);
                        }
                    }

                    /*
                     * Force a reconfigure and map-register if we're done.
                     * The live interface count check is a hack for now
                     * because when both interfaces are momentarily up
                     * during switchover, we don't control where the echos
                     * go. So the first responses may indicate the rmnet0's
                     * address on eth0 erroneously. XXX
                     *
                     */
                    if (is_nat_complete(intf) && (get_live_interface_count() == 1)) {
                        reconfigure_lisp_interfaces();
                        install_database_mappings();
                        map_register(NULL, NULL);
                        start_timer(nat_detect_retry_timer, NAT_PERIODIC_CHECK_TIME,  check_nat_status,
                                    NULL);
                    } else {

                        // Keep trying at a fast rate until complete.
                        start_timer(nat_detect_retry_timer, NAT_QUICK_CHECK_TIME,  check_nat_status,
                                    NULL);
                    }

                    return(TRUE);
                } else {

                    log_msg(INFO, "     Address unchanged or interface not-NAT");
                    start_timer(nat_detect_retry_timer, NAT_PERIODIC_CHECK_TIME,  check_nat_status,
                                NULL);
                    return(TRUE);
                }
            }
        }

        /*
         * Recheck default gateway
         */
        check_default_gateway(NULL, NULL);
        intf = intf->next_if;
    }
    log_msg(INFO, "No matching incomplete NAT interface found (normal with NAT traversal 2nd echo)");
    return(FALSE);
}

/*
 * send_lisp_echo_request()
 *
 * Send a LISP echo packet to our map-server, use
 * the returned address as our NAT global address.
 */
int send_lisp_echo_request(lispd_if_t *intf)
{
    lispd_pkt_echo_t      *pkt;
    lispd_pkt_lcaf_t      *lcaf;
    lispd_pkt_nat_lcaf_t  *nat_lcaf;
    lispd_pkt_lcaf_addr_t *lcaf_addr;
    struct sockaddr_in    map_server;
    int                   nbytes, size;
    char                  addr_buf[128];

    if (lispd_config.use_nat_lcaf) {
        size = sizeof(lispd_pkt_echo_t) + sizeof(lispd_pkt_lcaf_t) +
               sizeof(lispd_pkt_nat_lcaf_t) + 3 * sizeof(lispd_pkt_lcaf_addr_t); // XXX v4 only
    } else {
        size = sizeof(lispd_pkt_echo_t);
    }
    pkt = malloc(size);
    if (!pkt) {
        log_msg(INFO, "malloc: (send_lisp_echo_request) %s", strerror(errno));
        return(FALSE);
    }

    memset(pkt, 0, size);
    pkt->type = LISP_ECHO;
    pkt->echo_reply = 0;
    pkt->nonce = build_nonce((unsigned int)time(NULL));

    if (lispd_config.use_nat_lcaf) {
        lcaf = (lispd_pkt_lcaf_t *)pkt->data;
        lcaf->afi = htons(LISP_AFI_LCAF);
        lcaf->length = htons(4 + 3 * sizeof(uint16_t));
        lcaf->flags = 0;
        lcaf->type = LISP_LCAF_NAT;
        nat_lcaf = (lispd_pkt_nat_lcaf_t *)lcaf->address;
        nat_lcaf->port = htons(lispd_config.local_control_port);

        /*
         * Fill in NULL afi's for the three addresses
         * (global, private and NTR RLOCs).
         */
        lcaf_addr = (lispd_pkt_lcaf_addr_t *)nat_lcaf->addresses;
        lcaf_addr->afi = 0;
        lcaf_addr = (lispd_pkt_lcaf_addr_t *)lcaf_addr->address;
        lcaf_addr->afi = 0;
        lcaf_addr = (lispd_pkt_lcaf_addr_t *)lcaf_addr->address;
        lcaf_addr->afi = 0;
    }
    memset((char *)&map_server, 0, sizeof(struct sockaddr_in));
    map_server.sin_family = AF_INET;
    map_server.sin_addr.s_addr = lispd_config.map_servers->address->address.ip.s_addr;
    map_server.sin_port = htons(lispd_config.control_port);

    if ((nbytes = sendto(v4_receive_fd, (const void *)pkt,
                         sizeof(lispd_pkt_echo_t),
                         0,
                         (struct sockaddr *)&map_server,
                         sizeof(struct sockaddr))) < 0) {
        log_msg(INFO, "sendto (send_lisp_echo_request): %s", strerror(errno));
        free(pkt);
        return(FALSE);
    }

    /*
     * If using NAT traversal, send one from the data port as well.
     * TBD: If sourcing from two different ports, we'll need to do
     * this whole this with a raw socket since we're bound to the
     * control port. (Or bind to the data port?)
     */
    if (lispd_config.use_nat_lcaf) {
        map_server.sin_port = htons(lispd_config.data_port);
        if ((nbytes = sendto(v4_receive_fd, (const void *)pkt,
                             sizeof(lispd_pkt_echo_t),
                             0,
                             (struct sockaddr *)&map_server,
                             sizeof(struct sockaddr))) < 0) {
            log_msg(INFO, "sendto (send_lisp_echo_request (2)): %s", strerror(errno));
            free(pkt);
            return(FALSE);
        }
        log_msg(INFO, "   Additional LISP echo will be sent for data port translation.");
    }

    log_msg(INFO, "Sent LISP echo request(s) to %s",
           inet_ntop(AF_INET, &map_server.sin_addr,
                     addr_buf, 128));

    intf->nat_request_nonce = pkt->nonce;
    free(pkt);
    return(TRUE);
}
