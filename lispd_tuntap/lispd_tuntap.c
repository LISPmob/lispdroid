/*
 * lisp_tuntap.c
 *
 * Main entry point and initialization code for the
 * LISP data-plane over TUN/TAP implementation.
 *
 * Copyright 2012 cisco Systems, Inc.
 */

#include <stdio.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <pthread.h>
#include "lispd.h"
#include "lispd_config.h"
#include "lispd_encap.h"
#include "lispd_tuntap.h"

const char *Tundev = "lisp_tun";
const unsigned int TunReceiveSize = 2048; // Should probably tune to match largest MTU
int tun_receive_fd = 0;
int tun_ifindex = 0;

int create_tun() {

    struct ifreq ifr;
    int err, tmpsocket, flags = IFF_TUN | IFF_NO_PI;
    char *clonedev = "/dev/tun";


    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if( (tun_receive_fd = open(clonedev, O_RDWR)) < 0 ) {
        log_msg(INFO, "TUN/TAP: Failed to open clone device");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */
    strncpy(ifr.ifr_name, Tundev, IFNAMSIZ);

    /* try to create the device */
    if ( (err = ioctl(tun_receive_fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        close(tun_receive_fd);
        log_msg(INFO, "TUN/TAP: Failed to create tunnel interface, errno: %d.", errno);
        return err;
    }

    // get the ifindex for the tun/tap
    tmpsocket = socket(AF_UNIX, SOCK_DGRAM, 0); // Dummy socket for the ioctl, type/details unimportant
    if ( (err = ioctl(tmpsocket, SIOCGIFINDEX, (void *)&ifr)) < 0 ) {
        close(tun_receive_fd);
        close(tmpsocket);
        log_msg(INFO, "TUN/TAP: unable to determine ifindex for tunnel interface, errno: %d.", errno);
        return err;
    } else {
        log_msg(INFO, "TUN/TAP ifindex is: %d", ifr.ifr_ifindex);
        tun_ifindex = ifr.ifr_ifindex;
    }

    close(tmpsocket);

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    log_msg(INFO, "tunnel fd at creation is %d", tun_receive_fd);
    return tun_receive_fd;
}

void *tun_recv(void *arg)
{
    char *rcvbuf;
    int   nread;

    rcvbuf = malloc(TunReceiveSize);
    while (1) {
        nread = read(tun_receive_fd, rcvbuf, TunReceiveSize);
        lisp_output4(rcvbuf, nread);
    }
}

void start_tun_recv()
{
    pthread_t receiver_thread;

    if (pthread_create(&receiver_thread, NULL, tun_recv, NULL) != 0) {
        log_msg(ERROR, "TUN/TAP receiver thread creation failed %s", strerror(errno));
        return;
    }
 //   pthread_detach(receiver_thread);
}


/*
 * install_default_route_v4()
 *
 * Set up the default route through the tunnel for ipv4.
 */
int install_default_route_v4(void)
{
    struct nlmsghdr *nlh;
    struct rtmsg    *rtm;
    struct rtattr  *rta;
    int             rta_len = 0;
    char   sndbuf[4096];
    char   addr_buf[128];
    char   addr_buf2[128];
    int    retval;
    int    sockfd;

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
          log_msg(INFO, "Failed to connect to netlink socket for install_default_route()");
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
    rta = (struct rtattr *)((char *)rtm + sizeof(struct rtmsg));
    rta->rta_type = RTA_DST;
    rta->rta_len = sizeof(struct rtattr) + sizeof(struct in_addr);

    // Address is already zeroed
    rta_len += rta->rta_len;

    /*
     * Add the outgoing interface
     */
    rta = (struct rtattr *)(((char *)rta) + rta->rta_len);
    rta->rta_type = RTA_OIF;
    rta->rta_len = sizeof(struct rtattr) + sizeof(tun_ifindex); // if_index
    memcpy(((char *)rta) + sizeof(struct rtattr), &tun_ifindex,
           sizeof(tun_ifindex));
    rta_len += rta->rta_len;

    nlh->nlmsg_len =   NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | (NLM_F_CREATE | NLM_F_REPLACE);
    nlh->nlmsg_type =  RTM_NEWROUTE;

    rtm->rtm_family    = AF_INET;
    rtm->rtm_table     = RT_TABLE_MAIN;

    rtm->rtm_protocol  = RTPROT_BOOT;
    rtm->rtm_scope     = RT_SCOPE_UNIVERSE;
    rtm->rtm_type      = RTN_UNICAST;

    rtm->rtm_dst_len   = 0;

    retval = send(sockfd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        log_msg(INFO, "install_default_route: send() failed %s", strerror(errno));
        close(sockfd);
        return(FALSE);
    }
    log_msg(INFO, "Installed default route via %s", Tundev);
    close(sockfd);
    return(TRUE);
}


/*
 * delete_default_route_v4()
 *
 * Delete whatever default route is currently installed.
 * This is done to override any changes that DHCP might make
 * out from under us.
 */
int delete_default_route_v4 (void)
{
    struct nlmsghdr *nlh;
    struct rtmsg    *rtm;
    struct rtattr  *rta;
    int             rta_len = 0;
    char   sndbuf[4096];
    char   addr_buf[128];
    int    retval;
    int    sockfd;

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
          log_msg(INFO, "Failed to connect to netlink socket for delete_default_route()");
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
    rta = (struct rtattr *)((char *)rtm + sizeof(struct rtmsg));
    rta->rta_type = RTA_DST;
    rta->rta_len = sizeof(struct rtattr) + sizeof(struct in_addr);

    // Address is already zeroed
    rta_len += rta->rta_len;

    nlh->nlmsg_len =   NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_type =  RTM_DELROUTE;

    rtm->rtm_family    = AF_INET;
    rtm->rtm_table     = RT_TABLE_MAIN;

   // rtm->rtm_protocol  = RTPROT_STATIC;
   // rtm->rtm_scope     = RT_SCOPE_UNIVERSE;
   // rtm->rtm_type      = RTN_UNICAST;

    rtm->rtm_dst_len   = 0;

    retval = send(sockfd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        log_msg(INFO, "delete_default_route: send() failed %s", strerror(errno));
        close(sockfd);
        return(FALSE);
    }
    log_msg(INFO, "Deleted default route via %s",
           Tundev);
    close(sockfd);
    return(TRUE);
}

/*
 * install_default_route_v6()
 *
 * Installs a default route through the TUN/TAP interface.
 */
static int install_default_route_v6(void)
{
    struct nlmsghdr *nlh;
    struct rtmsg    *rtm;
    struct rtattr  *rta;
    int             rta_len = 0;
    char   sndbuf[4096];
    char   addr_buf2[128];
    int    retval;
    int    sockfd;

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
          log_msg(INFO, "Failed to connect to netlink socket for install_default_route()");
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
    rta = (struct rtattr *)((char *)rtm + sizeof(struct rtmsg));
    rta->rta_type = RTA_DST;
    rta->rta_len = sizeof(struct rtattr) + sizeof(struct in6_addr);

    // Address is already zeroed
    rta_len += rta->rta_len;

    /*
     * Add the outgoing interface
     */
    rta = (struct rtattr *)(((char *)rta) + rta->rta_len);
    rta->rta_type = RTA_OIF;
    rta->rta_len = sizeof(struct rtattr) + sizeof(tun_ifindex); // if_index
    memcpy(((char *)rta) + sizeof(struct rtattr), &tun_ifindex,
           sizeof(tun_ifindex));
    rta_len += rta->rta_len;

    nlh->nlmsg_len =   NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
    nlh->nlmsg_type =  RTM_NEWROUTE;

    rtm->rtm_family  =  AF_INET6;
    rtm->rtm_table    = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
    rtm->rtm_type     = RTN_UNICAST;
    rtm->rtm_dst_len  = 0;

    retval = send(sockfd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        log_msg(INFO, "install_default_route: send() failed %s", strerror(errno));
        close(sockfd);
        return(FALSE);
    }
    log_msg(INFO, "Installed default route for interface %s using ipv6 EID %s",
           Tundev,
           inet_ntop(AF_INET6, lispd_config.eid_address_v6.address.ipv6.s6_addr,
                     addr_buf2, 128));
    close(sockfd);
    return(TRUE);
}

int install_default_routes(void) {

    if (lispd_config.eid_address_v4.afi) {
        if (!delete_default_route_v4()) {
            return(FALSE);
        }
        if (!install_default_route_v4()) {
            return(FALSE);
        }
    }
    if (lispd_config.eid_address_v6.afi) {
        if (!install_default_route_v6()) {
            return(FALSE);
        }
    }
    return(TRUE);
}

/*
 * assign_eid()
 *
 * Assign an EID to the TUN/TAP interface
 */
int set_tuntap_eid(lisp_addr_t *addr)
{
    struct ifreq ifr;
    struct sockaddr_in *sp;
    int    netsock;

    if (addr->afi == AF_INET) {
        netsock = socket(addr->afi, SOCK_DGRAM, 0);
        if (netsock < 0) {
            log_msg(INFO, "assign: socket() %s", strerror(errno));
            return(FALSE);
        }

        /*
         * Fill in the request
         */
        strcpy(ifr.ifr_name, Tundev);

        sp = (struct sockaddr_in *)&ifr.ifr_addr;
        sp->sin_family = addr->afi;
        sp->sin_addr = addr->address.ip;

        // Set the address
        ioctl(netsock, SIOCSIFADDR, &ifr);
        sp->sin_addr.s_addr = 0xFFFFFFFF;
        ioctl(netsock, SIOCSIFNETMASK, &ifr);
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING; // Bring it up
        ioctl(netsock, SIOCSIFFLAGS, &ifr);
        close(netsock);
        return(TRUE);
    } else if (addr->afi == AF_INET6) {

        /*
         * In this case, we just add the address
         * to the default loopback interface, no
         * neeed to create a new one.
         */
       // return(add_loopback_address_v6(addr)); XXX TUN/TAP
        return(TRUE);
    }
    log_msg(ERROR, "Unknown address family %d for EID in assign_eid()", addr->afi);
    return(FALSE);
}

