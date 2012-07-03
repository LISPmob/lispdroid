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
#include "lispd_decap.h"
#include "lispd_tuntap.h"
#include "packettypes.h"

const char *Tundev = "lisp_tun";
const unsigned int TunReceiveSize = 2048; // Should probably tune to match largest MTU
int tun_receive_fd = 0;
int tun_ifindex = 0;
char *tun_receive_buf = NULL;

int tuntap_set_eids(void);
int tuntap_create_tun() {

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
        return(FALSE);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */
    strncpy(ifr.ifr_name, Tundev, IFNAMSIZ);

    /* try to create the device */
    if ( (err = ioctl(tun_receive_fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        close(tun_receive_fd);
        log_msg(INFO, "TUN/TAP: Failed to create tunnel interface, errno: %d.", errno);
        return(FALSE);
    }

    // get the ifindex for the tun/tap
    tmpsocket = socket(AF_INET, SOCK_DGRAM, 0); // Dummy socket for the ioctl, type/details unimportant
    if ((err = ioctl(tmpsocket, SIOCGIFINDEX, (void *)&ifr)) < 0) {
        close(tun_receive_fd);
        close(tmpsocket);
        log_msg(INFO, "TUN/TAP: unable to determine ifindex for tunnel interface, errno: %d.", errno);
        return(FALSE);
    } else {
        log_msg(INFO, "TUN/TAP ifindex is: %d", ifr.ifr_ifindex);
        tun_ifindex = ifr.ifr_ifindex;

        // Set the MTU to the configured MTU
        ifr.ifr_ifru.ifru_mtu = lispd_config.tun_mtu;
        if ((err = ioctl(tmpsocket, SIOCSIFMTU, &ifr)) < 0) {
            close(tmpsocket);
            log_msg(INFO, "TUN/TAP: unable to set interface MTU to %d, errno: %d.",
                    lispd_config.tun_mtu, errno);
            return(FALSE);
        } else {
            log_msg(INFO, "TUN/TAP mtu set to %d", lispd_config.tun_mtu);
        }
    }

    close(tmpsocket);

    tun_receive_buf = (char *)malloc(TunReceiveSize);
    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    log_msg(INFO, "tunnel fd at creation is %d", tun_receive_fd);

    if (!tuntap_set_eids()) {
        return(FALSE);
    }

    if (!tuntap_install_default_routes()) {
        return(FALSE);
    }
    return(TRUE);
}

/*
 * tun_recv()
 *
 * Somewhat paradoxically, this handles *outgoing* packets (a read from the tunnel
 * amounts to receiving packets from the TCP/IP stack that are locally originated).
 *
 * Send the packet to the encapsulation routines.
 */
static void *tun_recv(void *arg)
{
    while (1) {
       tuntap_process_output_packet();
    }
    return NULL;
}

/*
 * tuntap_process_input_packet()
 *
 * Handle a data packet received on the LISP data port. Decapsulate,
 * then inject into the tunnel so that the TCP/IP stack can continue
 * processing.
 */
void tuntap_process_input_packet(char *packet_buf, int length, void *source)
{
    lisp_input(packet_buf, length, source);
}

/*
 * tuntap_process_output_packet
 *
 * Process an output packet, possibly destined for encapsulation.
 */
void tuntap_process_output_packet(void)
{
    int nread;

    log_msg(INFO, "In process_output_packet()");
    nread = read(tun_receive_fd, tun_receive_buf, TunReceiveSize);
    lisp_output4(tun_receive_buf, nread);
}

/*
 * tuntap_start_tun_recv()
 *
 * Create a thread to receive packets (remember, OUTGOING packets)
 * on the tunnel.
 */
void tuntap_start_tun_recv(void)
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
static int install_default_route_v4(void)
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
static int delete_default_route_v4 (void)
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

/*
 * tuntap_install_default_routes
 *
 * Create default routes through the TUN interface
 * for all address families.
 */
int tuntap_install_default_routes(void) {

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
 * tuntap_set_eid()
 *
 * Assign an EID to the TUN/TAP interface
 */
int tuntap_set_eids(void)
{
    struct ifreq ifr;
    struct sockaddr_in *sp;
    int    netsock, err;

    if (lispd_config.eid_address_v4.afi) {
        netsock = socket(lispd_config.eid_address_v4.afi, SOCK_DGRAM, 0);
        if (netsock < 0) {
            log_msg(INFO, "assign: socket() %s", strerror(errno));
            return(FALSE);
        }

        /*
         * Fill in the request
         */
        strcpy(ifr.ifr_name, Tundev);

        sp = (struct sockaddr_in *)&ifr.ifr_addr;
        sp->sin_family = lispd_config.eid_address_v4.afi;
        sp->sin_addr = lispd_config.eid_address_v4.address.ip;

        // Set the address

        if ((err = ioctl(netsock, SIOCSIFADDR, &ifr)) < 0) {
            log_msg(FATAL, "TUN/TAP could not set EID on tun device, errno %d.",
                    errno);
            return(FALSE);
        }
        sp->sin_addr.s_addr = 0xFFFFFFFF;
        if ((err = ioctl(netsock, SIOCSIFNETMASK, &ifr)) < 0) {
            log_msg(FATAL, "TUN/TAP could not set netmask on tun device, errno %d",
                    errno);
            return(FALSE);
        }
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING; // Bring it up

        if ((err = ioctl(netsock, SIOCSIFFLAGS, &ifr)) < 0) {
            log_msg(FATAL, "TUN/TAP could not bring up tun device, errno %d.",
                    errno);
            return(FALSE);
        }
        close(netsock);
    }

    if (lispd_config.eid_address_v6.afi) {

        /*
         * In this case, we just add the address
         * to the default loopback interface, no
         * neeed to create a new one.
         */
       // return(add_loopback_address_v6(addr)); XXX TUN/TAP
    }
    return(TRUE);
}

