/*
 * lispd_events.c
 *
 * Event loop and dispatch for the lispd process.
 * This is the main run loop of the process.
 *
 * Author: Dave Meyer and Chris White
 * Copyright 2010 Cisco Systems
 */

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "lispd.h"
#include "lispd_config.h"
#include "lispd_events.h"
#include "lispd_packets.h"
#include "lispd_netlink.h"
#include "lispd_map_reply.h"
#include "lispd_timers.h"
#include "lispd_tuntap.h"
#include "packettypes.h"

static int signal_pipe[2]; // We don't have signalfd in bionic, fake it.

/*
 *	sockets (fds)
 */
int	v6_receive_fd			= 0;
int	v4_receive_fd			= 0;
int	netlink_fd			= 0;
int     signal_fd                       = 0;
int     rtnetlink_fd                    = 0;
int     data_receive_fd                 = 0;
fd_set  readfds;

/*
 * event_sig_handler
 *
 * Forward signal to the fd for handling in the event loop
 */
static void event_sig_handler(int sig)
{
    if (write(signal_pipe[1], &sig, sizeof(sig)) != sizeof(sig)) {
        log_msg(ERROR, "write signal %d: %s", sig, strerror(errno));
    }
}

/*
 * build_event_socket
 *
 * Set up the event handler socket. This is
 * used to serialize events like timer expirations that
 * we would rather deal with synchronously. This avoids
 * having to deal with all sorts of locking and multithreading
 * nonsense.
 */
int build_event_socket(void)
{
    int i, flags;
    struct sigaction sa;

    if (pipe(signal_pipe) == -1) {
        log_msg(ERROR, "signal pipe setup failed %s", strerror(errno));
        return 0;
    }
    signal_fd = signal_pipe[0];

    if ((flags = fcntl(signal_fd, F_GETFL, 0)) == -1) {
        log_msg(ERROR, "fcntl() F_GETFL failed %s", strerror(errno));
        return 0;
    }
    if (fcntl(signal_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_msg(ERROR, "fcntl() set O_NONBLOCK failed %s", strerror(errno));
        return 0;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = event_sig_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGRTMIN, &sa, NULL) == -1) {
        log_msg(ERROR, "sigaction() failed %s", strerror(errno));
    }
    return(1);
}

/*
 *      build_receive_sockets
 *
 *      Set up the receive sockets. Note that if you use a
 *      a random port, which is used as  the source port used
 *      in the inner UDP header of the encapsulated
 *      map-request. If proxy-reply on, you will receive map-replies
 *      destined to this port (i.e., the destination port). e.g.,
 *
 *      No. Time     Source         Destination     Protocol Info
 *      97  5.704114 128.223.156.23 128.223.156.117 LISP     Map-Reply
 *      ...
 *      Internet Protocol, Src: 128.223.156.23 (128.223.156.23), Dst: 128.223.156.117 (128.223.156.117)
 *      User Datagram Protocol, Src Port: lisp-control (4342), Dst Port: 48849 (48849)
 *      Locator/ID Separation Protocol
 *
 *      In this case, 48849 was the random source port I put in the
 *      inner UDP header source port in the encapsulated map-request
 *      which was sent to to the map-server at 128.223.156.23.
 *
 *      So we'll just use src port == dest port == 4342. Note that you
 *      need to setsockopt SO_REUSEADDR or you'll get bind: address in use.
 *
 */
int build_receive_sockets(void)
{

    struct protoent     *proto;
    struct sockaddr_in  v4;
    struct sockaddr_in6 v6;
    int                 tr =1;

    /*
     *  build the v4_receive_fd, and make the port reusable
     */
    if ((v4_receive_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_msg(ERROR, "socket (v4): %s", strerror(errno));
        return(0);
    }

    if (setsockopt(v4_receive_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &tr,
                   sizeof(int)) == -1) {
        log_msg(ERROR, "setsockopt (v4): %s", strerror(errno));
        return(0);
    }

    v4.sin_port        = htons(lispd_config.local_control_port);
    v4.sin_family      = AF_INET;
    v4.sin_addr.s_addr = INADDR_ANY;

    if (bind(v4_receive_fd,(struct sockaddr *) &v4, sizeof(v4)) == -1) {
        log_msg(ERROR, "bind (v4): %s", strerror(errno));
        return(0);
    }

    /*
     * build the v4 data packet receive socket.
     */
    /*
     *  build the data_receive_fd, and make the port reusable
     */
    if ((data_receive_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        log_msg(ERROR, "socket (v4): %s", strerror(errno));
        return(0);
    }

    if (setsockopt(data_receive_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &tr,
                   sizeof(int)) == -1) {
        log_msg(ERROR, "setsockopt (v4): %s", strerror(errno));
        return(0);
    }

    v4.sin_port        = htons(lispd_config.local_data_port);
    v4.sin_family      = AF_INET;
    v4.sin_addr.s_addr = INADDR_ANY;

    if (bind(data_receive_fd,(struct sockaddr *) &v4, sizeof(v4)) == -1) {
        log_msg(ERROR, "bind (v4): %s", strerror(errno));
        return(0);
    }
#ifndef ANDROID
    /*
     *  build the v6_receive_fd, and make the port reusable
     */
    if ((v6_receive_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_msg(ERROR, "socket (v6): %s", strerror(errno));
        return(0);
    }

    if (setsockopt(v6_receive_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &tr,
                   sizeof(int)) == -1) {
        log_msg(ERROR, "setsockopt (v6): %s", strerror(errno));
        return(0);
    }

    memset(&v6,0,sizeof(v6));                   /* be sure */
    v6.sin6_family   = AF_INET6;
    v6.sin6_port     = htons(LISP_CONTROL_PORT);
    v6.sin6_addr     = in6addr_any;

    if (bind(v6_receive_fd,(struct sockaddr *) &v6, sizeof(v6)) == -1) {
        log_msg(ERROR, "bind (v6): %s", strerror(errno));
        return(0);
    }
#endif
    return(1);
}

/*
 *	select from among readfds, the largest of which
 *	is max_fd.
 */
int have_input(int max_fd, fd_set *readfds)
{

    struct timeval tv;

    tv.tv_sec  = 0;
    tv.tv_usec = DEFAULT_SELECT_TIMEOUT;

    if (select(max_fd+1,readfds,NULL,NULL,&tv) == -1) {
        if (errno == EINTR) {
            return(0);
        } else {
          log_msg(ERROR, "select: %s", strerror(errno));
          return(-1);
      }
    }
    return(1);
}

/*
 *	Process a LISP protocol message sitting on
 *	socket s with address family afi
 */
int process_lisp_msg(int s, int afi)
{

    uint8_t	        packet[MAX_IP_PACKET];
    struct sockaddr_in  s4;
    struct sockaddr_in6 s6;

    switch(afi) {
    case AF_INET:
        memset(&s4, 0, sizeof(struct sockaddr_in));
        if (!retrieve_lisp_msg(s, packet, &s4, afi))
            return(0);
        /* process it here */
        break;
    case AF_INET6:
        memset(&s6,0,sizeof(struct sockaddr_in6));
        if (!retrieve_lisp_msg(s, packet, &s6, afi))
            return(0);
        /* process it here */
        break;
    default:
        return(0);
    }
    return(1);
}

int process_event_signal(void)
{
    int  timertype = 0;
    int sig;
    int  bytes;

    bytes = read(signal_fd, &sig, sizeof(sig));

    if (bytes != sizeof(sig)) {
        log_msg(ERROR, "process_event_signal(): nothing to read");
        return(-1);
    }

    if (sig == SIGRTMIN) {
        handle_timers();
    }
    return(0);
}

/*
 *	Retrieve a mesage from socket s
 */
int retrieve_lisp_msg(int s, uint8_t *packet, void *from, int afi)
{

    struct sockaddr_in  *s4 = NULL;
    struct sockaddr_in6 *s6 = NULL;
    char                addr_buf[128];
    int			fromlen4 = sizeof(struct sockaddr_in);
    int			fromlen6 = sizeof(struct sockaddr_in6);
    int                 recv_len;

    switch(afi) {
    case AF_INET:
        s4 = (struct sockaddr_in *) from;
        if ((recv_len = recvfrom(s,
                     packet,
                     MAX_IP_PACKET,
                     0,
                     (struct sockaddr *) s4,
                     &fromlen4)) < 0) {
            log_msg(ERROR, "recvfrom (v4): %s", strerror(errno));
            return(0);
        }
        break;
    case AF_INET6:
        s6 = (struct sockaddr_in6 *) from;
        if (recvfrom(s,
                     packet,
                     MAX_IP_PACKET,
                     0,
                     (struct sockaddr *) s6,
                     &fromlen6) < 0) {
            log_msg(ERROR, "recvfrom (v6): %s", strerror(errno));
            return(0);
        }
        break;
    default:
        log_msg(INFO, "retrieve_msg: Unknown afi %d", afi);
        return(0);
    }

    // HACK! xxx This is here instead of in a thread in lispd_tuntap.c
    // because the current NAT traversal scheme shares the data and control
    // ports and we have no way of listening to the data port separately. This
    // also assumes v6 over v4 for now.
    if ((ntohs(s4->sin_port) == LISP_DATA_PORT) && (((lispd_pkt_encapsulated_control_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE)) {
        tuntap_process_input_packet(packet, recv_len, from);
        return(1);
    }

    if (((lispd_pkt_encapsulated_control_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE) {
        log_msg(INFO, "Received encapsulated control message, decapsulating...");
        packet = decapsulate_ecm_packet(packet);
    }

    log_msg(INFO, "Received LISP control packet with sport %d",
            ntohs(s4->sin_port));

    /*
     * This only works because the type
     * field is in the same location in all lisp control
     * messages. Could case it to anything, the choice
     * of lispd_pkt_encapsulated_control_t is arbitrary.
     */
    switch (((lispd_pkt_encapsulated_control_t *) packet)->type) {
    case LISP_MAP_REPLY:
        log_msg(INFO, "Received map-reply from %s", inet_ntop(AF_INET,
                                                              &s4->sin_addr,
                                                              addr_buf,
                                                              128));
        process_map_reply((lispd_pkt_map_reply_t *)packet);
        break;
    case LISP_MAP_REQUEST:
        log_msg(INFO, "Received map-request");
        process_map_request((lispd_pkt_map_request_t *)packet, s4);
        break;
    case LISP_MAP_REGISTER:
        log_msg(INFO, "Received map-register");
        break;
    case LISP_ENCAP_CONTROL_TYPE:
        log_msg(INFO, "Received encapsulated control message");
        break;
    case LISP_ECHO:
        log_msg(INFO, "Received LISP echo");
        process_lisp_echo_reply((lispd_pkt_echo_t *)packet, s4->sin_port);
        break;
    default:
        log_msg(INFO, "Received unknown LISP packet type %d",
               ((lispd_pkt_encapsulated_control_t *)packet)->type);
        break;
    }
    return(1);
}

/*
 *	main event loop
 *
 *	should never return (in theory)
 */
void event_loop(void)
{
    int    max_fd;
    fd_set readfds;
    int    retval;

    /*
     *	calculate the max_fd for select.
     */

    log_msg(INFO, "tunnel fd in event_loop is: %d", tun_receive_fd);
    max_fd = (v4_receive_fd > v6_receive_fd) ? v4_receive_fd : v6_receive_fd;
  //  max_fd = (max_fd > netlink_fd)           ? max_fd : netlink_fd;
    max_fd = (max_fd > signal_fd)            ? max_fd : signal_fd;
    max_fd = (max_fd > rtnetlink_fd)         ? max_fd : rtnetlink_fd;
    max_fd = (max_fd > tun_receive_fd)       ? max_fd : tun_receive_fd;
    max_fd = (max_fd > data_receive_fd)      ? max_fd : data_receive_fd;
    for (EVER) {
        FD_ZERO(&readfds);
        FD_SET(v4_receive_fd, &readfds);
   //     FD_SET(v6_receive_fd, &readfds);
   //     FD_SET(netlink_fd, &readfds);
        FD_SET(signal_fd, &readfds);
        FD_SET(rtnetlink_fd, &readfds);
        FD_SET(tun_receive_fd, &readfds);
        FD_SET(data_receive_fd, &readfds);

        retval = have_input(max_fd, &readfds);
        if (retval == -1) {
            break;           /* doom */
        }
        if (retval == 0) {
            continue;        /* interrupted */
        }

        if (FD_ISSET(v4_receive_fd, &readfds))
            process_lisp_msg(v4_receive_fd, AF_INET);
     //   if (FD_ISSET(v6_receive_fd, &readfds)) {
     //       process_lisp_msg(v6_receive_fd, AF_INET6);
     //   }
      //  if (FD_ISSET(netlink_fd, &readfds)) {
      //      process_kernel_msg();
      //  }
        if (FD_ISSET(signal_fd, &readfds)) {
            process_event_signal();
        }
        if (FD_ISSET(rtnetlink_fd, &readfds)) {
            process_interface_notification();
        }
        if (FD_ISSET(tun_receive_fd, &readfds)) {
            tuntap_process_output_packet();
        }
       // if (FD_ISSET(data_receive_fd, &readfds)) {
       //     process_input_packet(NULL, 0);
       // }
    }
}

void signal_handler(int sig) {
    switch(sig) {
    case SIGHUP:
        log_msg(WARNING, "Received SIGHUP signal.");
        break;
    case SIGINT:
        log_msg(WARNING, "Received SIGINT signal.");
    case SIGTERM:
        log_msg(WARNING, "Received SIGTERM signal");
    case SIGKILL:
        log_msg(WARNING, "Received SIGKILL signal.");
        log_msg(WARNING, "Cleaning up routes...");
        cleanup_routes();

        log_msg(WARNING, "Restoring original DNS resolver(s)...");
        restore_dns_servers();
        log_msg(WARNING, "Exiting.");
        die(0);
        exit(0);
        break;
    default:
        log_msg(WARNING,"Unhandled signal (%d)", sig);
        die(-1);
        exit(-1);
    }
}
