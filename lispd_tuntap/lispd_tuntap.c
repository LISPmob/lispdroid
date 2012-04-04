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
#include "lispd_encap.h"

const char *Tundev = "lisp_tun";
const unsigned int TunReceiveSize = 2048; // Should probably tune to match largest MTU
int tun_fd = -1;

int create_tun() {

    struct ifreq ifr;
    int err, flags = IFF_TUN | IFF_NO_PI;
    char *clonedev = "/dev/tun";

    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if( (tun_fd = open(clonedev, O_RDWR)) < 0 ) {
        log_msg(INFO, "TUN/TAP: Failed to open clone device");
        return tun_fd;
    }

    /* preparation of the struct ifr, of type "struct ifreq" */
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */
    strncpy(ifr.ifr_name, Tundev, IFNAMSIZ);

    /* try to create the device */
    if ( (err = ioctl(tun_fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        close(tun_fd);
        log_msg(INFO, "TUN/TAP: Failed to create tunnel interface.");
        return err;
    }

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    return tun_fd;
}

void *tun_recv(void *arg)
{
    char *rcvbuf;
    int   nread;

    rcvbuf = malloc(TunReceiveSize);
    while (1) {
        nread = read(tun_fd, rcvbuf, TunReceiveSize);
        lisp_output4(rcvbuf);
    }
}

void start_tun_recv()
{
    pthread_t receiver_thread;

    if (pthread_create(&receiver_thread, NULL, tun_recv, NULL) != 0) {
        log_msg(ERROR, "TUN/TAP receiver thread creation failed %s", strerror(errno));
        return;
    }
    pthread_detach(receiver_thread);
}

