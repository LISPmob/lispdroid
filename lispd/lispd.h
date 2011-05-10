/*
 *	lispd.h --
 *
 *	Definitions for lispd
 #
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Fri Apr 16 13:17:58 2010
 *
 *	$Header: /usr/local/src/lispd/RCS/lispd.h,v 1.3 2010/04/21 20:29:42 dmm Exp $
 *
 */
#pragma once

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <inttypes.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include "ip6.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include "lisp_ipc.h"
#include "linux/netlink.h"
#include "patricia/patricia.h"
#include "lispd_syslog.h"

/*
 *	CO --
 *
 *	Calculate Offset
 *
 *	Try not to make dumb mistakes with
 *	pointer arithmetic
 *
 */
#define	CO(addr,len) (((char *) addr + len))

/*
 *	names for where the udp checksum goes
 */
#ifdef BSD
#define udpsum(x) x->uh_sum
#else
#define udpsum(x) x->check
#endif

/*
 *	lispd constants
 */
#define	EVER			;;
#define	LISPD			"lispd"
#define PID_FILE		"/var/run/lispd.pid"
#define	MAX_IP_PACKET		4096

/*
 *	misc parameters
 */
#define	IP6VERSION			6	/* what's the symbol? */
#define	PACKED				__attribute__ ((__packed__))
#define	uchar				u_char

#define GOOD				1
#define BAD				0
#define	MAX_IP_PACKET			4096
#define	MIN_EPHEMERAL_PORT		32768
#define	MAX_EPHEMERAL_PORT		65535

#define	DEFAULT_MAP_REQUEST_RETRIES	3
#define	DEFAULT_MAP_REGISTER_TIMEOUT	10	/* minutes */
#define DEFAULT_DATA_CACHE_TTL		60	/* seconds */
#define DEFAULT_SELECT_TIMEOUT		1000	/* ms */
#define TRUE 1
#define FALSE 0

/*
 *	generic list of addresses
 */
typedef struct _lispd_addr_list_t {
    lisp_addr_t	      *address;     // Why is this a pointer? XXX
    struct _lispd_addr_list_t *next;
} lispd_addr_list_t;

void dump_info_file(void);
