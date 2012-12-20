/*
 *	lispd.h --
 *
 *	Definitions for lispd main module.
 *
 * Copyright (C) 2009-2012 Cisco Systems, Inc, 2012. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Chris White       <chris@logicalelegance.com>
 *    David Meyer       <dmm@cisco.com>
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
#include <time.h>
#include <unistd.h>
#include "linux/netlink.h"
#include "patricia/patricia.h"
#include "lispd_syslog.h"
#include "lispd_ipc.h"

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

/*
 *	misc parameters
 */
#define	IP6VERSION			6	/* what's the symbol? */
#define	PACKED				__attribute__ ((__packed__))
#define	uchar				u_char

#define	MAX_IP_PACKET			4096

#define TRUE 1
#define FALSE 0

/*
 *	generic list of addresses
 */
typedef struct _lispd_addr_list_t {
    lisp_addr_t	      *address;
    struct _lispd_addr_list_t *next;
} lispd_addr_list_t;

void dump_info_file(void);
void die(int);
