/* 
 * cksum.c
 * 
 * Various checksum routines for packets and headers.
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

#include "cksum.h"

uint16_t ip_checksum(uint16_t *buffer, int size)
{
    uint32_t cksum = 0;
    
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }

    if (size) {
        cksum += *(uint8_t *) buffer;
    }

    cksum  = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    
    return ((uint16_t)(~cksum));
}

/*    
 *
 *	Calculate the IPv4 UDP checksum (calculated with the whole packet).
 *
 *	Parameters:
 *
 *	buff	-	pointer to the UDP header
 *	len	-	the UDP packet length.
 *	src	-	the IP source address (in network format).
 *	dest	-	the IP destination address (in network format).
 *
 *	Returns:        The result of the checksum
 *
 */
uint16_t udp_ipv4_checksum(const void	*buff,
                           unsigned int	 len,
                           in_addr_t	 src,
                           in_addr_t	 dest)
{

    const uint16_t *buf	   = buff;
    uint16_t	   *ip_src = (void *)&src;
    uint16_t	   *ip_dst = (void *)&dest;
    uint32_t       length  = len;
    uint32_t	   sum     = 0;

    while (len > 1) {
	sum += *buf++;
	if (sum & 0x80000000)
	    sum = (sum & 0xFFFF) + (sum >> 16);
	len -= 2;
    }
 
    /* Add the padding if the packet length is odd */

    if (len & 1)
	sum += *((uint8_t *)buf);
 
    /* Add the pseudo-header */
    sum += *(ip_src++);
    sum += *ip_src;
 
    sum += *(ip_dst++);
    sum += *ip_dst;
 
    sum += htons(IPPROTO_UDP);
    sum += htons(length);
 
    /* Add the carries */
    while (sum >> 16)
	sum = (sum & 0xFFFF) + (sum >> 16);
 
    /* Return the one's complement of sum */
    return ((uint16_t)(~sum));
}


/*
 * udp_ipv6_checksum
 *
 * Compute udp checksum for ipv6
 */
uint16_t udp_ipv6_checksum(const void	*buff,
                           unsigned int	len,
                           struct in6_addr src,
                           struct in6_addr dest)
{
    const uint16_t *buf	   = buff;
    uint32_t       length  = len;
    uint32_t       checksum = 0, addr = 0;

    while (length > 1) {
        checksum += *buf++;
        if (checksum & 0x80000000)
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        length -= 2;
    }

    /* Add the padding if the packet length is odd */

    if (length & 1)
        checksum += *((uint8_t *)buf);

    /*
       * Add in pseudo-header fields.
       */
    addr = src.s6_addr32[0];
    checksum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
    addr = src.s6_addr32[1];
    checksum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
    addr = src.s6_addr32[2];
    checksum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
    addr = src.s6_addr32[3];
    checksum += ((addr >> 16) & 0xffff) + (addr & 0xffff);

    addr = dest.s6_addr32[0];
    checksum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
    addr = dest.s6_addr32[1];
    checksum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
    addr = dest.s6_addr32[2];
    checksum += ((addr >> 16) & 0xffff) + (addr & 0xffff);
    addr = dest.s6_addr32[3];
    checksum += ((addr >> 16) & 0xffff) + (addr & 0xffff);

    checksum += htons(IPPROTO_UDP);
    checksum += htons(len);

    /*
     * Add in carry.
     */
    checksum = ((checksum >> 16) & 0xffff) + (checksum & 0xffff);
    return(~checksum & 0xffff);
  }

/*
 *	upd_checksum
 *
 *	Calculate the IPv4 or IPv6 UDP checksum
 *
 */
uint16_t udp_checksum(struct udphdr *udph, int udp_len,
                      void *iphdr, int afi)
{
    switch (afi) {
    case AF_INET:
        return(udp_ipv4_checksum(udph,
				 udp_len,
				 ((struct ip *)iphdr)->ip_src.s_addr,
				 ((struct ip *)iphdr)->ip_dst.s_addr));
    case AF_INET6:
	return(udp_ipv6_checksum(udph,
				 udp_len,
                                 ((struct ip6_hdr *)iphdr)->ip6_src,
                                 ((struct ip6_hdr *)iphdr)->ip6_dst));
    default:
        log_msg(INFO, "udp_checksum: Unknown AFI");
        return(0);
    }
}
