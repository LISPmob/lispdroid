/*
 * lispd_decap.c
 *
 * Packet input path for LISP module.
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

#include "lispd_config.h"
#include "tables.h"
#include "packettypes.h"
#include "lispd_tuntap.h"
#include "ip6.h"              // Direct import, missing in current Android source

const char echo_signature = 0x78; // First byte past udp header if lisp echo reply

//#define DEBUG
//#define DEBUG_PACKETS

/*
 * check_locator_bits()
 *
 * Verify that the locator status bits in the data packet
 * match our view. If not update it. We have to do a cache
 * lookup for every input packet to do this.
 */
void check_locator_bits(struct lisphdr *lisp_hdr,
                        struct iphdr *iph, uint32_t source)
{
    uint32_t i, bitval;
    int retval;
    lisp_map_cache_t *eid_entry;
    uint32_t packet_lsbs;

    // Lookup the source in the map cache
    retval = lookup_eid_cache_v4(iph->saddr, &eid_entry);

    // No entry, what to do?? XXX
    if (retval == 0) {
        log_msg(INFO, "   Odd, no cache entry for incoming packet.");
        return;
    }

    // Source must be using LSB's for us to care...
    if (lisp_hdr->lsb) {

        /*
         * Check our lsb's against theirs, first extract them from packet
         */
        if (lisp_hdr->instance_id) {
            packet_lsbs = ntohl(lisp_hdr->lsb_bits) & 0x000000FF;
        } else {
            packet_lsbs = ntohl(lisp_hdr->lsb_bits);
        }

        // Go through our list and mark the entries
        // with their current status.
        if (packet_lsbs != eid_entry->lsb) {
            log_msg(INFO, "     LSB change, was 0x%x, now 0x%x",
                   eid_entry->lsb, packet_lsbs);
            eid_entry->lsb = packet_lsbs;
            bitval = 1;
            for (i = 0; i < eid_entry->count; i++) {
                eid_entry->locator_list[i]->state = !!(bitval & packet_lsbs);
                bitval = bitval << 1;
            }
            // Update the hash table
            update_locator_hash_table(eid_entry);
        }
    }

    // Update the input stats
    eid_entry->active_within_period = 1;
    for (i = 0; i < MAX_LOCATORS; i++) {
        if (!eid_entry->locator_list[i]) {
            break;
        }
        if (source == eid_entry->locator_list[i]->locator.address.ip.s_addr) {
            eid_entry->locator_list[i]->data_packets_in++;
            break;
        }
    }
}

/*
 * lisp_input()
 *
 * Packet entry point into LISP processing. Decapsulate and handle
 * any cache updates and disposition.
 */
void lisp_input(uint8_t *packet_buf, int length, void *source)
{
  struct iphdr *iph;
  struct ip6_hdr *ip6;
  struct lisphdr *lisp_hdr;
  struct sockaddr_in *source_sock;
  char   first_byte;
  uint32_t source_locator, pkt_instance;
  uint16_t source_port;

  source_sock    = (struct sockaddr_in *)source;
  source_locator = source_sock->sin_addr.s_addr;
  source_port    = source_sock->sin_port;

#ifdef DEBUG_PACKETS
  {
      char addrbuf[128];

  log_msg(INFO, "In LISP Input with packet from %s for us\n",
          inet_ntop(AF_INET, &source_locator, addrbuf, 128));
  }
#endif

  /*
   * Certain things should never be LISP examined:
   * locally loopback sourced. XXX In TUNTAP, what happens
   * if we send packets to ourselves?
   */

  first_byte= *((char *)packet_buf + sizeof(struct lisphdr));

#ifdef DEBUG_PACKETS
    log_msg(INFO, "  Proto is UDP, src port: %d, dst port: %d",
           ntohs(source_port), lispd_config.local_data_port);
    log_msg(INFO, "  First byte: 0x%x", first_byte);
#endif

    // Detect non-encapsulated lisp control messages
    if (source_port != LISP_CONTROL_PORT &&
            (first_byte != echo_signature)) {

        lisp_hdr = (struct lisphdr *)packet_buf;

#ifdef DEBUG_PACKETS
        log_msg(INFO, "   LISP packet received: dest %d, len: %d\n", lispd_config.local_data_port,
               length);
        log_msg(INFO, "       rflags: %d, e: %d, l: %d, n: %d, i: %d, id/lsb: 0x%x",
               lisp_hdr->rflags, lisp_hdr->echo_nonce, lisp_hdr->lsb,
               lisp_hdr->nonce_present, lisp_hdr->instance_id, ntohl(lisp_hdr->lsb_bits));
#endif

        if (lispd_config.use_instance_id) {
            pkt_instance = ntohl(lisp_hdr->lsb_bits);
            pkt_instance = pkt_instance >> 8;

            if (pkt_instance != lispd_config.instance_id) {
                log_msg(INFO, "  Packet instance ID does not match configured value, dropping.");
                return;
            }
        }

        // Decapsulate
        iph = (struct iphdr *)((char *)lisp_hdr + sizeof(struct lisphdr));

        if (iph->version == 4) {
#ifdef DEBUG_PACKETS
            {
                char addr_buf[128];
                char addr_buf2[128];
                log_msg(INFO, "   Inner packet src: %s dst: %s, type: %d\n",
                        inet_ntop(AF_INET, &(iph->saddr), addr_buf, 128),
                        inet_ntop(AF_INET, &(iph->daddr),addr_buf2, 128), iph->protocol);
            }
#endif

            // Check the LSB's.
            check_locator_bits(lisp_hdr, iph, source_locator);
            write(tun_receive_fd, iph, length - sizeof(struct lisphdr));
            return;

        } else if (iph->version == 6) {
            ip6 = (struct ip6_hdr *)((char *)lisp_hdr + sizeof(struct lisphdr));
            log_msg(INFO, "   Inner packet src:%pI6 dst:%pI6, nexthdr: 0x%x\n",
                   ip6->ip6_src, ip6->ip6_dst, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);

            // check_locator_bits(lisp_hdr, iph, source_locator);
            write(tun_receive_fd, ip6, length - sizeof(struct lisphdr));
        } else {
            log_msg(INFO, "   Unknown ip version %d in inner packet, punting.",
                    iph->version);
            write(tun_receive_fd, packet_buf, length); // Don't know what it is, let ip deal with it.
        }
    } else {
        log_msg(INFO, "Odd, non-LISP packet or LISP control received in data-plane. This should not happen.");
        log_msg(INFO, "    udh->source: %d first_byte: %d",
                ntohs(source_port), first_byte);
        write(tun_receive_fd, packet_buf, length); // Punt;
    }
}

