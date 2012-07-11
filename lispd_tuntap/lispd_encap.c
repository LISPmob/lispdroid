/*
 * lispd_encap.c
 *
 * Handler routines for locally sourced packets destined
 * for LISP encapsulation.
 * 
 * Copyright 2012, cisco Systems.
 */

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "ip6.h"              // Direct import, missing in current Android source
#include "net/route.h"
#include "lispd_encap.h"
#include "lispd_if.h"
#include "packettypes.h"
#include "lispd_config.h"
#include "tables.h"

#define DEBUG
#define DEBUG_PACKETS

#define LISP_CONTROL_PORT 4342
#define LISP_ENCAP_PORT 4341

//extern lisp_globals globals;

static inline uint16_t src_port_hash(struct iphdr *iph)
{
  uint16_t result = 0;

  // Simple rotated XOR hash of src and dst
  result = (iph->saddr << 4) ^ (iph->saddr >> 28) ^ iph->saddr ^ iph->daddr;
  return result;
}

static inline unsigned char output_hash_v4(unsigned int src_eid, unsigned int dst_eid)
{
    int hash;

    hash = src_eid ^ dst_eid;
    return ((((hash & 0xFFFF0000) << 16) ^ (hash & 0xFFFF)) % LOC_HASH_SIZE);
}

int ipv4_transmit(char *packet_buf, int length, uint32_t dst_addr)
{
    int s, nbytes;
    struct sockaddr_in dst;

    /* XXX: assumes v4 transport, probably should open this only once early on too. */
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        log_msg(INFO, "socket (send_map_request): %s", strerror(errno));
        return 0;
    }

    memset((char *) &dst, 0, sizeof(dst));

    dst.sin_family      = AF_INET;	/* XXX: assume v4 transport */
    dst.sin_addr.s_addr = dst_addr;

    if ((nbytes = sendto(s,
                         (const void *)packet_buf,
                         length,
                         0,
                         (struct sockaddr *)&dst,
                         sizeof(struct sockaddr))) < 0) {
        close(s);
        free(packet_buf);
        log_msg(INFO, "sendto (ipv4_transmit): %s, msg len: %d", strerror(errno), length);
        return 0;
    }

    if (nbytes != length) {
        close(s);
        free(packet_buf);
        log_msg(INFO,
               "ipv4_transmit: nbytes (%d) != packet_len (%d)\n",
               nbytes, length);
        return 0;
    }
    close(s);
    free(packet_buf);
    return 1;
}

#if 0
uint32_t get_rloc_address_from_skb(struct sk_buff *skb)
{
    rloc_map_entry_t *entry;

    entry = globals.if_to_rloc_hash_table[skb->mark & ((1<< IFINDEX_HASH_BITS) - 1)];

    while (entry) {
        if (entry->ifindex == skb->mark) {
            break;
        }
        entry = entry->next;
    }
    if (!entry) {
        return 0;
    }

    printk(KERN_INFO "  Using source RLOC %pi4 from ifindex: %d", &entry->addr.address.ip.s_addr, entry->ifindex);
    return entry->addr.address.ip.s_addr;
}
#endif

void lisp_encap4(char *packet_buf, int length, int locator_addr)
{
  struct udphdr *udh;
  struct iphdr *iph;
  struct iphdr *old_iph4 = (struct iphdr *)packet_buf;
  struct ip6_hdr *old_iph6 = (struct ip6_hdr *)packet_buf;
  struct lisphdr *lisph;
  char    *new_packet;
  uint32_t encap_size;
  uint32_t rloc = 0;

  //if (globals.multiple_rlocs) {
  //    rloc = get_rloc_address_from_skb(skb);
  //} else {
  //    if (globals.if_to_rloc_hash_table[0]) {
  rloc = get_primary_interface()->address.address.ip.s_addr;
  //    }
  //}

  if (!rloc) {
      log_msg(INFO, "Unable to determine source rloc");
      return;
  }


  /*
   * Handle fragmentation XXX 
   */

  /*
   * Allocate space for the new packet. (We'll do this in a better way later
   * that doesn't require such an operation, by using a larger buffer at
   * receive and pointing the read far enough in that we have headeroom. XXX
   */
  encap_size = sizeof(struct lisphdr) + sizeof(struct iphdr) +
          sizeof(struct udphdr);
  new_packet = (char *)malloc(length + encap_size);

  memcpy(new_packet + encap_size, packet_buf, length);

  /* 
   * Construct and add the LISP header
   */
  lisph = (struct lisphdr *)(new_packet + sizeof(struct iphdr) +
                             sizeof(struct udphdr));

  memset((char *)lisph, 0, sizeof(struct lisphdr));

  // Single LSB for now, and set it to ON
  lisph->lsb = 1;
  lisph->lsb_bits = htonl(0x1);

  /*
   * Using instance ID? Or it in.
   */
 // if (globals.use_instance_id) {
 //     lisph->instance_id = 1;
 //     lisph->lsb_bits |= htonl(globals.instance_id << 8);
 // }

  lisph->nonce_present = 1;
  lisph->nonce[0] = random() & 0xFF;
  lisph->nonce[1] = random() & 0xFF;
  lisph->nonce[2] = random() & 0xFF;

#ifdef DEBUG_PACKETS
  log_msg(INFO, "          rflags: %d, e: %d, l: %d, n: %d, i: %d, id/lsb: 0x%x",
             lisph->rflags, lisph->echo_nonce, lisph->lsb,
             lisph->nonce_present, lisph->instance_id, ntohl(lisph->lsb_bits));
#endif

  /* 
   * Construct and add the udp header
   */
  udh = (struct udphdr *)(new_packet + sizeof(struct iphdr));

  /*
   * Hash of inner header source/dest addr. This needs thought.
   */
  udh->source = htons(lispd_config.local_data_port);
  udh->dest =  htons(LISP_ENCAP_PORT);
  udh->len = htons(sizeof(struct udphdr) + length +
		   sizeof(struct lisphdr));
  udh->check = 0; // SHOULD be 0 as in LISP ID

  /*
   * Construct and add the outer ip header
   */
  iph = (struct iphdr *)new_packet;

  iph->version  =    4;
  iph->ihl      =     sizeof(struct iphdr)>>2;
  iph->frag_off = 0;   // XXX recompute above, use method in 5.4.1 of draft
  iph->protocol = IPPROTO_UDP;
  if (old_iph4->version == 4) {
      iph->tos      = old_iph4->tos; // Need something else too? XXX
  } else {
      iph->tos      = 0; // No map from v6 to v6 tos.
  }
  iph->daddr    = locator_addr;
  iph->saddr    = rloc;
  if (old_iph4->version == 4) {
      iph->ttl      = old_iph4->ttl;
  } else if (old_iph4->version == 6) {
      iph->ttl      = old_iph6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
      log_msg(INFO, "Set ipv4 ttl to %d from v6 packet", iph->ttl);
  } else {
      iph->ttl      = 0;
  }

#ifdef DEBUG_PACKETS
  {
      char buf1[128];
      char buf2[128];
      log_msg(INFO, "     Packet encapsulated to %s from %s\n",
         inet_ntop(AF_INET, &iph->daddr, buf1, 128),
              inet_ntop(AF_INET, &iph->saddr, buf2, 128));
  }
#endif
  ipv4_transmit(new_packet, length + encap_size, locator_addr);
  return;
}

#if 0
void lisp_encap6(char *packet_buf, int length, int locator_addr)
{
  struct udphdr *udh;
  struct ipv6hdr *iph;
  struct ipv6hdr *old_iph = ipv6_hdr(skb);
  struct lisphdr *lisph;
  struct sk_buff *new_skb = NULL;
  uint32_t orig_length = skb->len;
  uint32_t pkt_len, err;
  uint32_t max_headroom;
  struct net_device *tdev; // Output device
  struct dst_entry *dst;
  int    mtu;
  uint8_t dsfield;
  struct flowi fl;
  lisp_addr_t *rloc = NULL;
  
  if (globals.multiple_rlocs) {
      //get_rloc_for_skb(rloc);
  } else {
      rloc = &globals.if_to_rloc_hash_table[0]->addr; // XXX should lock?
  }

  /*
   * We have to do a routing check on our
   * proposed RLOC dstadr to determine the output
   * device. This is so that we can be assured
   * of having the proper space available in the 
   * skb to add our headers. This is modelled after
   * the iptunnel6.c code.
   */
  {
    ipv6_addr_copy(&fl.fl6_dst, &locator_addr.address.ipv6);
    if (rloc->afi != AF_INET6) {
      printk(KERN_INFO "No AF_INET6 source rloc available\n");
      return;
    }
    ipv6_addr_copy(&fl.fl6_src, &rloc->address.ipv6);
    fl.oif = 0;

    fl.fl6_flowlabel = 0;
    fl.proto = IPPROTO_UDP;
  }

  dst = ip6_route_output(&init_net, NULL, &fl);

  if (dst->error) {
    printk(KERN_INFO "  Failed v6 route lookup for RLOC\n");
    
    // Error fail cleanup XXX
    return;
  }
     
  /*
   * Get the output device 
   */
  tdev = dst->dev;
  
  printk(KERN_INFO "   Got route for RLOC\n");

  /*
   * Handle fragmentation XXX 
   */
  mtu = dst_mtu(dst) - (sizeof(*iph) + sizeof(*lisph));
  if (mtu < IPV6_MIN_MTU) {
    mtu = IPV6_MIN_MTU;
  };

#ifdef NEW_KERNEL
  /*
   * Do we really want to do this? XXX
   */
  if (skb_dst(skb))
    skb_dst(skb)->ops->update_pmtu(skb_dst(skb), mtu);
  if (skb->len > mtu) {
    printk(KERN_INFO "   skb does not fit in MTU");
    return; // Cleanup XXX
  }
#else
  if (skb->dst)
      skb->dst->ops->update_pmtu(skb->dst, mtu);
  if (skb->len > mtu) {
      printk(KERN_INFO "   skb does not fit in MTU\n");
      return; // Cleanup XXX
  }
#endif
  
  /* 
   * Determine if we have enough space.
   */
  max_headroom = (LL_RESERVED_SPACE(tdev) + sizeof(struct ipv6hdr) +
		  sizeof(struct udphdr) + sizeof(struct lisphdr));
  printk(KERN_INFO "  Max headroom is %d\n", max_headroom);

  /*
   * If not, gotta make some more.
   */
  if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
      (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
      printk(KERN_INFO "  Forced to allocate new sk_buff\n");
      new_skb = skb_realloc_headroom(skb, max_headroom);
      if (!new_skb) {
          printk(KERN_INFO "Failed to allocate new skb for packet encap\n");
          return;
      }

      /*
     * Repoint socket if necessary
     */
      if (skb->sk)
          skb_set_owner_w(new_skb, skb->sk);

      dev_kfree_skb(skb);
      skb = new_skb;
      old_iph = ipv6_hdr(skb); // Err.. what if its v6 encaped v4? XXX
  }

#ifdef NEW_KERNEL
  skb_dst_drop(skb);
  skb_dst_set(skb, dst);
#else
  dst_release(skb->dst);
  skb->dst = dst_clone(dst);
#endif

  /* 
   * Construct and add the LISP header
   */
  skb->transport_header = skb->network_header;
  lisph = (struct lisphdr *)(skb_push(skb, sizeof(struct lisphdr)));
  skb_reset_transport_header(skb);

  // no flags XXX
  memset((char *)lisph, 0, sizeof(struct lisphdr));

   /* 
   * Construct and add the udp header
   */ 
  skb->transport_header = skb->network_header;
  udh = (struct udphdr *)(skb_push(skb, sizeof(struct udphdr)));
  skb_reset_transport_header(skb);
  
  /*
   * Hash of inner header source/dest addr. This needs thought.
   */
  udh->source = htons(globals.udp_encap_port);
  udh->dest =  LISP_ENCAP_PORT;
  udh->len = htons(sizeof(struct udphdr) + orig_length +
		   sizeof(struct lisphdr));
  udh->check = 0; // SHOULD be 0 as in LISP ID

  /*
   * Construct and add the outer ipv6 header
   */
  skb_push(skb, sizeof(struct ipv6hdr));
  skb_reset_network_header(skb);
  iph = ipv6_hdr(skb);
  *(__be32*)iph = htonl(0x60000000); // Flowlabel? XXX
  dsfield = INET_ECN_encapsulate(0, dsfield);
  ipv6_change_dsfield(iph, ~INET_ECN_MASK, dsfield);
  iph->hop_limit = 10; // XXX grab from inner header.
  iph->nexthdr = IPPROTO_UDP;
  ipv6_addr_copy(&iph->saddr, &fl.fl6_src);
  ipv6_addr_copy(&iph->daddr, &fl.fl6_dst);
  nf_reset(skb);

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "  Packet encapsulated to %pI6\n", iph->daddr.s6_addr);
#endif

  /* 
   * We must transmit the packet ourselves:
   * the skb has probably changed out from under
   * the upper layers that have a reference to it.
   * 
   * This is the same work that the tunnel code does
   */
  pkt_len = skb->len;
  err = ip6_local_out(skb);
  if (net_xmit_eval(err) != 0) {
    printk(KERN_INFO "ip_local_out() reported an error: %d\n", err);
  }

  return;
}
#endif

unsigned int lisp_output6(char *packet_buf, int length)
{
  struct ip6_hdr   *iph;
  lisp_map_cache_t *eid_entry;
  int               retval;
  lisp_addr_t       locator_addr;
  uint16_t          loc_afi;
  lisp_addr_t       dst_addr;

  /* 
   * Extract the ip header
   */
  iph = (struct ip6_hdr *)(packet_buf);

#ifdef DEBUG_PACKETS
  {
      char addr_buf[128];
      char addr_buf2[128];
      log_msg(INFO, "   Output packet destined for %s from %s\n",
              inet_ntop(AF_INET6, iph->ip6_dst.s6_addr, addr_buf, 128),
              inet_ntop(AF_INET6, iph->ip6_src.s6_addr, addr_buf2, 128));
  }
#endif

  /*
   * Sanity check the inner packet XXX
   */

  /*
   * Eventually, when supporting ipv6/ipv6 or v4 or v6, we
   * will need to escape LISP control messages, like in lisp_output4.
   * XXX
   */

  /*
   * Lookup the destination in the map-cache, this will
   * need to return the full entry in the future for all
   * the flags to be processed. TDB: Check for concurrency
   * issues with directly using the entry pointer here. May
   * need to lock it or make a copy (ick)
   */
  dst_addr.afi = AF_INET6;
  memcpy(dst_addr.address.ipv6.s6_addr, iph->ip6_dst.s6_addr, sizeof(iph->ip6_dst));
  retval = lookup_eid_cache_v6(dst_addr, &eid_entry);
  
  /*
   * Check status of returned entry XXX (requires extension
   * of above function).
   */
  if (retval == 0 || !eid_entry->count) {
      log_msg(INFO, "No EID mapping found, notifying lispd...\n");
      handle_cache_miss(dst_addr);
      return 0;
  }

  /*
   * Mark that traffic has been received.
   */
  eid_entry->active_within_period = 1;

  /*
   * Get the first locator for now... sync up with output4 to use hash XXX
   */
  if (!eid_entry->locator_list[0]) {
    log_msg(INFO, " No suitable locators.\n");
    return(0);
  } else {
      loc_afi = eid_entry->locator_list[0]->locator.afi;
      memcpy(&locator_addr, &eid_entry->locator_list[0]->locator, sizeof(lisp_addr_t));
      log_msg(INFO, " Locator found.\n");
  }
  
  /* 
   * Prepend UDP, LISP, outer IP header
   */
  if (loc_afi == AF_INET) {
      lisp_encap4(packet_buf, length, locator_addr.address.ip.s_addr);
#ifdef DEBUG_PACKETS
      log_msg(INFO, "   Using locator address: %pI4\n", &locator_addr);
#endif
  } else {
      if (loc_afi == AF_INET6) {
        //  lisp_encap6(packet_buf, locator_addr, AF_INET6);
#ifdef DEBUG_PACKETS
          log_msg(INFO, "   Using locator address: %pI6\n", locator_addr.address.ipv6.s6_addr);
#endif
      }
  }

  eid_entry->locator_list[0]->data_packets_out++;
  return(1);
}

#if 0
/*
 * is_v4addr_local
 *
 * Perform a route lookup to determine if this address
 * belongs to us. See arp.c for comparable check.
 */
bool is_v4addr_local(struct iphdr *iph, struct sk_buff *packet_buf)
{
    struct flowi fl;
    struct rtable *rt;
    struct net_device *dev;

    memset(&fl, 0, sizeof(fl));
    fl.fl4_dst = iph->daddr;
    fl.fl4_tos = RTO_ONLINK;
    if (ip_route_output_key(dev_net(packet_buf->dev), &rt, &fl))
        return 0;
    dev = rt->u.dst.dev;
    ip_rt_put(rt);
    if (!dev)
        return 0;

    // If we got anything, it's local
    return 1;
}
#endif

unsigned int lisp_output4(char *packet_buf, int length)
{
  struct iphdr     *iph;
  struct udphdr    *udh;
  lisp_map_cache_t *eid_entry;
  int               retval;
  int               locator_addr;
  unsigned char     loc_index;
  lisp_addr_t       miss_addr;

  /* 
   * Extract the ip header
   */
  iph = (struct iphdr *)packet_buf;
  
#ifdef DEBUG_PACKETS
  {
      char addr_buf[128];
      char addr_buf2[128];
      log_msg(INFO, "   Output packet destined for %s from %s, proto: %d\n",
              inet_ntop(AF_INET, &iph->daddr, addr_buf, 128),
              inet_ntop(AF_INET, &iph->saddr, addr_buf2, 128), iph->protocol);
  }
#endif

  /*
   * Don't encapsulate LISP control messages
   */
  if (iph->protocol == IPPROTO_UDP) {
      udh = (struct udphdr *)packet_buf + sizeof(struct iphdr);

      /*
       * If either of the udp ports are the control port or data, allow
       * to go out natively. This is a quick way around the
       * route filter which rewrites the EID as the source address.
       */
      if ( (ntohs(udh->dest) == LISP_CONTROL_PORT) ||
          (ntohs(udh->source) == LISP_CONTROL_PORT) ||
          (ntohs(udh->source) == LISP_ENCAP_PORT) ||
          (ntohs(udh->dest) == LISP_ENCAP_PORT) ) {

          // Undo the pull
#ifdef DEBUG_PACKETS
          log_msg(INFO, "      Packet looks like lisp control: dstprt %d, srcprt %d\n",
                 ntohs(udh->dest), ntohs(udh->source));
#endif

          return(0);
      } else {
#ifdef DEBUG_PACKETS
          log_msg(INFO, "       Packet not lisp control: dstprt %d, srcprt %d\n", ntohs(udh->dest),
                 ntohs(udh->source));
#endif
      }
       // Undo the pull
    }

  /*
   * Sanity check the inner packet XXX
   */

  /*
   * Lookup the destination in the map-cache, this will
   * need to return the full entry in the future for all
   * the flags to be processed. TDB: Check for concurrency
   * issues with directly using the entry pointer here. May
   * need to lock it or make a copy (ick)
   */
  retval = lookup_eid_cache_v4(iph->daddr, &eid_entry);
  
  /*
   * Check status of returned entry XXX (requires extension
   * of above function).
   */
  if (retval == 0 || !eid_entry->count) {

    log_msg(INFO, "        No EID mapping found, triggering request...\n");
    miss_addr.address.ip.s_addr = iph->daddr;
    miss_addr.afi = AF_INET;
    handle_cache_miss(miss_addr);
    return(0);
  }

  /*
   * Mark that traffic has been received.
   */
  eid_entry->active_within_period = 1;

  /*
   * Hash to find the correct locator based on weight, priority, etc.
   */
  loc_index = eid_entry->locator_hash_table[output_hash_v4(iph->saddr, iph->daddr)];
  if (eid_entry->locator_list[loc_index]) {
      locator_addr = eid_entry->locator_list[loc_index]->locator.address.ip.s_addr;
  } else {
      log_msg(INFO,"    Invalid locator list!\n");
      return(0);
  }

  /* 
   * Prepend UDP, LISP, outer IP header (use encap6 if locator is ipv6 XXX)
   */
  lisp_encap4(packet_buf, length, locator_addr);

  eid_entry->locator_list[loc_index]->data_packets_out++;

#ifdef DEBUG_PACKETS
  log_msg(INFO, "       Using locator address: %pI4\n", &locator_addr);
#endif
  return(1);
}
