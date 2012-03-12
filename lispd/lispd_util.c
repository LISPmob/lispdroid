/*
 *      lisp_util.c --
 *
 *      Various library routines
 *
 *
 *      David Meyer
 *      dmm@1-4-5.net
 *      Thu Apr 22 10:06:22 2010
 *
 *      $Header: $
 *
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
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
#include <sys/types.h>
#include <unistd.h>
#include "linux/netlink.h"
#include "lispd_config.h"
#include "lispd_if.h"
#include "lispd_packets.h"
#include "lispd_util.h"

/*
 *      get_afi
 *
 *      Assume if there's a colon in str that its an IPv6 
 *      address. Otherwise its v4.
 *
 *      David Meyer
 *      dmm@1-4-5.net
 *      Wed Apr 21 16:31:34 2010
 *
 *      $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */
int get_afi(char *str)
{ 
    if (strchr(str,':'))                /* poor-man's afi discriminator */
        return(AF_INET6);
    else        
        return(AF_INET);
}

/*
 *      copy_lisp_addr_t
 *
 *      Copy a lisp_addr_t, converting it using convert
 *      if supplied
 */
int copy_lisp_addr_t(lisp_addr_t *a1, lisp_addr_t *a2, uint16_t afi, int convert)
{
    switch(afi) {
    case AF_INET:
        if (convert)
            a1->address.ip.s_addr = htonl(a2->address.ip.s_addr);
        else 
            a1->address.ip.s_addr = a2->address.ip.s_addr;
        break;
    case AF_INET6:
            memcpy(a1->address.ipv6.s6_addr,
                   a2->address.ipv6.s6_addr,
                   sizeof(struct in6_addr));
            break;
        default:
            log_msg(INFO, "copy_lisp_addr_t: Unknown AFI (%d)", afi);
            return(0);
    }
    return(1);
}

/*
 *      copy_addr
 *
 *      Copy a lisp_addr_t to a memory location, htonl'ing it
 *      it convert != 0. Return the length or 0;
 */
int copy_addr(void *a1, lisp_addr_t *a2, int afi, int convert)
{

    switch(afi) {
    case AF_INET:
        if (convert)
            ((struct in_addr *) a1)->s_addr = htonl(a2->address.ip.s_addr);
        else 
            ((struct in_addr *) a1)->s_addr = a2->address.ip.s_addr;
        return(sizeof(struct in_addr));
    case AF_INET6:
        memcpy(a1,
               a2->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        return(sizeof(struct in6_addr));
    default:
        log_msg(INFO, "copy_addr: Unknown AFI (%d)", afi);
        return(0);
    }
}

/*
 *      find a useable source address with AFI = afi
 */
lisp_addr_t *get_my_addr(char *if_name, int afi)
{
    lisp_addr_t        *addr;
    struct ifaddrs      *ifaddr;
    struct ifaddrs      *ifa;
    struct sockaddr_in  *s4;
    struct sockaddr_in6 *s6;

    if ((addr = malloc(sizeof(lisp_addr_t))) == NULL) {
        log_msg(INFO, "malloc (get_my_addr): %s", strerror(errno));
        return(0);
    }

    memset(addr,0,sizeof(lisp_addr_t));

    if (getifaddrs(&ifaddr) !=0) {
        log_msg(INFO, "getifaddrs(get_my_addr): %s", strerror(errno));
        free(addr);
        return(0);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr             == NULL) ||
            ((ifa->ifa_flags & IFF_UP) == 0)    ||
            (ifa->ifa_addr->sa_family  != afi)  ||
            strcmp(ifa->ifa_name, if_name))
            continue;
        switch(ifa->ifa_addr->sa_family) {
        case AF_INET:
            s4 = (struct sockaddr_in *)(ifa->ifa_addr);
            memcpy((void *) &(addr->address),
                   (void *)&(s4->sin_addr), sizeof(struct sockaddr_in));
            addr->afi = (ifa->ifa_addr)->sa_family;
            return(addr);
        case AF_INET6:
            s6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
            memcpy((void *) &(addr->address),
                   (void *)&(s6->sin6_addr),
                   sizeof(struct sockaddr_in6));
            addr->afi = (ifa->ifa_addr)->sa_family;
            return(addr);
        default:
            continue;                   /* keep looking */
        }
    }
    free(addr);
//    freeaddrlist(ifaddrs);
    return(0);                          /* no luck */
}

/*
 *      lispd_get_address
 *
 *      return lisp_addr_t for host or 0 if none
 */
lisp_addr_t *lispd_get_address(char *host, lisp_addr_t *addr, uint32_t *flags)
{
    struct hostent      *hptr;
    struct ifaddrs      *ifaddr;
    struct ifaddrs      *ifa;
    struct sockaddr_in  *s4;
    struct sockaddr_in6 *s6;

    /* 
     * make sure this is clean
     */

    memset((void *) &(addr->address), 0, sizeof(lisp_addr_t));

    /*
     *  check to see if hhost is either a FQDN of IPvX address.
     */

    if (((hptr = gethostbyname2(host,AF_INET))  != NULL) ||
        ((hptr = gethostbyname2(host,AF_INET6)) != NULL)) {
        memcpy((void *) &(addr->address),
               (void *) *(hptr->h_addr_list), sizeof(lisp_addr_t));
        addr->afi = hptr->h_addrtype;
        if (isfqdn(host))
            *flags = FQDN_LOCATOR;      
        else 
            *flags = STATIC_LOCATOR;
        return(addr);
    } 
    /*
     *  ok, assume host is actually an interface name (e.g., eth0), 
     *  i.e., a DYNAMIC_LOCATOR... and tell the caller if it cares
     */

    *flags = DYNAMIC_LOCATOR;

    /*
     *  go search for the interface
     */

    if (getifaddrs(&ifaddr) !=0) {
        log_msg(INFO,
	       "getifaddrs(get_interface_addr): %s", strerror(errno));
        return(0);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr == NULL) || ((ifa->ifa_flags & IFF_UP) == 0))
            continue;
        switch(ifa->ifa_addr->sa_family) {
        case AF_INET:
            s4 = (struct sockaddr_in *)(ifa->ifa_addr);
            if (!strcmp(ifa->ifa_name, host)) {
                memcpy((void *) &(addr->address),
                       (void *)&(s4->sin_addr), sizeof(struct sockaddr_in));
                addr->afi = (ifa->ifa_addr)->sa_family;
                return(addr);
            } else {
                continue;
            }
        case AF_INET6:
            s6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
            if (!strcmp(ifa->ifa_name, host)) {
                memcpy((void *) &(addr->address),
                       (void *)&(s6->sin6_addr),
                       sizeof(struct sockaddr_in6));
                addr->afi = (ifa->ifa_addr)->sa_family;
                return(addr);
            } else {
                continue;
            }
        default:
            continue;                   /* XXX */
        }
    }
//    freeaddrlist(ifaddr);
    return(NULL);
 }

/*
 *      isfqdn(char *s)
 *
 *      See if a string qualifies as an FQDN. To qualifiy, s must
 *      contain one or more dots. The dots may not be the first
 *      or the last character. Two dots may not immidiately follow
 *      each other. It must consist of the characters a..z, A..Z,,
 *      0..9, '.', '-'. The first character must be a letter or a digit.
 */
int isfqdn(char *s)
{
    int         i = 1;
    uint8_t     dot = 0;
    char        c;

    if ((!isalnum(s[0])) || (!strchr(s,':')))
        return(0);

    while (((c = s[i]) != 0) && (c != ',') && (c != ':')) {
        if (c == '.') {
            dot = 1;
            if (s[i-1] == '.')
                return(0);
        }
        if (!(isalnum(c) || c=='-' || c=='.'))
            return(0);
        i++;
    }

    if (s[0] == '.' || s[i-1] == '.')
        return(0);

    return(dot);
}

/*
 *      get_lisp_afi
 *
 *      Map from Internet AFI -> LISP_AFI
 *
 *      Get the length while you're at it
 */
int get_lisp_afi(int afi, int *len)
{
    switch(afi) {
    case AF_INET:
        if (len)
            *len = sizeof(struct in_addr);
        return(LISP_AFI_IP);
    case AF_INET6:
        if (len)
            *len = sizeof(struct in6_addr);
        return(LISP_AFI_IPV6);
    default:
        log_msg(INFO, "get_lisp_afi: uknown AFI (%d)", afi);
        return(0);
    }
    return(0);
}

/*
 *      lisp2inetafi
 *
 *      Map from Internet LISP AFI -> INET AFI
 *
 */
int lisp2inetafi(int afi)
{
    switch(afi) {
    case LISP_AFI_IP:
        return(AF_INET);
    case LISP_AFI_IPV6:
        return(AF_INET6);
    default:
        log_msg(INFO, "lisp2inet_afi: uknown AFI (%d)", afi);
        return(0);
    }
    return(0);
}


/*
 *      given afi, get the IP header length
 */
int get_ip_header_len(int afi)
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct ip));
    case AF_INET6:
        return(sizeof(struct ip6_hdr));
    default:
        log_msg(INFO, "Unknown AFI %d", afi);
        return(0);
    }
    return(0);
}

/*
 *      given afi, get addr len
 */
int get_addr_len(int afi)
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct in_addr));
    case AF_INET6:
        return(sizeof(struct in6_addr));
    default:
        log_msg(INFO, "Unknown AFI %d", afi);
        return(0);
    }
    return(0);
}

struct udphdr *build_ip_header(void *cur_ptr, lisp_addr_t *src,
                               lisp_addr_t *dest, int ip_len)
{
    struct ip      *iph;
    struct ip6_hdr *ip6h;
    struct udphdr  *udph;

    switch (src->afi) {
    case AF_INET:
        iph                = (struct ip *) cur_ptr;
        iph->ip_hl         = 5;
        iph->ip_v          = IPVERSION;
        iph->ip_tos        = 0;
        iph->ip_len        = htons(ip_len);
        iph->ip_id         = htons(54321);
        iph->ip_off        = 0;
        iph->ip_ttl        = 255;
        iph->ip_p          = IPPROTO_UDP;
        iph->ip_sum        = 0;
        iph->ip_src.s_addr = src->address.ip.s_addr;
        iph->ip_dst.s_addr = dest->address.ip.s_addr;
        udph              = (struct udphdr *) CO(iph, sizeof(struct ip));
        break;
    case AF_INET6:
        ip6h           = (struct ip6_hdr *) cur_ptr;
        ip6h->ip6_hops = 255;
        ip6h->ip6_vfc  = (IP6VERSION << 4);
        ip6h->ip6_nxt  = IPPROTO_UDP;
        ip6h->ip6_plen = htons(ip_len - sizeof(struct ip6_hdr)); // Don't include header length
        memcpy(ip6h->ip6_src.s6_addr,
               src->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        memcpy(ip6h->ip6_dst.s6_addr,
               dest->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        udph = (struct udphdr *) CO(ip6h,sizeof(struct ip6_hdr));
        break;
    default:
        return(0);
    }
    return(udph);
}

/*
 * setbit()
 *
 * Sets the given bit in a 32-bit word to 1
 */
int setbit(int word, char bit)
{
    int mask = 1 << bit;

    return (word | mask);
}

/*
 * clearbit()
 *
 * Sets the given bit in a 32-bit word to 0
 */
int clearbit(int word, char bit)
{
    int mask = 1 << bit;
    mask = ~mask;

    return (word & mask);
}

/*
 *      requires librt
 */
uint64_t build_nonce(int seed)
{

    uint64_t            nonce;
    uint32_t            nonce_lower;
    uint32_t            nonce_upper;
    struct timespec     ts;

    /*
     * Put nanosecond clock in lower 32-bits and put an XOR of the nanosecond
     * clock with the seond clock in the upper 32-bits.
     */
    clock_gettime(CLOCK_MONOTONIC,&ts);
    nonce_lower = ts.tv_nsec;
    nonce_upper = ts.tv_sec ^ htonl(nonce_lower);

    /*
     * OR in a caller provided seed to the low-order 32-bits.
     */
    nonce_lower |= seed;

    /*
     * Return 64-bit nonce.
     */
    nonce = nonce_upper;
    nonce = (nonce << 32) | nonce_lower;

    // Unlikely
    if (nonce == 0) {
        nonce = 1;
    }
    return(nonce);
}


void dump_message(char *msg, int length)
{
  int words = length / sizeof(uint32_t);
  int i;

  for (i = 0; i < words; i++) {
      log_msg(INFO, " %06x %02x %02x %02x %02x\n", i, *msg,*(msg + 1), *(msg + 2), *(msg + 3));
      msg = msg + 4;
  }
}

/*
 *      dump_X
 *
 *      walk the lispd X data structures 
 *
 *      David Meyer
 *      dmm@1-4-5.net
 *      Wed Apr 21 14:08:42 2010
 *
 *      $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */
int dump_database(patricia_tree_t *tree, int afi, FILE *fp)
{
    patricia_node_t             *node;
    lispd_locator_chain_t       *locator_chain;
    lispd_locator_chain_elt_t   *locator_chain_elt;

    if (!tree) {
        switch(afi) {
        case AF_INET:
            log_msg(INFO, "No database for AF_INET");
            return(0);
        case AF_INET6:
            log_msg(INFO, "No database for AF_INET6");
            return(0);
        default:        
            log_msg(INFO, "Unknown database AFI (%d)", afi);
            return(0);
        }
    }

    PATRICIA_WALK(tree->head, node) {
        locator_chain     = ((lispd_locator_chain_t *)(node->data));
        locator_chain_elt = locator_chain->head;
        while (locator_chain_elt) {
            dump_database_entry(locator_chain, locator_chain_elt, fp);
            locator_chain_elt = locator_chain_elt->next;
        }
    } PATRICIA_WALK_END;
    return(1);
}

void dump_database_entry(lispd_locator_chain_t *chain, lispd_locator_chain_elt_t *db_entry, FILE *fp)
{
    int              afi; 
    char             eid[128];
    char             rloc[128];

    char             buf[128];

    afi = chain->eid_prefix.afi;
    inet_ntop(afi,
              &(chain->eid_prefix.address),
              eid,
              128);
    if (!db_entry->interface) {
        inet_ntop(db_entry->locator_afi,
                  &(db_entry->locator_addr.address),
                  rloc, 128);
    } else {
        if (db_entry->interface->nat_type == NATOff) {
        inet_ntop(db_entry->interface->address.afi,
                  &db_entry->interface->address,
                  rloc, 128);
        } else {
    if (is_nat_complete(db_entry->interface)) {
        inet_ntop(db_entry->interface->nat_address.afi,
                  &db_entry->interface->nat_address,
                  rloc, 128);
    } else {
        sprintf(rloc, "No Address");
    }

        }
    }
    if (db_entry->locator_type == DYNAMIC_LOCATOR)
	sprintf(buf, "%s (%s)", db_entry->locator_name, rloc);
    else
	sprintf(buf, "%s", rloc);
    fprintf(fp, "%15s, %6s: %4s, pr %3d, wt %d\n",
            buf,
           db_entry->interface->name,
           (db_entry->interface->flags & IFF_UP) ? "up" : "down",
	   db_entry->priority,
	   db_entry->weight);
}

void dump_map_resolvers(void)
{ 
    lisp_addr_t        *addr = 0;
    lispd_addr_list_t   *mr   = 0;
    int                 afi; 
    char                buf[128];

    if (!lispd_config.map_resolvers)
        return;

    log_msg(INFO, "map-resolvers:");
    mr = lispd_config.map_resolvers;

    while (mr) {
        addr = mr->address;
        afi = addr->afi;
        inet_ntop(afi, &(addr->address), buf, sizeof(buf));
        log_msg(INFO," %s", buf);
        mr = mr->next;
    }
}

void dump_map_servers(void)
{ 
    int                     afi;
    lisp_addr_t            *addr;
    lispd_map_server_list_t *ms;
    char                    buf[128];

    if (!lispd_config.map_servers)
        return;

    log_msg(INFO, "map-servers:");
    ms = lispd_config.map_servers;

    while (ms) {
        dump_map_server(ms);
        ms = ms->next;
    }
}

void dump_map_server(lispd_map_server_list_t *ms)
{
    int                     afi;
    lisp_addr_t            *addr;
    char                    buf[128];

    addr = ms->address;
    afi = addr->afi;
    inet_ntop(afi, &(addr->address), buf, sizeof(buf));
    log_msg(INFO, " %s key-type: %d key: %s",
	   buf,
	   ms->key_type,
	   ms->key);
}

void dump_map_cache(void)
{
    lispd_map_cache_t       *map_cache;
    lispd_map_cache_entry_t *map_cache_entry;
    int              afi; 
    unsigned int     ttl; 
    char             eid[128];
    char             rloc[128];

    if (!lispd_map_cache)
        return;

    log_msg(INFO, "map-cache:");
    map_cache = lispd_map_cache;

    while (map_cache) {
        map_cache_entry = &(map_cache->map_cache_entry);
        afi = map_cache_entry->eid_prefix.afi;
        ttl = map_cache_entry->ttl;
        inet_ntop(afi,
                  &(map_cache_entry->eid_prefix.address),
                  eid,
                  128);
        inet_ntop(map_cache_entry->locator_afi,
                  &(map_cache_entry->locator.address),
                  rloc, 128);
        log_msg(INFO," %s lisp %s/%d %s p %d w %d ttl %d (%s)",
	       (afi == AF_INET) ? "ip":"ipv6",
	       eid,
	       map_cache_entry->eid_prefix_length, 
	       rloc,
	       map_cache_entry->priority,
	       map_cache_entry->weight,
	       ttl,
	       (map_cache_entry->how_learned == STATIC_MAP_CACHE_ENTRY)
	       ? "static" : "dynamic");
        map_cache = map_cache->next;
    }
}

void dump_interfaces(FILE *fp)
{
    lispd_if_t *if_list;
    char addrstr[128];

    if_list = get_interface_list();

    while (if_list) {
        inet_ntop(if_list->address.afi, &if_list->address.address, addrstr, 128);
        fprintf(fp, "  %6s: %4s, %15s%s, pref: %2d\n",
                if_list->name, (if_list->flags & IFF_UP) ? "up" : "down", addrstr,
                (if_list->nat_type != NATOff) ? "(N)" : "", if_list->dev_prio);
        if_list = if_list->next_if;
    }
}

void dump_tree_elt(lispd_locator_chain_t *locator_chain)
{
    log_msg(INFO, " locator_chain->eid_name = %s",
           locator_chain->eid_name);
}

void dump_tree(int afi, patricia_tree_t *tree)
{
    patricia_node_t *node;
   
    switch(afi) {
    case AF_INET:
        printf("dump_tree for AF_INET\n");
        break;
    case AF_INET6:
        printf("dump_tree for AF_INET6\n");
        break;
    }

    PATRICIA_WALK(tree->head, node) {
        printf("node: %s/%d\n", 
               prefix_toa(node->prefix), node->prefix->bitlen);
        printf("dump_tree:\t%s (%d)\n",
               ((lispd_locator_chain_t *)(node->data))->eid_name,
               ((lispd_locator_chain_t *)(node->data))->locator_count);
        dump_tree_elt((lispd_locator_chain_t *)(node->data));

    } PATRICIA_WALK_END;
}

void debug_installed_database_entry(lispd_locator_chain_t *locator_chain,
                                    lispd_locator_chain_elt_t *db_entry)
{
    char        buf[128];
    char        rloc[128];

    if (!db_entry->interface) {
        inet_ntop(db_entry->locator_afi,
                  &(db_entry->locator_addr.address),
                  rloc, 128);
    } else {
        inet_ntop(db_entry->locator_afi,
                  &(db_entry->interface->address),
                  rloc, 128);
    }
    if (db_entry->locator_type == STATIC_LOCATOR)
        sprintf(buf, "%s", rloc);
    else
        sprintf(buf, "%s (%s)", db_entry->locator_name, rloc);
    log_msg(INFO, " installed %s lisp %s %s p %d w %d",
           (locator_chain->eid_prefix.afi == AF_INET) ? "ip":"ipv6",
	   locator_chain->eid_name,
	   buf,
           db_entry->priority,
	   db_entry->weight);
}

void print_hmac(uchar *hmac, int len)
{

    int i;

    for (i = 0; i < len; i += 4) {
        printf("i = %d\t(0x%04x)\n", i, (unsigned int) hmac[i]);
    }
    printf("\n");
}
 
/* 
 * lisp_print_nonce 
 * 
 * Print 64-bit nonce in 0x%08x-0x%08x format. 
 */ 
void print_nonce (uint64_t nonce)
{ 
    uint32_t lower; 
    uint32_t upper; 
 
    lower = nonce & 0xffffffff; 
    upper = (nonce >> 32) & 0xffffffff; 
    log_msg(INFO,"nonce: 0x%08x-0x%08x\n", htonl(upper), htonl(lower));
} 

    

    
