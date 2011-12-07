/*
 * lispd_packets.h
 *
 * Packet formats for LISP control messages.
 *
 * Author: Chris White
 *
 * Copyright 2010 Cisco Systems.
 */

#pragma once

#include "lispd.h"

/*
 * LISP Packet Types
 */
#define	LISP_MAP_REQUEST		1
#define	LISP_MAP_REPLY			2
#define	LISP_MAP_REGISTER		3
#define LISP_ECHO                       7
#define LISP_ENCAP_CONTROL_TYPE		8
#define	LISP_CONTROL_PORT		4342
#define LISP_DATA_PORT                  4341
#define LISP_LOCAL_CONTROL_PORT         43420
#define LISP_LOCAL_DATA_PORT            LISP_LOCAL_CONTROL_PORT

/*
 *	Map Reply action codes
 */
#define LISP_ACTION_NO_ACTION		0
#define LISP_ACTION_FORWARD		1
#define LISP_ACTION_DROP		2
#define LISP_ACTION_SEND_MAP_REQUEST	3

/*
 *	#define AF_INET         2
 *	#define AF_INET6        10
 *
 */
#define LISP_AFI_IP			1
#define LISP_AFI_IPV6			2
#define LISP_AFI_LCAF                   16387
#define	LISP_IP_MASK_LEN		32

/*
 *	map-cache entry types (how_learned)
 */
#define	STATIC_MAP_CACHE_ENTRY		0
#define	DYNAMIC_MAP_CACHE_ENTRY		1

/*
 *	for map-register auth data...
 */
#define LISP_SHA1_AUTH_DATA_LEN		20

/*
 * Map Echo message use to determine NAT address, ports (in the future)
 *
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=7 |R|                      Reserved                       |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |               AFI             |        Locator Address ...    |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * AFI and Locator Address only present in Echo-Reply.
 */
typedef struct {
#ifdef __LITTLE_ENDIAN_BITFIELD
   uchar     rsvd:3;
   uchar     echo_reply:1;
   uchar     type:4;
#else
   uchar     type:4;
   uchar     echo_reply:1;
   uchar     rsvd:3;
#endif
   uchar     reserved[3];
   uint64_t  nonce;
   uchar     data[0];
} PACKED lispd_pkt_echo_t;

#define LISP_LCAF_NAT 7

typedef struct {
    uint16_t  afi;
    uchar     address[0];
} PACKED lispd_pkt_echo_reply_t;

/*
 * LISP LCAF Address structure
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |           AFI = 16387         |    Rsvd1     |     Flags      |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |    Type       |     Rsvd2     |            Length             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef struct {
    uint16_t  afi;
    uint8_t   rsvd;
    uint8_t   flags;
    uint8_t   type;
    uint8_t   rsvd2;
    uint16_t  length;
    uint8_t   address[0];
} PACKED lispd_pkt_lcaf_t;

/*
 * LISP NAT Travseral LCAF format
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Reserved            |       UDP/TCP Port Number     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |       Global RLOC Address ... |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |     Private RLOC Address  ... |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |       NTR RLOC Address    ... |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef struct {
    uint16_t rsvd;
    uint16_t port;
    uint8_t  addresses[0];
} PACKED lispd_pkt_nat_lcaf_t;

typedef struct {
    uint16_t afi;
    uint8_t address[0];
} PACKED lispd_pkt_lcaf_addr_t;

/*
 * Mapping record used in all LISP control messages.
 *
 *  +--->  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      |                          Record  TTL                          |
 *  |      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R      | Locator Count | EID mask-len  | ACT |A|       Reserved        |
 *  e      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c      | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  o      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r      |                          EID-prefix                           |
 *  d      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  |    / +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Loc |         Unused Flags    |L|p|R|           Loc-AFI             |
 *  |    \ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     \|                             Locator                           |
 *  +--->  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Fixed portion of the mapping record. EID prefix address and
 * locators follow.
 */
typedef struct lispd_pkt_mapping_record_t_ {
    uint32_t ttl;
    uint8_t locator_count;
    uint8_t eid_prefix_length;
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t reserved1:4;
    uint8_t authoritative:1;
    uint8_t action:3;
#else
    uint8_t action:3;
    uint8_t authoritative:1;
    uint8_t reserved1:4;
#endif
    uint8_t reserved2;
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t version_hi:4;
    uint8_t reserved3:4;
#else
    uint8_t reserved3:4;
    uint8_t version_hi:4;
#endif
    uint8_t version_low;
    uint16_t eid_prefix_afi;
} PACKED lispd_pkt_mapping_record_t;

/*
 * Fixed portion of the mapping record locator. Variable length
 * locator address follows.
 */
typedef struct lispd_pkt_mapping_record_locator_t_ {
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;
    uint8_t unused1;
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t reachable:1;
    uint8_t probed:1;
    uint8_t local:1;
    uint8_t unused2:5;
#else
    uint8_t unused2:5;
    uint8_t local:1;
    uint8_t probed:1;
    uint8_t reachable:1;
#endif
    uint16_t locator_afi;
} PACKED lispd_pkt_mapping_record_locator_t;

/*
 * Map-Registers have an authentication header before the UDP header.
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=3 |P|            Reserved                 | Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                       Mapping Records ...                     |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                      Mapping Protocol Data                    |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Map-Register Message Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=3 |P|            Reserved             |m|M| Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   |                          Record  TTL                          |
 *   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   r   |                          EID-prefix                           |
 *   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+a
 *   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  \|                             Locator                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                     Mapping Protocol Data                     |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct lispd_pkt_map_register_t_ {
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t  reserved1:3;
    uint8_t  proxy_reply:1;
    uint8_t  lisp_type:4;
#else
    uint8_t  lisp_type:4;
    uint8_t  proxy_reply:1;
    uint8_t  reserved1:3;
#endif

    uchar    reserved2;

#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t  map_notify:1;
    uint8_t  mobile_node:1;
    uint8_t  reserved3:6;
#else
    uint8_t  reserved3:6;
    uint8_t  mobile_node:1;
    uint8_t  map_notify:1;
#endif

    uint8_t  record_count;
    uint64_t nonce;
    uint16_t key_id;
    uint16_t auth_data_len;
    uint8_t  auth_data[LISP_SHA1_AUTH_DATA_LEN];
} PACKED lispd_pkt_map_register_t;


/*
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |                   Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct lispd_pkt_encapsulated_control_t_ {
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t reserved1:4;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t reserved1:4;
#endif
    uint8_t reserved2[3];
} PACKED lispd_pkt_encapsulated_control_t;

/*
 * Map-Request Message Format
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=1 |A|M|P|S|      Reserved       |   IRC   | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         Source-EID-AFI        |    Source EID Address  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                        EID-prefix ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                      Mappping Record ...                      |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Use the nonce to calculate the source port for a map request
 * message.
 */
#define LISP_PKT_MAP_REQUEST_UDP_SPORT(_Nonce) (0xf000 | (_Nonce & 0xfff))

#define LISP_PKT_MAP_REQUEST_TTL 32

/*
 * Fixed size portion of the map request. Variable size source EID
 * address, originating ITR RLOC AFIs and addresses and then map
 * request records follow.
 */
typedef struct lispd_pkt_map_request_t_ {
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t solicit_map_request:1;
    uint8_t rloc_probe:1;
    uint8_t map_data_present:1;
    uint8_t authoritative:1;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t authoritative:1;
    uint8_t map_data_present:1;
    uint8_t rloc_probe:1;
    uint8_t solicit_map_request:1;
#endif
#ifdef __LITTLE_ENDIAN_BITFIELD
   uchar             reserved1:5;
   uchar             mn_bit:1;
   uchar             smr_invoked_bit:1;
   uchar             pitr_bit:1;
#else
   uchar             pitr_bit:1;
   uchar             smr_invoked_bit:1;
   uchar             mn_bit:1;
   uchar             reserved1:5;
#endif

#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t additional_itr_rloc_count:5;
    uint8_t d_bit:1;
    uint8_t reserved2:2;
#else
    uint8_t reserved2:2;
    uint8_t d_bit:1;
    uint8_t additional_itr_rloc_count:5;
#endif
    uint8_t record_count;
    uint64_t nonce;
    uint16_t source_eid_afi;
} PACKED lispd_pkt_map_request_t;

/*
 * The IRC value above is set to one less than the number of ITR-RLOC
 * fields (an IRC of zero means one ITR-RLOC). In 5 bits we can encode
 * the number 15 which means we can have up to 16 ITR-RLOCs.
 */
#define LISP_PKT_MAP_REQUEST_MAX_ITR_RLOCS 16

/*
 * Fixed size portion of map request ITR RLOC.
 */
typedef struct lispd_pkt_map_request_itr_rloc_t_ {
    uint16_t afi;
    /*    uint8_t address[0]; */
} PACKED lispd_pkt_map_request_itr_rloc_t;

/*
 * Fixed size portion of the map request record. Variable size EID
 * prefix address follows.
 */
typedef struct lispd_pkt_map_request_eid_prefix_record_t_ {
    uint8_t reserved;
    uint8_t eid_prefix_mask_length;
    uint16_t eid_prefix_afi;
} PACKED lispd_pkt_map_request_eid_prefix_record_t;


/*
 * Map-Reply Message Format
 *
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=2 |P|E|            Reserved               | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   |                          Record  TTL                          |
 *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r   |                          EID-prefix                           |
 *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  \|                             Locator                           |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Fixed size portion of the EID record. Variable sized EID prefix follows
 */
typedef struct {
    uint32_t ttl;
    uint8_t  loc_count;
    uint8_t  eid_masklen;

#ifdef __LITTLE_ENDIAN_BITFIELD
     uint8_t reserved1:4;
     uint8_t authoritative:1;
     uint8_t act:3;
#else
    uint8_t act:3;
    uint8_t authoritative:1;
    uint8_t reserved1:4;
#endif

   uint8_t reserved2;

#ifdef __LITTLE_ENDIAN_BITFIELD // XXX can't do this with uint16's
    uint16_t version:12;
    uint16_t reserved3:4;
#else
    uint16_t reserved3:4;
    uint16_t version:12;
#endif

    uint16_t eid_afi;
    uint8_t  eid_prefix[0];
} PACKED lispd_pkt_map_reply_eid_prefix_record_t;

/*
 * Fixed size portion of the locator record. Variable sized locator addres
 * follows.
 */
typedef struct {
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;

    uint8_t reserved;
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t reachable:1;
    uint8_t probe:1;
    uint8_t local:1;
    uint8_t reserved2:5;

#else
    uint8_t reserved2:5;
    uint8_t local:1;
    uint8_t probe:1;
    uint8_t reachable:1;
#endif

    uint16_t loc_afi;
    uint8_t  locator[0];
} PACKED lispd_pkt_map_reply_locator_record_t;

/*
 * Fixed size portion of the map reply. Variable size records then follow.
 */
typedef struct lispd_pkt_map_reply_t_ {
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t reserved1:2;
    uint8_t echononce:1;
    uint8_t probe:1;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t probe:1;
    uint8_t echononce:1;
    uint8_t reserved1:2;
#endif
    uint8_t reserved2;
    uint8_t reserved3;
    uint8_t count;

    uint64_t nonce;
    uint8_t records[0];
} PACKED lispd_pkt_map_reply_t;
