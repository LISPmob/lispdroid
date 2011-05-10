/*
 * lispd_map_request.h
 *
 * Declarations for map request packet functions.
 *
 * Author: David Meyer and Chris White
 * Copyright 2010, Cisco Systems
 */
#pragma once

#include "lispd_config.h"
#include "lispd_packets.h"

#define REQUEST_INTERVAL 1 // One second between map request retries
#define SMR_HOLDOFF_TIME 5 // five seconds between database change and start of SMRs

typedef enum {
    NormalRequest = 0,
    SMR = 1,
    RLOCProbe = 2
} request_type_e;

uint64_t build_and_send_map_request(lisp_addr_t              *eid_prefix,
                                    uint8_t                   eid_prefix_length);
void process_map_request(lispd_pkt_map_request_t *pkt,
                         struct sockaddr_in *sa);
void schedule_solicit_map_requests(void);
