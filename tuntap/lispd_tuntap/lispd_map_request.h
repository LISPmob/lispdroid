/*
 * lispd_map_request.h
 *
 * Declarations for map request packet functions.
 *
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

#include "lispd_config.h"
#include "lispd_packets.h"

#define	DEFAULT_MAP_REQUEST_RETRIES	3
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
void setup_probe_timer(void);
void schedule_map_requests(void);
uint8_t *decapsulate_ecm_packet(uint8_t *);
