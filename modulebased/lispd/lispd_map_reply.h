/*
 * lispd_map_reply.h
 *
 * Handle the processing of map-replies from the mapping
 * system. Adds map cache entries if required.
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems
 */

int process_map_reply(lispd_pkt_map_reply_t *pkt);
void retry_map_requests(void);
void send_map_reply(lispd_pkt_map_request_t *pkt,
                    struct sockaddr_in *source);
