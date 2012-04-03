/*
 * lispd_timers.h
 *
 * Timer maintenance routines. Simple to start with (single
 * master timer triggers check of timestamps for map-registers/
 * map-reply retries).
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems, Inc.
 */
#pragma once

#include <signal.h>
#include <time.h>

#define RLOC_PROBE_CHECK_INTERVAL 1 // 1 second

typedef struct {
    struct timeval register_time;
    struct timeval request_time;
    struct timeval rp_time;
    struct timeval nat_check_time;
    struct timeval smr_time;
    struct timeval gw_time;
} lispd_timers_t;

/*
 * Timer definitions
 */
typedef enum {
    MapRegisterSend = 1,
    MapRequestRetry = 2,
    NATDetectRetry = 3,
    RLOCProbeScan = 4,
    StartSMRs = 5,
    DefaultGWDetect = 6
} timer_type_e;

int  init_timers(void);
void set_timer(timer_type_e, int);
void stop_timer(timer_type_e);
void handle_timers(void);
