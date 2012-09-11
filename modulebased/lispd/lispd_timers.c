/*
 * lispd_timers.c
 *
 * Timer maintenance routines.
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems, Inc.
 */
#include <signal.h>
#include <time.h>

#include "lispd.h"
#include "lispd_db.h"
#include "lispd_if.h"
#include "lispd_map_register.h"
#include "lispd_timers.h"
#include "lispd_netlink.h"

#define TIMER_INTERVAL 1   // Seconds

lispd_timers_t timers;

/*
 * create_timer()
 *
 * Creates (and starts) a posix timer with the given
 * interval in seconds. Timer will automatically restart.
 */
timer_t create_timer(int seconds)
{
    timer_t tid;
    struct sigevent sev;
    long long freq_ns;
    struct itimerspec timerspec;

    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    sev.sigev_value.sival_ptr = &tid;
    if (timer_create(CLOCK_REALTIME, &sev, &tid) == -1)
    {
        log_msg(INFO, "timer_create(): %s", strerror(errno));
        return -1;
    }

    timerspec.it_value.tv_nsec = 0;
    timerspec.it_value.tv_sec = seconds;
    timerspec.it_interval.tv_nsec = 0;
    timerspec.it_interval.tv_sec = seconds;
    log_msg(INFO, "timer %d set for %d seconds",
           tid, timerspec.it_value.tv_sec);

    if (timer_settime(tid, 0, &timerspec, NULL) == -1) {
        log_msg(INFO, "timer start failed for %d %s",
               tid, strerror(errno));
        return -1;
    }

    return(tid);
}
/*
 * init_timers()
 *
 */
int init_timers(void)
{
    log_msg(INFO, "Initializing lispd timers...");

    timers.register_time.tv_sec = 0;
    timers.register_time.tv_usec = 0;

    timers.request_time.tv_sec = 0;
    timers.request_time.tv_usec = 0;

    timers.rp_time.tv_sec = 0;
    timers.rp_time.tv_usec = 0;

    timers.nat_check_time.tv_sec = 0;
    timers.nat_check_time.tv_usec = 0;

    timers.smr_time.tv_sec = 0;
    timers.smr_time.tv_usec = 0;

    timers.gw_time.tv_sec = 0;
    timers.gw_time.tv_usec = 0;

    if (create_timer(TIMER_INTERVAL) == -1) {
        log_msg(INFO, "Failed to set up lispd timers.");
        return(0);
    }
    return(1);
}


/*
 * set_timer()
 *
 * Sets the given time to go off at the next interval
 * in seconds.
 */
void set_timer(timer_type_e timertype, int seconds)
{
    struct timeval nowtime;

    gettimeofday(&nowtime, NULL);
    switch (timertype) {
    case MapRegisterSend:
        timers.register_time.tv_sec = nowtime.tv_sec + seconds; // Jitter XXX
        timers.register_time.tv_usec = 0;
        break;
    case MapRequestRetry:
        timers.request_time.tv_sec = nowtime.tv_sec + seconds;
        timers.request_time.tv_usec = 0;
        break;
    case RLOCProbeScan:
        timers.rp_time.tv_sec = nowtime.tv_sec + seconds;
        timers.rp_time.tv_usec = 0;
        break;
    case NATDetectRetry:
        timers.nat_check_time.tv_sec = nowtime.tv_sec + seconds;
        timers.nat_check_time.tv_usec = 0;
        break;
    case StartSMRs:
        timers.smr_time.tv_sec = nowtime.tv_sec + seconds;
        timers.smr_time.tv_usec = 0;
        break;
    case DefaultGWDetect:
        timers.gw_time.tv_sec = nowtime.tv_sec + seconds;
        timers.gw_time.tv_usec = 0;
        break;
    }
}

/*
 * stop_timer()
 *
 * Mark one of the global timers as stopped.
 */
void stop_timer(timer_type_e timertype)
{
    switch (timertype) {
    case MapRegisterSend:
        timers.register_time.tv_sec = 0;
        timers.register_time.tv_usec = 0;
        break;
    case MapRequestRetry:
        timers.request_time.tv_sec = 0;
        timers.request_time.tv_usec = 0;
        break;
    case RLOCProbeScan:
        timers.rp_time.tv_sec = 0;
        timers.rp_time.tv_usec = 0;
        break;
    case NATDetectRetry:
        timers.nat_check_time.tv_sec = 0;
        timers.nat_check_time.tv_usec = 0;
        break;
    case StartSMRs:
        timers.smr_time.tv_sec = 0;
        timers.smr_time.tv_usec = 0;
        break;
    case DefaultGWDetect:
        timers.gw_time.tv_sec = 0;
        timers.gw_time.tv_usec = 0;
    }
 }

/*
 * handle_timers()
 *
 * Check to see if any of the lisp timers have expired.
 * If so, call the appropriate function to deal with it.
 */
void handle_timers(void)
{
    struct timeval nowtime;

    gettimeofday(&nowtime, NULL);

    if (timercmp(&nowtime, &timers.register_time, >) && (timers.register_time.tv_sec != 0)) {
        log_msg(INFO, "Map-register timer expired");
        map_register();
    }

    if (timercmp(&nowtime, &timers.request_time, >) && (timers.request_time.tv_sec != 0)) {
        log_msg(INFO, "Check for map request retries");
        retry_map_requests();
    }

    if (timercmp(&nowtime, &timers.rp_time, >) && (timers.rp_time.tv_sec != 0)) {
        issue_rloc_probes();
    }

    if (timercmp(&nowtime, &timers.nat_check_time, >) && (timers.nat_check_time.tv_sec != 0)) {
        check_nat_status();
    }

    if (timercmp(&nowtime, &timers.smr_time, >) && (timers.smr_time.tv_sec != 0)) {
      //  start_smr_traffic_monitor();
    }

    if (timercmp(&nowtime, &timers.gw_time, >) && (timers.gw_time.tv_sec != 0)) {
        check_default_gateway();
    }
    return;
}
