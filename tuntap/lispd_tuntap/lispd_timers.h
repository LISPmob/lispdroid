/*
 * lispd_timers.h
 *
 * Timer maintenance routines. Simple to start with (single
 * master timer triggers check of timestamps for map-registers/
 * map-reply retries).
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

#include <signal.h>
#include <time.h>

#define RLOC_PROBE_CHECK_INTERVAL 1 // 1 second

typedef struct _timer_links {
    struct _timer_links *prev;
    struct _timer_links *next;
} timer_links;

struct _timer;
typedef int (*timer_callback)(struct _timer *t, void *arg);

typedef struct _timer {
    timer_links     links;
    int             duration;
    int             rotation_count;
    timer_callback  cb;
    void           *cb_argument;
    char            name[64];
} timer;

int      init_timers();
timer   *create_timer(char *);
void     start_timer(timer *, int, timer_callback,
                   void *);
void     stop_timer(timer *);
void     handle_timers(void);
