/*
 * lispd_events.h
 *
 * Event loop and dispatch declarations for the lispd process.
 * This is the main run loop of the process.
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

#include "lispd.h"

#define DEFAULT_SELECT_TIMEOUT		1	/* s */

void event_loop(void);
void signal_handler(int sig);
int build_event_socket(void);
int build_receive_sockets(void);
int have_input(int max_fd, fd_set *readfds);
int process_lisp_msg(int s, int afi);
int retrieve_lisp_msg(int s, uint8_t *packet, void *from, int afi);
