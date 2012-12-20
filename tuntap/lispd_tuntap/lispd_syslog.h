/*
 * lispd_syslog.h
 *
 * Syslog routines for lispd.
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

#ifndef LISPD_SYSLOG_H
#define LISPD_SYSLOG_H

#include <stdarg.h>

#define LOGFILE_LOCATION "/sdcard/lispd.log"

#define INFO        0
#define WARNING     1
#define ERROR       2
#define FATAL       3

#define MAX_LOGFILES 5

void setup_log(void);
void log_msg(int level, char *format, ...);

#endif
