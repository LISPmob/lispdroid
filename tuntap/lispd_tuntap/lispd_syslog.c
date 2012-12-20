/*
 *	lispd_syslog --
 *
 *	Logging and debug output routinges for lispd.
 *
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

#include "lispd_syslog.h"
#include "lispd.h"
#include "lispd_config.h"
#include <time.h>

FILE *logfile = NULL;
int log_level = INFO;

static char *logstrings[] = {
    "INFO",
    "WARN",
    "ERR",
    "FATAL"
};

void log_msg(int level, char *format, ...)
{
    FILE *fp = logfile;
    va_list argptr;
    char timebuf[80];
    struct tm *ts;
    time_t now;

    if (level >= log_level && level <= FATAL) {
        if (!fp) {
           fp = stderr;
        }

        now = time(NULL);
        ts = localtime(&now);
        va_start(argptr, format);
        strftime(timebuf, 80, "%b %d %H:%M:%S", ts);
        fprintf(fp, "%s [%s]: ", timebuf, logstrings[level]);
        vfprintf(fp, format, argptr);
        fprintf(fp, "\n");
        va_end(argptr);

        fflush(logfile);
    } else {
        printf("ASSERT: Unknown log level passed to log_msg, %d", level);
    }
}

void set_log_level(int level) {
    if (log_level >= INFO && log_level <= FATAL) {
        log_level = level;
    } else {
        fprintf(stderr, "Attempt to set logging level out of bounds, %d\n", level);
    }
}

void rotate_logs (void) {
    FILE *fp;
    char name[128];
    char newname[128];
    int i;

    /*
     * Remove the oldest log file
     */
    sprintf(name, "%s.%d", LOGFILE_LOCATION, MAX_LOGFILES);
    fp = fopen(name, "r");

    if (fp) {
        fclose(fp);
        unlink(name);
    }

    /*
     * Rename all the existing logfiles to one older
     */
    for (i = MAX_LOGFILES - 1; i > 0; i--) {
        sprintf(name, "%s.%d", LOGFILE_LOCATION, i);
        sprintf(newname, "%s.%d", LOGFILE_LOCATION, i+1);
        rename(name, newname);
    }

    /*
     * And special case the most recent log
     */
    sprintf(newname, "%s.1", LOGFILE_LOCATION);
    rename(LOGFILE_LOCATION, newname);
}

void setup_log (void)
{
    set_log_level(log_level);

    if (lispd_config.daemonize) {

        freopen( "/dev/null", "r", stdin);
        freopen( "/dev/null", "w", stdout);
        freopen( "/dev/null", "w", stderr);

        rotate_logs();
        logfile = freopen(LOGFILE_LOCATION, "w", stderr);
        if (!logfile) {
            fprintf(stderr, "Failed to open logfile errno: %d", errno);
            exit(-1);
            return;
        }
    } else {
        logfile = stdout;
    }
    log_msg(INFO, "starting up...");
}


