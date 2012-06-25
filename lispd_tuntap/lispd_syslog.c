/*
 *	lispd_syslog --
 *
 *	write a message to /var/log/syslog
 *
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Mon Apr 19 11:12:10 2010
 *
 *	$Header: /usr/local/src/lispd/RCS/lispd_syslog.c,v 1.6 2010/04/21 20:29:42 dmm Exp $
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


