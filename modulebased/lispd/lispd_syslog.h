/*
 * lispd_syslog.h
 *
 * Syslog routines for lispd.
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems
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
