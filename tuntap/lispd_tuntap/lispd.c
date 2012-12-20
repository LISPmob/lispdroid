/*
 *	lispd.c 
 *
 *	lispd main entry point and startup code.
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

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>

#include "lispd.h"
#include "lispd_packets.h"
#include "lispd_config.h"
#include "lispd_events.h"
#include "lispd_db.h"
#include "lispd_netlink.h"
#include "lispd_if.h"
#include "lispd_syslog.h"
#include "lispd_map_register.h"
#include "lispd_timers.h"
#include "lispd_util.h"
#include "lispd_tuntap.h"
#include "tables.h"
#include "version.h"

/*
 * Lock to prevent multiple instances
 */
#define LISPD_LOCKFILE "/sdcard/lispd.lock"
#define LISPD_INFOFILE "/sdcard/lispd.info"
int fdlock;

void init(void) {

    /*
     *	config paramaters
     */
    memset(&lispd_config, 0, sizeof(lispd_config));
    lispd_config.map_resolvers	= 0;
    lispd_config.map_servers	= 0;
    lispd_config.config_file			= "lispd.conf";
    lispd_config.map_resolver_name		= NULL;
    lispd_config.map_server_name	        = NULL;
    lispd_config.debug				= 0;
    lispd_config.daemonize			= 1;
    lispd_config.map_request_retries		= DEFAULT_MAP_REQUEST_RETRIES;
    lispd_config.control_port			= LISP_CONTROL_PORT;
    lispd_config.data_port                      = LISP_DATA_PORT;
    lispd_config.local_control_port             = LISP_LOCAL_CONTROL_PORT;
    lispd_config.local_data_port                = LISP_LOCAL_CONTROL_PORT;
    lispd_config.use_ms_as_petr                 = 0;
    lispd_config.use_nat_lcaf                   = 1;
    lispd_config.petr_addr_is_set               = 0;
    lispd_config.translated_control_port        = 0;
    lispd_config.rloc_probe_interval            = DEFAULT_PROBE_INTERVAL;
    lispd_config.rloc_probe_retries             = DEFAULT_PROBE_RETRIES;
    lispd_config.use_dns_override               = FALSE;
    lispd_config.instance_id                    = 0;
    lispd_config.use_instance_id                = FALSE;
    lispd_config.use_location                   = FALSE;
    lispd_config.tun_mtu                        = 0;
}

void dump_fatal_error(void) {
    FILE *fp, *logfp;
    char logline[128];
    fp = fopen(LISPD_INFOFILE, "w+");

    if (!fp) {
        log_msg(WARNING, "Could not write lispd info file to %s", LISPD_INFOFILE);
        return;
    }

    logfp = fopen(LOGFILE_LOCATION, "r");

    if (!logfp) {
        log_msg(WARNING, "Could not open log file for reading.");
    }
    fprintf(fp, "There was an error starting the LISP daemon:\n");

    while (fgets(logline, 128, logfp)) {

        /* note that the newline is in the buffer */
        fprintf(fp, "%s", logline);
    }
    fclose(logfp);
    fclose(fp);
}

void dump_info_file(void) {
    FILE *fp;
    char addr_buf[128];
    lispd_map_server_list_t *ms = NULL;
    lispd_addr_list_t *mr = NULL;
    int plural = FALSE;

    fp = fopen(LISPD_INFOFILE, "w+");

    if (!fp) {
        log_msg(WARNING, "Could not write lispd info file to %s", LISPD_INFOFILE);
        return;
    }

    fprintf(fp, "Version:         %d.%d.%d\n", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);
    fprintf(fp, "Device EID(s):   ");
    if (lispd_config.eid_address_v4.afi) {
        fprintf(fp, "%s\n", inet_ntop(AF_INET,
                                      &lispd_config.eid_address_v4.address,
                                      addr_buf, 128));
    }
    if (lispd_config.eid_address_v6.afi) {
        fprintf(fp, "                 %s\n", inet_ntop(AF_INET6,
                                                       lispd_config.eid_address_v6.address.ipv6.s6_addr,
                                                       addr_buf, 128));
    }

    if (lispd_config.use_instance_id) {
        fprintf(fp, "Instance ID:     %d\n", lispd_config.instance_id);
    }
    fprintf(fp, "Map Server(s):   ");
    ms = lispd_config.map_servers;
    while (ms)
    {
        if (plural) {
            fprintf(fp, ",\n                 ");
        }
        fprintf(fp, "%s", inet_ntop(ms->address->afi,
                                    &ms->address->address,
                                    addr_buf, 128));
        plural = TRUE;
        ms = ms->next;
    }
    fprintf(fp, "\n");

    plural = FALSE;
    fprintf(fp, "Map Resolver(s): ");
    mr = lispd_config.map_resolvers;
    while (mr) {

        if (plural) {
            fprintf(fp, ",\n                 ");
        }
        fprintf(fp, "%s", inet_ntop(mr->address->afi,
                                    &mr->address->address,
                                    addr_buf, 128));
        plural = TRUE;
        mr = mr->next;
    }
    fprintf(fp, "\n");
    fprintf(fp, "Configured Interface(s):\n");
    dump_interfaces(fp);

    fprintf(fp, "Locator(s):\n");
    dump_database(AF4_database, AF_INET, fp);
    dump_database(AF6_database, AF_INET6, fp);

    if (lispd_config.use_dns_override) {
        fprintf(fp, "LISP DNS Resolver: %s", inet_ntop(AF_INET, &lispd_config.dns_override_address1.address,
                                                       addr_buf, 128));

        if (lispd_config.dns_override_address2.address.ip.s_addr != 0) {
            fprintf(fp, "\nLISP Second DNS Resolver: %s", inet_ntop(AF_INET, &lispd_config.dns_override_address2.address,
                                                                    addr_buf, 128));
        }
    }
    fclose(fp);
}

int get_process_lock(int pid)
{
    struct flock fl;
    char pidString[128];

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 1;

    if ((fdlock = open(LISPD_LOCKFILE, O_RDWR|O_CREAT, 0666)) == -1) {
        return FALSE;
    }

    if (fcntl(fdlock, F_SETLK, &fl) == -1) {
        return FALSE;
    }
    sprintf(pidString, "%d\n", pid);
    write(fdlock, pidString, strlen(pidString));
    return TRUE;
}

void remove_process_lock()
{
    close(fdlock);
    unlink(LISPD_LOCKFILE);
}

void die(int exitcode)
{
    remove_process_lock();
    exit(exitcode);
}


int main(int argc, char **argv)
{
    int    fd                           = 0;
    pid_t  pid				= 0;	/* child pid */
    pid_t  sid				= 0;

    init();

    /*
     *	set up databases
     */
    if (!db_init()) {
        log_msg(INFO, "Couldn't create databases");
        exit(EXIT_FAILURE);
    }

    /*
     *	Parse command line options
     */
    handle_lispd_command_line(argc, argv);

    /*
     *	see if we need to daemonize, and if so, do it
     */
    if (lispd_config.daemonize) {
        log_msg(INFO, "lispd is backgrounding...");
        if ((pid = fork()) < 0) {
            exit(EXIT_FAILURE);
        }

        if (pid > 0) {
            log_msg(INFO, "done. Running as PID %d", pid);
            exit(EXIT_SUCCESS);
        }
        umask(0);
        if ((sid = setsid()) < 0)
            exit(EXIT_FAILURE);
        if ((chdir("/")) < 0)
            exit(EXIT_FAILURE);

        /*
         * Redirect standard files to /dev/null save fd in
         * case we need to get back to stdout later
         */
        fd = dup(fileno(stdout));
    }

    signal(SIGHUP,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGQUIT, signal_handler);

    init_timers();

    /*
     * Check if lispd is already running. Only allow one instance!
     */
    if (!get_process_lock(getpid())) {
        log_msg(FATAL, "lispd already running, please stop before restarting. If this seems wrong"
                " remove %s.", LISPD_LOCKFILE);


        printf("lispd already running, please stop before restarting.\n If this appears wrong,"
               " remove %s.\n", LISPD_LOCKFILE);
        exit(EXIT_FAILURE);
    }
#if 0
    if (!setup_netlink()) {
        log_msg(FATAL, "Can't set up netlink socket (is the kernel module loaded?), exiting...");
        die(EXIT_FAILURE);
    }
#endif
    if (!setup_rtnetlink()) {
        log_msg(FATAL, "Can't setup rtnetlink socket, exiting...");
        die(EXIT_FAILURE);
    }
#if 0
    if (!register_lispd_process()) {
        log_msg(FATAL, "Couldn't register lispd process, exiting...");
        die(EXIT_FAILURE);
    }
#endif
    log_msg(INFO, "Version %d.%d.%d starting up...",
            MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

    /*
     * now build the v4/v6 receive sockets
     */
    if (build_receive_sockets() == 0) {
        log_msg(FATAL, "  exiting...");
        die(EXIT_FAILURE);
    }

    create_tables();

    if (build_event_socket() == 0)
    {
        log_msg(FATAL, "  exiting...");
        die(EXIT_FAILURE);
    }
    log_msg(INFO, "Built receive/event sockets");

    /*
     *	Now do the config file
     */
    if (handle_lispd_config_file()) {
        log_msg(FATAL, "Fatal error parsing config file.");
        dump_fatal_error();
        die(EXIT_FAILURE);
    }

    if (tuntap_create_tun() < 0) {
        log_msg(FATAL, "  exiting...");
        die(EXIT_FAILURE);
    }

    /*
     *	set up syslog now, checking to see if we're daemonizing...
     */
    setup_log();

    log_msg(INFO, "Read config file");

    if (!install_database_mappings()) {
        log_msg(FATAL, "  exiting...");
        die(EXIT_FAILURE);
    }
#ifdef DEADCODE
    if (!install_map_cache_entries())
        log_msg(INFO, "Could not install static map-cache entries");
#endif
    map_register(NULL, NULL);
    setup_probe_timer();

    // Open up the data plane (done in the event loop for now, due to NAT port issues)
    // start_tun_recv();

    clear_map_cache();

    listen_on_well_known_port();

    dump_info_file();
    event_loop();
    log_msg(INFO, "exiting...");		/* event_loop returned bad */
    remove_process_lock();
    exit(0);
}


