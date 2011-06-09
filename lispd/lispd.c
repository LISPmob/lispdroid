/*
 *	lispd.c 
 *
 *	implement the lispd
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Fri Apr 16 13:48:48 2010
 *
 *	$Header: /usr/local/src/lispd/RCS/lispd.c,v 1.8 2010/04/21 20:29:42 dmm Exp $
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
    fprintf(fp, "Device EID(s):      ");
    if (lispd_config.eid_address_v4.afi) {
        fprintf(fp, "%s\n", inet_ntop(AF_INET,
                                  &lispd_config.eid_address_v4.address,
                                  addr_buf, 128));
    }
    if (lispd_config.eid_address_v6.afi) {
        fprintf(fp, "%s\n", inet_ntop(AF_INET6,
                                  lispd_config.eid_address_v6.address.ipv6.s6_addr,
                                  addr_buf, 128));
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
    fprintf(fp, "Locator(s):\n");
    dump_database(AF4_database, AF_INET, fp);
    dump_database(AF6_database, AF_INET6, fp);
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

  if ((fdlock = open(LISPD_LOCKFILE, O_WRONLY|O_CREAT, 0666)) == -1) {
      return FALSE;
  }

  sprintf(pidString, "%d\n", pid);
  write(fdlock, pidString, strlen(pidString));
  if (fcntl(fdlock, F_SETLK, &fl) == -1) {
      return FALSE;
  }
  return TRUE;
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
        freopen( "/dev/null", "r", stdin);
        freopen( "/dev/null", "w", stdout);
        freopen( "/dev/null", "w", stderr);
    }

    signal(SIGHUP,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGQUIT, signal_handler);

    init_timers();

    /*
     *	set up syslog now, checking to see if we're daemonizing...
     */
    setup_log();

    /*
     * Check if lispd is already running. Only allow one instance!
     */
    if (!get_process_lock(getpid())) {
        log_msg(FATAL, "lispd already running, please stop before restarting. If this seems wrong"
                " remove %s.", LISPD_LOCKFILE);

        /*
         * Wrench stdout back so we can nofity user outside log
         */
        dup2(fd, fileno(stdout));
        close(fd);
        clearerr(stdout);
        printf("lispd already running, please stop before restarting.\n If this appears wrong,"
               " remove %s.\n", LISPD_LOCKFILE);
        exit(EXIT_FAILURE);
    }

    if (!setup_netlink()) {
        log_msg(FATAL, "Can't set up netlink socket, exiting...");
        exit(EXIT_FAILURE);
    }
    if (!setup_rtnetlink()) {
        log_msg(FATAL, "Can't setup rtnetlink socket, exiting...");
        exit(EXIT_FAILURE);
    }

    if (!register_lispd_process()) {
        log_msg(FATAL, "Couldn't register lispd process, exiting...");
        exit(EXIT_FAILURE);
    }

    log_msg(INFO, "Version %d.%d.%d starting up...",
           MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

    /*
     * now build the v4/v6 receive sockets
     */
    if (build_receive_sockets() == 0) {
        log_msg(FATAL, "  exiting...");
        exit(EXIT_FAILURE);
    }

    if (build_event_socket() == 0)
    {
        log_msg(FATAL, "  exiting...");
        exit(EXIT_FAILURE);
    }
    log_msg(INFO, "Built receive/event sockets");

    /*
     *	Now do the config file
     */
    handle_lispd_config_file();
    log_msg(INFO, "Read config file");

    if (!install_database_mappings()) {
        log_msg(FATAL, "  exiting...");
        exit(EXIT_FAILURE);
    }
#ifdef DEADCODE
    if (!install_map_cache_entries())
        log_msg(INFO, "Could not install static map-cache entries");
#endif
    if (!map_register())
        log_msg(INFO, "Could not map register.");

    set_timer(RLOCProbeScan, RLOC_PROBE_CHECK_INTERVAL);

    clear_map_cache();

    dump_info_file();
    event_loop();
    log_msg(INFO, "exiting...");		/* event_loop returned bad */
    return 0;
}


