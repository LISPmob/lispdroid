/*
 * lispd_ipc.c
 *
 * Interprocess communication definitions for lispd.
 * Provides an API for other applications and utilities to
 * control/query lispd over a UNIX domain socket.
 *
 * Copyright 2012 Cisco Systems
 * Author: Chris White
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "lispd_ipc.h"
#include "lispd_util.h"
#include "lispd_db.h"
#include "tables.h"


const int LispIPCPathMax = 100;
const char *LispIPCFile = "/data/data/com.le.lispmon/lispd_dcache";
const int MaxIPCCommandLen = 128;

int client_fd = 0;

/*
 * IPC command table
 */
void handle_list_map_cache(void);
void handle_list_data_cache(void);
void handle_list_db(void);

const struct ipc_handler_struct ipc_table[] = {
    { "MapCacheList", "List the current contents of the map cache", handle_list_map_cache },
    { "DataCacheList", "List the current contents of the data cache", handle_list_data_cache },
    { "DatabaseList", "List the current contents of the map database", handle_list_db },
    { "ClearMapCache", "Clear the current map cache", clear_map_cache }
};

static int make_sock_addr(const char *sock_name, struct sockaddr_un *sock_addr,
                          socklen_t *sock_len)
{
    int namelen = strlen(sock_name);

    if (namelen >= ( (int)sizeof(sock_addr->sun_path) - 1)) {
        log_msg(ERROR, "namelen greater than allowed");
        return -1;
    }

    strcpy(sock_addr->sun_path, sock_name);

    sock_addr->sun_family = AF_LOCAL;
   *sock_len = strlen(sock_addr->sun_path) + sizeof(sock_addr->sun_family);
    return 0;
}

void handle_list_map_cache(void)
{}

void handle_list_db(void)
{}

void handle_list_data_cache(void)
{
    datacache_elt_t *elt, *prev;
    char *nonce, addr_buf[128], *msg = NULL, prefix_len[10];
    int msize;

    elt = datacache->head;
    while (elt) {
        nonce = lisp_print_nonce(elt->nonce);
        inet_ntop(elt->eid_prefix.afi, &(elt->eid_prefix.address), addr_buf, sizeof(addr_buf));
        sprintf(prefix_len, "%d", elt->prefix_length);
        if (msg) {
            free(msg);
            msg = NULL;
        }
        msize = sizeof(addr_buf) + strlen(nonce) + strlen(prefix_len) + 1;
        msg = (char *)malloc(sizeof(char)*msize);
        sprintf(msg, "%s#%s#%s", addr_buf, prefix_len, nonce);
        log_msg(INFO, "dcache entry: %s", msg);
        if ( ( send(client_fd, msg, 200, 0) ) < 0 ) {
            log_msg(ERROR, "send error %s", strerror(errno));
            free(msg);
            return NULL;
        }
        elt = elt->next;
    }
    if (msg) {
        free(msg);
    }
}

static void * handle_ipc_requests(void *arg)
{
    struct sockaddr_un sock_addr;
    socklen_t sock_len;
    int sock_fd;
    char cmd[MaxIPCCommandLen];

    unlink(LispIPCFile);

    memset((char *)&sock_addr, 0 ,sizeof(struct sockaddr_un));

    if (make_sock_addr(LispIPCFile, &sock_addr, &sock_len) < 0) {
        log_msg(ERROR, "IPC sock_addr creation failed");
        return NULL;
    }

    if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_msg(ERROR, "IPC socket creation failed %s", strerror(errno));
        return NULL;
    }

    if ((bind(sock_fd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un))) != 0) {
        log_msg(ERROR, "bind call failed %s", strerror(errno));
        return NULL;
    }

    if (listen(sock_fd, 1) != 0) {
        log_msg(ERROR, "listen failed %s", strerror(errno));
        return NULL;
    }

    log_msg(INFO, "Listening on domain socket for IPC");

    while (1) {
        int i;

        if ((client_fd = accept(sock_fd, (struct sockaddr *)&sock_addr, &sock_len)) == -1) {
            log_msg(ERROR, "IPC accept call failed %s", strerror(errno));
            return NULL;
        }

        if (recv(client_fd, cmd, MaxIPCCommandLen, 0) < 0) {
            log_msg(INFO, "IPC recv call failed, %s", strerror(errno));
            return NULL;
        }

        log_msg(INFO, "Received command %s", cmd);

        for (i = 0; i < (sizeof(ipc_table) / sizeof(struct ipc_handler_struct)); i++) {
            if (!strcmp(cmd, ipc_table[i].command)) {
                (*(ipc_table[i].handler))();
                close(client_fd);
                break;
            }
        }
    }
    return 0;
}

void listen_on_well_known_port()
{
    pthread_t ipc_thread;

    if (pthread_create(&ipc_thread, NULL, handle_ipc_requests, NULL) != 0) {
        log_msg(ERROR, "IPC thread creation failed %s", strerror(errno));
        return;
    }
    pthread_detach(ipc_thread);
}
