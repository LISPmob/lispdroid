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

int sock_fd = 0;

const int LispIPCPathMax = 100;
const char *LispServerIPCFile = "/data/data/com.le.lispmontun/lispd_ipc_server";
const char *LispClientIPCFile = "/data/data/com.le.lispmontun/lispd_ipc_client";
const int MaxIPCCommandLen = 1024;

struct sockaddr_un client_addr;
socklen_t address_length = sizeof(struct sockaddr_un);


/*
 * IPC command table
 */
void handle_map_cache_lookup(lisp_cmd_t *);
void handle_map_db_lookup(lisp_cmd_t *);
void handle_no_action(lisp_cmd_t *);
void handle_clear_map_cache(lisp_cmd_t *);

// List of IPC commands and their handlers. Several
// of these should be removed as they no longer apply
// without the kernel module. See almost all that
// resolve to handle_no_action() XXX
const struct ipc_handler_struct ipc_table[] = {
    { "Ok", handle_no_action },
    { "Failed", handle_no_action },
    { "Map Cache Lookup", handle_map_cache_lookup },
    { "Map Cache EID List", handle_no_action },
    { "Map Cache RLOC List", handle_no_action },
    { "Database Lookup", handle_map_db_lookup },
    { "Cache Sample", handle_no_action },
    { "Add RLOC", handle_no_action },
    { "Add Map Cache Entry", handle_no_action },
    { "Delete Map Cache", handle_no_action },
    { "Map Cache Clear", handle_clear_map_cache },
    { "Add Database Entry", handle_no_action },
    { "Delete Database Entry", handle_no_action },
    { "Register Daemon", handle_no_action },
    { "Start Traffic Monitor", handle_no_action },
    { "Set UDP Ports", handle_no_action },
    { "Set Instance ID", handle_no_action }
};

static int make_sock_addr(const char *sock_name, struct sockaddr_un *sock_addr)

{
    int namelen = strlen(sock_name);

    if (namelen >= ( (int)sizeof(sock_addr->sun_path) - 1)) {
        log_msg(ERROR, "namelen greater than allowed");
        return -1;
    }

    strcpy(sock_addr->sun_path, sock_name);

    sock_addr->sun_family = AF_UNIX;
    return 0;
}

static void wait_for_completion()
{
    socklen_t addr_len;
    lisp_cmd_t *cmd = malloc(MaxIPCCommandLen);
    struct timeval tv;

    tv.tv_sec = 2;  /* 2 Secs Timeout */
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors

    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

    if (recvfrom(sock_fd, cmd, MaxIPCCommandLen, 0, (struct sockaddr *)&client_addr,
                 &addr_len) < 0) {
        log_msg(INFO, "IPC recv call failed, %s", strerror(errno));
        free(cmd);
        return;
    }

    log_msg(INFO, "Received command, type: %d", cmd->type);

    if (cmd->type == LispOk) {
        log_msg(INFO, "Transaction complete, closing connection");
    } else {
        log_msg(INFO, "Unknown command in mid-transaction, closing connection anyway.");
    }
    free(cmd);
}

static void * handle_ipc_requests(void *arg)
{
    struct sockaddr_un sock_addr;
    socklen_t sock_len = sizeof(struct sockaddr_un);
    lisp_cmd_t *cmd = malloc(MaxIPCCommandLen);

    if (!cmd) {
        log_msg(ERROR, "Failed to allocate IPC receive msg buffer!");
        return NULL;
    }

    unlink(LispServerIPCFile);

    memset((char *)&sock_addr, 0 ,sizeof(struct sockaddr_un));

    if (make_sock_addr(LispServerIPCFile, &sock_addr) < 0) {
        log_msg(ERROR, "IPC sock_addr creation failed");
        return NULL;
    }

    if ((sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
        log_msg(ERROR, "IPC socket creation failed %s", strerror(errno));
        return NULL;
    }

    if ((bind(sock_fd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un))) != 0) {
        log_msg(ERROR, "bind call failed %s", strerror(errno));
        return NULL;
    }

    while (1) {

        if (recvfrom(sock_fd, cmd, MaxIPCCommandLen, 0, (struct sockaddr *)&client_addr,
                     &sock_len) < 0) {
            log_msg(INFO, "IPC recvfrom call failed, %s", strerror(errno));
            continue;
        }

        log_msg(INFO, "Received command, type: %d", cmd->type);

        (*(ipc_table[cmd->type].handler))(cmd);
      //  wait_for_completion();

    }
    close(sock_fd);
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

int send_message(lisp_cmd_t *cmd)
{
    int err;

    log_msg(INFO, "Sending command to client, type %d", cmd->type);

    err = sendto(sock_fd, cmd, cmd->length + sizeof(lisp_cmd_t), MSG_DONTWAIT,
                 (struct sockaddr *)&client_addr, sizeof(struct sockaddr_un));
    if (err < 0) {
        log_msg(ERROR, "Failed to send message to client, errno: %d", errno);
    }
    return(err);
}

/*
 * send_command_complete_msg()
 *
 * Send a message to user-level client that the previous
 * command is complete.
 */
int send_command_complete_msg()
{
    int err;
    lisp_cmd_t *cmd = malloc(sizeof(lisp_cmd_t));
    if (!cmd) {
        log_msg(INFO,  "Unable to allocate space for response.\n");
        return -1;
    }

    cmd->type                 = LispOk;
    cmd->length               = 0;
    err = send_message(cmd);
    free(cmd);
    return(err);
}

/*
 * send_cache_lookup_response_msg()
 *
 * Send a response message to user-level clients for
 * a cache lookup.
 */
int send_cache_lookup_response_msg(lisp_map_cache_t *entry)
{
    lisp_cmd_t                *cmd = malloc(MaxIPCCommandLen);
    int                        max_locators;
    lisp_cache_response_loc_t *tmp_loc;
    lisp_map_cache_loc_t      *locator;
    uint32_t                   loc_count = 0;
    int                        err = 0;
    lisp_cache_response_msg_t *map_msg;

    if (!cmd) {
        log_msg(INFO,  "Unable to allocate space for response.\n");
        return -1;
    }

    max_locators = (MaxIPCCommandLen - sizeof(lisp_cache_response_msg_t)) /
            sizeof(lisp_cache_response_loc_t);

    cmd->type                 = LispMapCacheLookup;
    cmd->length               = sizeof(lisp_eid_map_msg_t); // XXX reflect locators
    map_msg  = (lisp_cache_response_msg_t *)cmd->val;

    memcpy(&map_msg->eid_prefix, &entry->eid_prefix,
           sizeof(lisp_addr_t));
    map_msg->eid_prefix_length = entry->eid_prefix_length;
    map_msg->ttl         = entry->ttl;
    map_msg->how_learned = entry->how_learned;
    map_msg->nonce0      = entry->nonce0;
    map_msg->nonce1      = entry->nonce1;
    map_msg->lsb         = entry->lsb;
    map_msg->timestamp   = entry->timestamp;
    map_msg->control_packets_in  = entry->control_packets_in;
    map_msg->control_packets_out = entry->control_packets_out;

    /*
     * Walk the locator list and fill in the locator entries.
     */
    for (loc_count = 0; loc_count < entry->count; loc_count++) {
        tmp_loc = map_msg->locators + loc_count;
        locator = entry->locator_list[loc_count];
        if (locator) {
            memcpy(&tmp_loc->locator, &locator->locator, sizeof(lisp_addr_t));
            tmp_loc->priority = locator->priority;
            tmp_loc->weight = locator->weight;
            tmp_loc->mpriority = locator->mpriority;
            tmp_loc->mweight = locator->mweight;
            tmp_loc->reachability_alg = locator->reachability_alg;
            tmp_loc->state = locator->state;
            tmp_loc->data_packets_in = locator->data_packets_in;
            tmp_loc->data_packets_out = locator->data_packets_out;
        }
    }
    map_msg->num_locators = entry->count;
    cmd->length += map_msg->num_locators * (sizeof(lisp_addr_t) +
                                            sizeof(lisp_cache_response_loc_t));

    log_msg(INFO,  " Added %d locators\n", entry->count);
    log_msg(INFO,  " Sending response.");
    err = send_message(cmd);
    if (err < 0)
        log_msg(INFO,  " send_message() returned %d\n", err);
    free(cmd);
    return 0;
}

/*
 * send_db_lookup_response_msg()
 *
 * Send a response message to user-level clients for
 * a cache lookup.
 */
int send_db_lookup_response_msg(lisp_database_entry_t *entry)
{
    lisp_cmd_t                *cmd = malloc(MaxIPCCommandLen);
    int                        err;
    int                        max_locators;
    lisp_database_loc_t       *locator;
    lisp_db_response_loc_t    *tmp_loc;
    int                        loc_count = 0;
    lisp_db_response_msg_t    *map_msg;

    if (!cmd) {
        log_msg(INFO,  "Unable to allocate space for response.\n");
        return -1;
    }

    max_locators = (MaxIPCCommandLen - sizeof(lisp_db_response_msg_t)) /
            sizeof(lisp_db_response_loc_t);

    cmd->type                 = LispDatabaseLookup;
    cmd->length               = sizeof(lisp_eid_map_msg_t);
    map_msg  = (lisp_db_response_msg_t *)cmd->val;

    memcpy(&map_msg->eid_prefix, &entry->eid_prefix,
           sizeof(lisp_addr_t));
    map_msg->eid_prefix_length = entry->eid_prefix_length;
    map_msg->lsb = entry->lsb;

    /*
     * Walk the locator list and fill in the locator entries.
     */
    for (loc_count = 0; loc_count < entry->count; loc_count++) {
        tmp_loc = map_msg->locators + loc_count;
        locator = entry->locator_list[loc_count];
        if (locator) {
            memcpy(&tmp_loc->locator, &locator->locator, sizeof(lisp_addr_t));
            tmp_loc->priority = locator->priority;
            tmp_loc->weight = locator->weight;
            tmp_loc->mpriority = locator->mpriority;
            tmp_loc->mweight = locator->mweight;
        }
    }
    map_msg->num_locators = entry->count;
    cmd->length += map_msg->num_locators * ((sizeof(lisp_addr_t) +
                                             sizeof(lisp_cache_response_loc_t)));
    log_msg(INFO,  " Added %d locators\n", loc_count);
    log_msg(INFO,  " Sending response.");

    err = send_message(cmd);
    if (err < 0)
        log_msg(INFO,  " netlink_unicast() returned %d\n", err);
    free(cmd);
    return 0;
}

/*
 * handle_map_cache_lookup()
 *
 * Process a cache lookup request message from user-level
 */
void handle_map_cache_lookup(lisp_cmd_t *cmd)
{
    patricia_node_t *node;
    lisp_map_cache_t *map_entry = NULL;
    lisp_lookup_msg_t *lu_msg = (lisp_lookup_msg_t *)cmd->val;

    // replace with mutex spin_lock_bh(&table_lock);
    log_msg(INFO, "In handle_map_cache_lookup()");
    /*
     * Exact match request? Do the lookup and send a single
     * response
     */
    if (!lu_msg->all_entries) {
        switch (lu_msg->prefix.afi) {
        case AF_INET:
            if (lu_msg->exact_match) {
                lookup_eid_cache_v4_exact(lu_msg->prefix.address.ip.s_addr,
                                          lu_msg->prefix_length,
                                          &map_entry);
            } else {
                lookup_eid_cache_v4(lu_msg->prefix.address.ip.s_addr, &map_entry);
            }
            break;
        case AF_INET6:
            if (lu_msg->exact_match) {
                lookup_eid_cache_v6_exact(lu_msg->prefix,
                                          lu_msg->prefix_length,
                                          &map_entry);
            } else {
                lookup_eid_cache_v6(lu_msg->prefix, &map_entry);
            }
            break;
        }
        if (map_entry != NULL) {
            send_cache_lookup_response_msg(map_entry);
        }
    } else {

        /*
         * Walk the cache patricia trie and send a message back
         * for each entry.
         */
        PATRICIA_WALK(AF4_eid_cache->head, node) {
            map_entry = node->data;
            log_msg(INFO,  "at node %pi4/%d @0x%x\n",
                    &(node->prefix->add.sin.s_addr),
                    node->prefix->bitlen,
                    (unsigned) map_entry);
            if (map_entry) {
                    send_cache_lookup_response_msg(map_entry);
            }
        } PATRICIA_WALK_END;

        PATRICIA_WALK(AF6_eid_cache->head, node) {
            map_entry = node->data;
            log_msg(INFO,  "at node %pi6/%d @0x%x\n",
                    node->prefix->add.sin6.s6_addr,
                    node->prefix->bitlen,
                    (unsigned) map_entry);
            if (map_entry) {
                send_cache_lookup_response_msg(map_entry);
            }
        } PATRICIA_WALK_END;
    }
    // replace with mutex spin_unlock_bh(&table_lock);

    /*
     * Notify the client that the walk is complete
     */
    send_command_complete_msg();
}

/*
 * allocate_cmd_buffer()
 *
 * Allocate a new buffer for a message.
 */
int allocate_cmd_buffer(lisp_cmd_t **cmd, lisp_msgtype_e type, int len)
{
    *cmd = malloc(MaxIPCCommandLen);

    if (!*cmd) {
        log_msg(INFO,  "Failed to allocate space for %s message", ipc_table[type].command);
        return FALSE;
    }

    (*cmd)->type                 = type;
    (*cmd)->length               = len;
    return(TRUE);
}

/*
  * build_eid_list_entry()
  *
  * Place a single eid address in the eid list for a message
  */
int build_eid_list_entry(uint32_t *count, lisp_cmd_t **cmd,
                          lisp_addr_t *addr)
{
    int err;
    uint32_t max_entries = (MaxIPCCommandLen - (sizeof(lisp_cmd_t) + sizeof(lisp_cache_address_list_t))) /
            sizeof(lisp_addr_t);
    lisp_cache_address_list_t *eidlist = (lisp_cache_address_list_t *)(*cmd)->val;

    if (*count == max_entries) {
        log_msg(INFO, "Entries exceeds single message size, sending current and building new");
        (*cmd)->length = sizeof(lisp_cache_address_list_t) + sizeof(lisp_addr_t) * (*count);
        eidlist->count = *count;
        err = send_message(*cmd);
        if (err < 0) {
            log_msg(INFO,  "Error sending to client, aborting. Errno: %d\n", errno);
            return(FALSE);
        }

        /* Grab a new buffer */
        *count = 0;
        free(cmd);
        *cmd = NULL;
        if (!allocate_cmd_buffer(cmd, LispMapCacheEIDList, 0)) {; // Set length later
            return(FALSE); // Client can retry on schedule.
        }
        eidlist = (lisp_cache_address_list_t *)(*cmd)->val;
    }
    (*count)++;
    memcpy(&eidlist->addr_list[*count - 1], addr,
           sizeof(lisp_addr_t));
    return(TRUE);
}

/*
  * build_rloc_list_entry()
  *
  * Place a single rloc address in the list for a message
  */
int build_rloc_list_entry(uint32_t *count, lisp_cmd_t **cmd,
                           lisp_map_cache_t *entry)
{
    int err;
    uint32_t i;
    uint32_t max_entries = (MaxIPCCommandLen - (sizeof(lisp_cmd_t) + sizeof(lisp_cache_address_list_t))) /
            sizeof(lisp_addr_t);
    lisp_cache_address_list_t *rloclist = (lisp_cache_address_list_t *)(*cmd)->val;

    for (i = 0; i < entry->count; i++) {
        if (*count == max_entries) {
            log_msg(INFO, "Entries exceeds single message size, sending current and building new");
            (*cmd)->length = sizeof(lisp_cache_address_list_t) + sizeof(lisp_addr_t) * (*count);
            rloclist->count = *count;
            err = send_message(*cmd);
            if (err < 0) {
                log_msg(INFO,  "Error sending to client. Aborting. Errno %d\n", errno);
                return(FALSE);
            }

            /* Grab a new buffer */
            *count = 0;
            free(*cmd);
            if (!allocate_cmd_buffer(cmd, LispMapCacheRLOCList, 0)) { // Set length later
                return(FALSE); // Client can retry on schedule.
            }
            rloclist = (lisp_cache_address_list_t *)(*cmd)->val;
        }
        (*count)++;
        memcpy(&rloclist->addr_list[*count - 1], &entry->locator_list[i]->locator,
               sizeof(lisp_addr_t));
    }
    return(TRUE);
}

/*
 * send_map_cache_list()
 *
 * Provide a list of all EIDs or RLOCs in all address families
 * currently in the map cache, addresses and AFIs only.
 */
void send_map_cache_list(uint16_t request_type,
                         char with_traffic_only)
{
    patricia_node_t *node;
    lisp_map_cache_t *map_entry = NULL;
    lisp_cmd_t *cmd;
    uint32_t addr_count = 0;

    if (!allocate_cmd_buffer(&cmd, request_type, 0)) // Set length later
    {
        return; // Client can retry on schedule.
    }
    // replace with mutex spin_lock_bh(&table_lock);

    /*
     * Walk the cache patricia trie and build a
     * message containing the list of addresses
     * of each EID entry.
     */
    PATRICIA_WALK(AF4_eid_cache->head, node) {
        map_entry = node->data;
        log_msg(INFO,  "at node %pi4/%d @0x%x\n",
                &(node->prefix->add.sin.s_addr),
                node->prefix->bitlen,
                (unsigned) map_entry);

        if (request_type == LispMapCacheEIDList) {
            if (!build_eid_list_entry(&addr_count, &cmd,
                                      &map_entry->eid_prefix)) {
                return;
            }
        } else if (request_type == LispMapCacheRLOCList) {

            /*
             * If for traffic monitoring function, only add those
             * entries that had traffic.
             */
            if (!(with_traffic_only && !map_entry->active_within_period)) {
                if (!build_rloc_list_entry(&addr_count, &cmd,
                                           map_entry)) {
                    return;
                }
            }
        } else {
            log_msg(INFO,  "Unknown map cache request type %d\n", request_type);
            return;
        }
    } PATRICIA_WALK_END;

    PATRICIA_WALK(AF6_eid_cache->head, node) {
        map_entry = node->data;
        log_msg(INFO,  "at node %pi6/%d @0x%x\n",
                node->prefix->add.sin6.s6_addr,
                node->prefix->bitlen,
                (unsigned) map_entry);

        if (request_type == LispMapCacheEIDList) {
            if (!build_eid_list_entry(&addr_count, &cmd,
                                      &map_entry->eid_prefix)) {
                return;
            }
        } else if (request_type == LispMapCacheRLOCList) {

            /*
             * If for traffic monitoring function, only add those
             * entries that had traffic.
             */
            if (!(with_traffic_only && !map_entry->active_within_period)) {
                if (!build_rloc_list_entry(&addr_count, &cmd,
                                           map_entry)) {
                    return;
                }
            }
        } else {
            log_msg(INFO,  "Unknown map cache request type %d\n", request_type);
            return;
        }
    } PATRICIA_WALK_END;

    /*
     * If any are left after the above run, send them out
     */
    if (addr_count) {
        int err;
        log_msg(INFO, "Sending map-cache list to client with %d entries.", addr_count);
        ((lisp_cache_address_list_t *)(cmd->val))->count = addr_count;
        cmd->length = sizeof(lisp_cache_address_list_t) + sizeof(lisp_addr_t) * (addr_count);
        err = send_message(cmd);
        if (err < 0) {
            log_msg(INFO,  "Error sending to client: %d.", errno);
            return;
        }
    }

    // replace with mutex // replace with mutex spin_unlock_bh(&table_lock);

    /*
     * Notify the client that the list is complete
     */
    send_command_complete_msg();
}

/*
 * handle_clear_map_cache()
 *
 */
void handle_clear_map_cache(lisp_cmd_t *cmd)
{
    clear_map_cache();
}

/*
 * handle_map_db_lookup()
 *
 * Process a databse lookup request message from user-level
 */
void handle_map_db_lookup(lisp_cmd_t *cmd)
{
    patricia_node_t *node;
    lisp_database_entry_t *db_entry;

    /*
   * Walk the cache patricia trie and send a message back
   * for each entry.
   */
    // replace with mutex spin_lock_bh(&table_lock);
    PATRICIA_WALK(AF4_eid_db->head, node) {
        db_entry = node->data;
        log_msg(INFO,  "at node %pi4/%d @0x%x\n",
                &(node->prefix->add.sin.s_addr),
                node->prefix->bitlen,
                (unsigned) db_entry);
        if (db_entry)
            send_db_lookup_response_msg(db_entry);
    } PATRICIA_WALK_END;

    PATRICIA_WALK(AF6_eid_db->head, node) {
        db_entry = node->data;
        log_msg(INFO,  "at node %pi6/%d @0x%x\n",
                node->prefix->add.sin6.s6_addr,
                node->prefix->bitlen,
                (unsigned) db_entry);
        if (db_entry)
            send_db_lookup_response_msg(db_entry);
    } PATRICIA_WALK_END;
    // replace with mutex spin_unlock_bh(&table_lock);

    /*
   * Notify the client that the walk is complete
   */
    send_command_complete_msg();
}

/*
 * handle_no_action()
 *
 * Generic handler for messages we either don't take action on or don't
 * support.
 */
void handle_no_action(lisp_cmd_t *cmd)
{
    log_msg(INFO,  "  No action taken for this message type.");
}
