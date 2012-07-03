/*
 * lispd_ipc.h
 *
 * Interprocess communication declarations for lispd.
 * Provides an API for other applications and utilities to
 * control/query lispd over a unix domain socket.
 *
 * Copyright 2012 Cisco Systems
 * Author: Chris White
 */

#pragma once

/*
 * Command table
 */
typedef void(*ipc_handler)(void);

struct ipc_handler_struct {
    const char *command;
    const char *description;
    ipc_handler handler;
};

void listen_on_well_known_port(void);
