/*
 * lispd_events.h
 *
 * Event loop and dispatch declarations for the lispd process.
 * This is the main run loop of the process.
 *
 * Author: Dave Meyer and Chris White
 * Copyright 2010 Cisco Systems
 */

#include "lispd.h"

void event_loop(void);
void signal_handler(int sig);
int build_event_socket(void);
int build_receive_sockets(void);
int have_input(int max_fd, fd_set *readfds);
int process_lisp_msg(int s, int afi);
int retrieve_lisp_msg(int s, uint8_t *packet, void *from, int afi);
