/*
 * lispd_encap.h
 *
 * Packet output path declarations for LISP
 *
 * Copyright 2010, Cisco Systems
 * Author: Chris White
 */

#pragma once

unsigned int lisp_output4(char *packet_buf, int length);
unsigned int lisp_output6(char *packet_buf, int length);
