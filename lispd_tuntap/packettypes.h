/*
 * packettypes.h
 *
 * Header definitions for LISP control
 * and encapsulation packets.
 *
 * Copyright 2010 Cisco Systems
 *
 */

#pragma once

#define LISP_ENCAP_PORT 4341

typedef struct lisphdr { 
  uint32_t nonce_present:1;
  uint32_t lsb:1;
  uint32_t echo_nonce:1;
  uint32_t rflags:5;
  uint32_t nonce:24;
  uint32_t lsr_bits;
} listhdr_t;

