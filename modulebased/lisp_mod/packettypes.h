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
#define LISP_CONTROL_PORT 4342

typedef struct lisphdr { 
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t rflags:3;
    uint8_t instance_id:1;
    uint8_t map_version:1;
    uint8_t echo_nonce:1;
    uint8_t lsb:1;
    uint8_t nonce_present:1;
#else
  uint8_t nonce_present:1;
  uint8_t lsb:1;
  uint8_t echo_nonce:1;
  uint8_t map_version:1;
  uint8_t instance_id:1;
  uint8_t rflags:3;
#endif
  uint8_t nonce[3];
  uint32_t lsb_bits;
} lisphdr_t;

