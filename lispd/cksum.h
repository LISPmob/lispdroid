/*
 * cksum.h
 *
 * Various checksum routines for packets and headers.
 *
 * Author: David Meyer
 * Copyright 2010 Cisco Systems
 */

#pragma once

#include "lispd.h"

uint16_t ip_checksum(uint16_t *buffer, int size);
uint16_t udp_ipv4_checksum(const void	*buff,
                           unsigned int	 len,
                           in_addr_t	 src,
                           in_addr_t	 dest);
uint16_t udp_checksum(struct udphdr *udph, int udp_len,
                      void *iphdr, int afi);



