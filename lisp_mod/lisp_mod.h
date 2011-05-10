/*
 * lisp_mod.h
 *
 * Declarations and constants for the LISP kernel module.
 *
 * Copyright 2010, Cisco Systems
 * Author: Chris White
 */

#pragma once

#include "linux/module.h"	
#include "linux/kernel.h"
#include "linux/netfilter.h"
#include "linux/netfilter_ipv4.h"
#include "linux/netlink.h"
#include "net/net_namespace.h"
#include "tables.h"
#include "lisp_ipc.h"
#include "lisp_ipc_kernel.h"
#include "lisp_input.h"
#include "lisp_output.h"
#include "lisp_slab.h"
#include "lib/patricia/patricia.h"

#define NETLINK_LISP 20  /* XXX Temporary, needs to be in /usr/include/linux/netlink.h */

typedef struct {
  struct sock *nl_socket;       /* Netlink socket */
  struct nf_hook_ops netfilter_ops_in;  /* Netfilter hook definition, input */
  struct nf_hook_ops netfilter_ops_out; /* Netfilter hook definition, output */
  struct nf_hook_ops netfilter_ops_out6; /* "" For ipv6 */
  int    always_encap;         /* Always LISP encapsulate? */
  lisp_addr_t my_rloc; /* Locally generated packets source RLOC, set via command-line */
  ushort my_rloc_af;
  ushort udp_encap_port;
  ushort udp_control_port;
  int   daemonPID; /* Process ID for lispd */
} lisp_globals;

