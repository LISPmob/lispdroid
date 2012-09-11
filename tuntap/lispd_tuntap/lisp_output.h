/*
 * lisp_output.h
 *
 * Packet output path declarations for LISP module.
 *
 * Copyright 2010, Cisco Systems
 * Author: Chris White
 */

#pragma once

unsigned int lisp_output4(unsigned int hooknum, struct sk_buff *packet_buf,
			 const struct net_device *input_dev,
			 const struct net_device *output_dev,
			  int (*okfunc)(struct sk_buff*));

unsigned int lisp_output6(unsigned int hooknum, struct sk_buff *packet_buf,
			 const struct net_device *input_dev,
			 const struct net_device *output_dev,
			 int (*okfunc)(struct sk_buff*));

