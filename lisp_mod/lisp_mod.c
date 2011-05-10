/*
 * lisp_mod.c
 *
 * Main entry point and initialization code
 * for the LISP kernel module.
 *
 * Copyright 2010, Cisco Systems
 * Author: Chris White
 */

#include "lisp_mod.h"
#include "lisp_slab.h"
#include "packettypes.h"
#include "tables.h"
#include "version.h"

MODULE_LICENSE("GPL");  /* Temporary, just quiets the kernel down */
MODULE_AUTHOR("Christopher White");
MODULE_DESCRIPTION("LISP Protocol Support");

/*
 * Module globals
 */
lisp_globals globals;

/*
 * setup_netfilter_hooks()
 *
 * Wire up our input and output routines into the
 * ip stack.
 */
int setup_netfilter_hooks(void)
{
  globals.netfilter_ops_in.hook     = lisp_input;
  globals.netfilter_ops_in.pf       = PF_INET;
  globals.netfilter_ops_in.hooknum  = NF_INET_PRE_ROUTING;
  globals.netfilter_ops_in.priority = NF_IP_PRI_FIRST;

  globals.netfilter_ops_out.hook    = lisp_output4;
  globals.netfilter_ops_out.pf      = PF_INET;
  globals.netfilter_ops_out.hooknum = NF_INET_LOCAL_OUT;
  globals.netfilter_ops_out.priority = NF_IP_PRI_FIRST;

  globals.netfilter_ops_out6.hook    = lisp_output6;
  globals.netfilter_ops_out6.pf      = PF_INET6;
  globals.netfilter_ops_out6.hooknum = NF_INET_LOCAL_OUT;
  globals.netfilter_ops_out6.priority = NF_IP_PRI_FIRST;
    
  globals.udp_control_port = LISP_CONTROL_PORT;
  globals.udp_encap_port   = LISP_ENCAP_PORT;
  nf_register_hook(&globals.netfilter_ops_in); 
  nf_register_hook(&globals.netfilter_ops_out);
  nf_register_hook(&globals.netfilter_ops_out6);
  printk(KERN_INFO "   Netfilter hooks created.");

  return 0;
}

/* 
 * teardown_netfilter_hooks()
 *
 * Remove ourselves from the IP stack if the module
 * is being removed.
 */
int teardown_netfilter_hooks(void)
{
  nf_unregister_hook(&globals.netfilter_ops_in);
  nf_unregister_hook(&globals.netfilter_ops_out);
  nf_unregister_hook(&globals.netfilter_ops_out6);
  return 0;
}

/*
 * Module initialization
 */

/*
 * lisp_init()
 *
 * Main entry point for the module, performs all sub-initialization
 */
static int __init lisp_init (void)
{
  int result = 0;

  printk(KERN_INFO "lisp_mod version %d.%d.%d starting up...\n",
         MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

  result = setup_netfilter_hooks(); 

  if (result != 0) {
    printk(KERN_INFO "   failed to create hooks...\n");
    return -1;
  }

  result = setup_netlink_socket();

  if (result != 0) { 
    printk(KERN_INFO "   failed to create NL socket...\n");
    return -1;
  }

  create_tables();

#ifdef	USE_LISP_SLAB_ALLOCATOR
  if (init_lisp_caches()) {
    printk(KERN_INFO "lisp caches created\n");
  } else {
    printk(KERN_INFO "couldn't create lisp caches\n");
    return -1;
  }
#endif 

  globals.always_encap = 1;       // XXX temporary for testing
  memset(&globals.my_rloc, 0, sizeof(lisp_addr_t));
  globals.my_rloc_af = 0;
  globals.daemonPID = 0;          // 0 indicates unset

  return 0;
}

/* 
 * lisp_exit()
 *
 * Cleanup routine, called when module is removed from the
 * kernel.
 */
static void __exit lisp_exit (void)
{

  printk(KERN_INFO "lisp_mod cleaning up...\n");
  teardown_netfilter_hooks();
  printk(KERN_INFO "   Netfilter hooks removed.");
  teardown_netlink_socket();
  printk(KERN_INFO "   Netlink socket closed.");
#ifdef	USE_LISP_SLAB_ALLOCATOR
  delete_lisp_caches();
  printk(KERN_INFO "   lisp caches deleted\n");
#endif
}

module_init(lisp_init);
module_exit(lisp_exit);
