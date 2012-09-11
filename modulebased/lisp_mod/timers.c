/*
 * timers.h
 *
 * Support for a scalable timer mechanism in the 
 * lisp kernel module. Uses the normal kernel
 * timer facility to wake up every second and
 * walk a sorted list of timers, expiring as necessary.
 */

#include "timers.h"


/*
 * insertion sorted list of timers, closest
 * to expiration first. If we need to scale
 * up further than this can reasonably handle,
 * implemenet as wheel or heap.
 */
