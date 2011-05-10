/*
 *	lisp_slab.c
 *
 *	Initialize/destroy and support for the slab allocator
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Tue Apr 13 14:46:48 2010
 *
 *	$Header: $
 *
 */


#include "tables.h"
#include "lisp_mod.h"

#ifdef	USE_LISP_SLAB_ALLOCATOR
struct kmem_cache *lisp_map_cache;		/* map cache */
struct kmem_cache *lisp_map_cache_loctype;	/* mc locators */
struct kmem_cache *lisp_database;		/* database */
struct kmem_cache *lisp_database_loctype;	/* db locators */

int init_lisp_caches(void)
{
    lisp_map_cache = kmem_cache_create("lisp_map_cache_t",
				       sizeof(lisp_map_cache_t), 
				       0,                  
				       SLAB_HWCACHE_ALIGN, 
				       NULL);              
    if (lisp_map_cache == NULL) {
	printk(KERN_INFO "Couldn't create lisp_map_cache_t cache\n");
	return (0);
    }

    lisp_map_cache_loctype = kmem_cache_create("lisp_map_cache_loc_t",
				       sizeof(lisp_map_cache_loc_t), 
				       0,                  
				       SLAB_HWCACHE_ALIGN, 
				       NULL);              
    if (lisp_map_cache_loctype == NULL) {
	printk(KERN_INFO "Couldn't create lisp_map_cache_loc_t cache\n");
	return (0);
    }

    lisp_database = kmem_cache_create("lisp_database_entry_t",
				       sizeof(lisp_database_entry_t), 
				       0,                  
				       SLAB_HWCACHE_ALIGN, 
				       NULL);              
    if (lisp_database == NULL) {
	printk(KERN_INFO "Couldn't create lisp_database_entry_t cache\n");
	return (0);
    }

    lisp_database_loctype = kmem_cache_create("lisp_database_loc_t",
				       sizeof(lisp_database_loc_t), 
				       0,                  
				       SLAB_HWCACHE_ALIGN, 
				       NULL);              
    if (lisp_database_loctype == NULL) {
	printk(KERN_INFO "Couldn't create lisp_database_loc_t cache\n");
	return (0);
    }

    return(1);
}

void delete_lisp_caches(void)
{
    teardown_trees();

    if (lisp_map_cache)
	kmem_cache_destroy(lisp_map_cache);
    if (lisp_map_cache_loctype)
	kmem_cache_destroy(lisp_map_cache_loctype);
    if (lisp_database)
	kmem_cache_destroy(lisp_database);
    if (lisp_database_loctype)
	kmem_cache_destroy(lisp_database_loctype);
    return;
}

#endif

