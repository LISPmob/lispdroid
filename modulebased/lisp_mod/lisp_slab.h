
/*
 *	lisp_slab.h
 *
 *	Support for the slab allocator
 * 
 *	David Meyer
 *	dmm@1-4-5.net
 *	Tue Apr 13 14:59:35 2010
 *
 *
 */

#define	USE_LISP_SLAB_ALLOCATOR

#ifdef USE_LISP_SLAB_ALLOCATOR
extern struct kmem_cache *lisp_map_cache;		/* map cache */
extern struct kmem_cache *lisp_map_cache_loctype;	/* mc locators */
extern struct kmem_cache *lisp_database;		/* database */
extern struct kmem_cache *lisp_database_loctype;	/* db locators */

int init_lisp_caches(void);
void delete_lisp_caches(void);
#endif
