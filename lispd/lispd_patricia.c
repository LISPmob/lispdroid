/*
 *	lispd_patricia.c
 *
 *	Patrica tree manipulation functions
 */

#include "lispd_external.h"

/*
 *	make_and_lookup for network format prefix
 */

patricia_node_t *make_and_lookup_network(afi,addr,mask_len)
     int	afi;
     void      *addr;
     int	mask_len;
{
    struct in_addr	*sin;
    struct in6_addr	*sin6;
    int			 bitlen;
    prefix_t		*prefix;
    patricia_node_t	*node;

    if ((node = malloc(sizeof(patricia_node_t))) == NULL) {
        log_msg(INFO, "can't allocate patrica_node_t");
	return(NULL);
    }

    switch(afi) {
    case AF_INET:
        sin    = (struct in_addr *) addr;
	if ((prefix = New_Prefix(AF_INET, sin, mask_len)) == NULL) {
            log_msg(INFO, "couldn't alocate prefix_t for AF_INET");
	    return(NULL);
	}
        node   = patricia_lookup(AF4_database, prefix);
	break;
    case AF_INET6:
        sin6   = (struct in6_addr *) addr;
	if ((prefix = New_Prefix(AF_INET6, sin6, mask_len)) == NULL) {
            log_msg(INFO, "couldn't alocate prefix_t for AF_INET6");
	    return(NULL);
	}
        node   = patricia_lookup(AF6_database, prefix);
	break;
    default:
	free(node);
	free(prefix);
        log_msg(INFO, "Unknown afi (%d) when allocating prefix_t", afi);
	return (NULL);
    }
    Deref_Prefix (prefix);
    return(node);
}
