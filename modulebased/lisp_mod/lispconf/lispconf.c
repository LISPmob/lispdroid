/*
 * lispconf.c
 *
 * Lisp user-level configuration and querying utility. Communicate
 * with lisp kernel module using netlink socket.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "../lisp_ipc.h"
#include <linux/netlink.h>
#include "cmdline.h"

#include <sys/un.h>

const int true = 1;
const int false = 0;

/*
 * Globally reused socket parameters
 */
int    sock_fd;
struct sockaddr_nl src_addr, dst_addr;

int send_command(lisp_cmd_t *cmd, int length)
{
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int retval;

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&iov,      0, sizeof(struct iovec));
    memset(&msg,     0, sizeof(struct msghdr));

    nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_MSG_LENGTH));
    if (!nlh) {
        return -1;
    }

    memset(nlh,       0, sizeof(struct nlmsghdr));

    /* Fill the netlink message header */
    nlh->nlmsg_len   = length + sizeof(struct nlmsghdr);
    nlh->nlmsg_pid   = 0;  /* To kernel */
    nlh->nlmsg_flags = 0;

    /* Fill in the netlink message payload */
    memcpy(NLMSG_DATA(nlh), (char *)cmd, length);

    iov.iov_base     = (void *)nlh;
    iov.iov_len      = nlh->nlmsg_len;
    msg.msg_name     = (void *)&dst_addr;
    msg.msg_namelen  = sizeof(dst_addr);
    msg.msg_iov      = &iov;
    msg.msg_iovlen   = 1;

    if ((retval = sendmsg(sock_fd, &msg, 0)) < 0) {
        perror("sendmsg");
        exit(-1);
    }
    //  free(nlh);
    return retval;
}

#if 0
/*
 * send_map_cache_msg_v4()
 * 
 * Send a single EID/RLOC mapping to the kernel module for the cache.
 * This could easily be expanded to send a list of lisp_cmd_t's
 * to the send_cmd function for multiple entries at once.
 * 
 * For ipv4.
 */
int send_map_cache_msg_v4(uint32_t eid, uint8_t prefixlen, lisp_addr_t rloc,
                          int rloc_afi,
                          uint32_t priority,
                          uint32_t weight,
                          uint32_t ttl)
{
    lisp_eid_map_msg_t map_msg;
    lisp_cmd_t        *cmd;
    int cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_eid_map_msg_t);

    cmd = (lisp_cmd_t *)malloc(cmd_length);
    if (!cmd) {
        return -1;
    }

    cmd->type = LispMapCacheAdd;
    cmd->length = cmd_length;
    memset((char *)&map_msg, 0, sizeof(lisp_eid_map_msg_t));
    map_msg.eid_prefix.address.ip.s_addr = eid;
    map_msg.eid_prefix_length = prefixlen;
    map_msg.eid_afi = AF_INET;
    memcpy(&map_msg.locator, &rloc, sizeof(lisp_addr_t));
    map_msg.loc_afi = rloc_afi;
    map_msg.priority = priority;
    map_msg.weight = weight;
    map_msg.ttl = ttl;
    map_msg.how_learned = 0; // Static
    memcpy(cmd->val, (char *)&map_msg, cmd->length);

    return(send_command(cmd, cmd_length + sizeof(lisp_cmd_t)));
}

/*
 * send_map_cache_msg_v6()
 * 
 * Send a single EID/RLOC mapping to the kernel module for the cache.
 * This could easily be expanded to send a list of lisp_cmd_t's
 * to the send_cmd function for multiple entries at once.
 * 
 * For ipv6.
 */
int send_map_cache_msg_v6(struct in6_addr prefix, uint8_t prefixlen, 
                          lisp_addr_t rloc,
                          int rloc_afi,
                          uint32_t priority,
                          uint32_t weight,
                          uint32_t ttl)
{
    lisp_eid_map_msg_t map_msg;
    lisp_cmd_t        *cmd;
    int cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_eid_map_msg_t);

    cmd = (lisp_cmd_t *)malloc(cmd_length);
    if (!cmd) {
        return -1;
    }

    cmd->type = LispMapCacheAdd;
    cmd->length = cmd_length;
    memset((char *)&map_msg, 0, sizeof(lisp_eid_map_msg_t));
    memcpy(&map_msg.eid_prefix.address.ipv6, &prefix, sizeof(struct in6_addr));
    map_msg.eid_prefix_length = prefixlen;
    map_msg.eid_afi = AF_INET6;
    memcpy(&map_msg.locator, &rloc, sizeof(lisp_addr_t));
    map_msg.loc_afi = rloc_afi;
    map_msg.priority = priority;
    map_msg.weight = weight;
    map_msg.ttl = ttl;
    map_msg.how_learned = 0; // Static
    memcpy(cmd->val, (char *)&map_msg, cmd->length);

    return(send_command(cmd, cmd_length + sizeof(lisp_cmd_t)));
}

/*
 * send_map_db_msg_v6()
 * 
 * Send a single EID/RLOC mapping to the kernel module for the database.
 * This could easily be expanded to send a list of lisp_cmd_t's
 * to the send_cmd function for multiple entries at once.
 * 
 * For ipv6 eid's with ipv4 or ipv6 rlocs.
 */
int send_map_db_msg_v6(struct in6_addr prefix, uint8_t prefixlen, 
                       lisp_addr_t rloc,
                       int rloc_afi,
                       uint32_t priority,
                       uint32_t weight)
{
    lisp_db_add_msg_t map_msg;
    lisp_cmd_t        *cmd;
    int cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_db_add_msg_t);

    cmd = (lisp_cmd_t *)malloc(cmd_length);
    if (!cmd) {
        return -1;
    }

    cmd->type = LispDatabaseAdd;
    cmd->length = sizeof(lisp_db_add_msg_t);
    memset((char *)&map_msg, 0, sizeof(lisp_db_add_msg_t));
    memcpy(&map_msg.eid_prefix.address.ipv6, &prefix, sizeof(struct in6_addr));
    map_msg.eid_prefix_length = prefixlen;
    map_msg.eid_prefix.afi= AF_INET6;
    memcpy(&map_msg.locator, &rloc, sizeof(lisp_addr_t));
    map_msg.locator.afi = rloc_afi;
    map_msg.priority = priority;
    map_msg.weight = weight;

    memcpy(cmd->val, (char *)&map_msg, cmd->length);

    return(send_command(cmd, cmd_length + sizeof(lisp_cmd_t)));
}

/*
 * send_map_db_msg_v4()
 * 
 * Send a single EID/RLOC mapping to the kernel module for the database.
 * This could easily be expanded to send a list of lisp_cmd_t's
 * to the send_cmd function for multiple entries at once.
 * 
 * For v4 eid's with v4 or v6 rloc's
 */
int send_map_db_msg_v4(uint32_t eid, uint8_t prefixlen, lisp_addr_t rloc,
                       int loc_afi,
                       uint32_t priority,
                       uint32_t weight)
{
    lisp_db_add_msg_t map_msg;
    lisp_cmd_t        *cmd;
    int cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_db_add_msg_t);

    cmd = (lisp_cmd_t *)malloc(cmd_length);
    if (!cmd) {
        return -1;
    }

    cmd->type = LispDatabaseAdd;
    cmd->length = sizeof(lisp_db_add_msg_t);
    memset((char *)&map_msg, 0, sizeof(lisp_db_add_msg_t));
    map_msg.eid_prefix.address.ip.s_addr = eid;
    map_msg.eid_prefix_length = prefixlen;
    map_msg.eid_prefix.afi = AF_INET;
    memcpy(&map_msg.locator, &rloc, sizeof(lisp_addr_t));
    map_msg.locator.afi = loc_afi;
    map_msg.priority = priority;
    map_msg.weight = weight;

    memcpy(cmd->val, (char *)&map_msg, cmd->length);

    return(send_command(cmd, cmd_length + sizeof(lisp_cmd_t)));
}

#endif
/*
 * format_uptime
 *
 * Create a string in HH:MM:ss format given a number of seconds
 */
void format_uptime(int seconds, char *buffer) 
{
    double hours = seconds / 3600.0;
    int    wholehours = floor(hours);
    double    frachours = hours - wholehours;
    double minutes = frachours * 60.0;
    int   wholemins = floor(minutes);
    double   fracmins = minutes - wholemins;
    int   new_seconds = fracmins * 60.0;

    sprintf(buffer, "%02d:%02d:%02d", wholehours, wholemins, new_seconds);
}

/*
 * process_print_cache_responses
 *
 * Wait for, receive and process responses from the kernel 
 * to the previous cache lookup request. A string of responses
 * to a request will be terminated by a LispOk message.
 *
 */
int process_print_cache_responses(void)
{
    struct nlmsghdr *nlh = malloc(NLMSG_SPACE(MAX_MSG_LENGTH));
    lisp_cmd_t *cmd;
    lisp_cache_response_msg_t *map_msg;
    lisp_cache_response_loc_t *tmp_loc;
    int retval;
    int loc_count = 0;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    char buf[256], buf2[256];
    char *formatted_eid = NULL;
    char *formatted_rloc = NULL;
    struct timeval uptime;
    struct timeval expiretime;

    iov.iov_base    = (void *)nlh;
    iov.iov_len     = MAX_MSG_LENGTH;
    msg.msg_name    = (void *)&(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    
    if (!nlh) {
        printf("Memory allocation failure\n");
        return -1;
    }

    printf("LISP IP Mapping Cache\n\n");

    while (1) {
        if ((retval = recvmsg(sock_fd, &msg, 0)) < 0) {
            perror("recvmsg");
            break;
        }
        cmd = NLMSG_DATA(nlh);
        map_msg = (lisp_cache_response_msg_t *)cmd->val;
        if (cmd->type == LispOk) {
            break;
        }
        if (cmd->type == LispMapCacheLookup) {
            switch (map_msg->eid_prefix.afi) {
            case AF_INET:
                if ((formatted_eid = (char *)  inet_ntop(AF_INET,
                                                         &(map_msg->eid_prefix.address.ip.s_addr),
                                                         buf,
                                                         sizeof(buf))) == NULL) {
                    perror("inet_ntop (eid)");
                    exit(-1);
                }
                break;
            case AF_INET6:
                if ((formatted_eid = (char *)  inet_ntop(AF_INET6,
                                                         map_msg->eid_prefix.address.ipv6.s6_addr,
                                                         buf,
                                                         sizeof(buf))) == NULL) {
                    perror("inet_ntop (eid)");
                    exit(-1);
                }
                break;
            default:
                printf("Unknown address family in response\n");
                continue;
                break;
            }

            printf("%s/%d, ", formatted_eid, map_msg->eid_prefix_length);
            gettimeofday(&uptime, NULL);
            uptime.tv_sec = uptime.tv_sec - map_msg->timestamp;
            format_uptime(uptime.tv_sec, buf);
            expiretime.tv_sec = (map_msg->ttl * 60) - uptime.tv_sec;
            if (expiretime.tv_sec > 0) {
                format_uptime(expiretime.tv_sec, buf2);
            }
            printf("uptime: %s, expires: %s, via ", buf, expiretime.tv_sec > 0 ? buf2 : "EXPIRED");

            if (map_msg->how_learned == 0) { // static
                printf("static\n");
            } else {
                printf("map-reply\n");
            }

            tmp_loc = map_msg->locators;
            if (map_msg->num_locators) {
                printf("       Locator     State    Weight/Priority  Data In/Out\n");

                // Loop through the locators and print each
                while (loc_count < map_msg->num_locators) {
                    switch (tmp_loc->locator.afi) {
                    case AF_INET:
                        if ((formatted_rloc = (char *) inet_ntop(AF_INET,
                                                                 &(tmp_loc->locator.address.ip.s_addr),
                                                                 buf,
                                                                 sizeof(buf))) == NULL) {
                            perror("inet_ntop (rloc)");
                            exit(-1);
                        }
                        break;
                    case AF_INET6:
                        if ((formatted_rloc = (char *) inet_ntop(AF_INET6,
                                                                 tmp_loc->locator.address.ipv6.s6_addr,
                                                                 buf,
                                                                 sizeof(buf))) == NULL) {
                            perror("inet_ntop (rloc)");
                            exit(-1);
                        }
                        break;
                    default:
                        printf(" Unknown address family in locator");
                        tmp_loc++;
                        loc_count++;
                        continue;
                        break;
                    }

                    printf(" %15s ", formatted_rloc);
                    printf(" %5s ", tmp_loc->state ? "Up" : "Down");
                    printf("       %3d/%-3d ", tmp_loc->weight, tmp_loc->priority);
                    printf("        %5d/%-5d\n", tmp_loc->data_packets_in,
                           tmp_loc->data_packets_out);
                    tmp_loc++;
                    loc_count++;
                }
                printf("\n");
            }
            loc_count = 0;
            continue;
        } else {
            printf("Unexpected message type from kernel %d\n", cmd->type);
            break;
        }
    }
    return 0;
}

/*
 * process_list_responses
 *
 * Wait for, receive and process responses from the kernel
 * to the previous cache list request. A string of responses
 * to a request will be terminated by a LispOk message.
 *
 */
int process_list_responses(void)
{
    struct nlmsghdr *nlh = malloc(NLMSG_SPACE(MAX_MSG_LENGTH));
    lisp_cmd_t *cmd;
    lisp_cache_address_list_t *addr_list;
    int retval;
    int i;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    char *formatted_eid;
    char buf[256];

    iov.iov_base    = (void *)nlh;
    iov.iov_len     = MAX_MSG_LENGTH;
    msg.msg_name    = (void *)&(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    if (!nlh) {
        printf("Memory allocation failure\n");
        return -1;
    }

    while (1) {
        if ((retval = recvmsg(sock_fd, &msg, 0)) < 0) {
            perror("recvmsg");
            break;
        }
        cmd = NLMSG_DATA(nlh);
        addr_list = (lisp_cache_address_list_t *)cmd->val;
        if (cmd->type == LispOk) {

            printf("List complete.\n");
            break;
        }
        if ((cmd->type == LispMapCacheEIDList) ||
            (cmd->type == LispMapCacheRLOCList)) {
            printf("Contains: %d addresses\n", addr_list->count);

            for (i = 0; i < addr_list->count; i++) {
                switch (addr_list->addr_list[i].afi) {
                case AF_INET:
                    if ((formatted_eid = (char *)  inet_ntop(AF_INET,
                                                             &(addr_list->addr_list[i].address.ip.s_addr),
                                                             buf,
                                                             sizeof(buf))) == NULL) {
                        perror("inet_ntop (eid)");
                        exit(-1);
                    }
                    break;
                case AF_INET6:
                    if ((formatted_eid = (char *)  inet_ntop(AF_INET6,
                                                             addr_list->addr_list[i].address.ipv6.s6_addr,
                                                             buf,
                                                             sizeof(buf))) == NULL) {
                        perror("inet_ntop (eid)");
                        exit(-1);
                    }
                    break;
                default:
                    printf("Unknown AFI %d in address list entry", addr_list->addr_list[i].afi);
                    printf("First byte of address was %d", addr_list->addr_list[i].address.ip.s_addr);
                    break;
                }
                printf("%s\n", formatted_eid);
            }
        } else {
            printf("Unexpected message type from kernel %d\n", cmd->type);
            break;
        }
    }
    return 0;
}

/*
 * process_print_db_responses
 *
 * Wait for, receive and process responses from the kernel 
 * to the previous database lookup request. A string of responses
 * to a request will be terminated by a LispOk message.
 *
 */
int process_print_db_responses(void)
{
    struct nlmsghdr *nlh = malloc(NLMSG_SPACE(MAX_MSG_LENGTH));
    lisp_cmd_t *cmd;
    lisp_db_response_msg_t *map_msg;
    lisp_db_response_loc_t *tmp_loc;
    int retval;
    int loc_count = 0;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    char buf[256];
    char *formatted_eid = NULL;
    char *formatted_rloc = NULL;
    struct timeval uptime;

    iov.iov_base    = (void *)nlh;
    iov.iov_len     = MAX_MSG_LENGTH;
    msg.msg_name    = (void *)&(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    
    if (!nlh) {
        printf("Memory allocation failure\n");
        return -1;
    }

    printf("LISP IP Mapping Database\n\n");

    while (1) {
        if ((retval = recvmsg(sock_fd, &msg, 0)) < 0) {
            perror("recvmsg");
            break;
        }
        cmd = NLMSG_DATA(nlh);
        map_msg = (lisp_db_response_msg_t *) cmd->val;
        if (cmd->type == LispOk) {
            break;
        }
        if (cmd->type == LispDatabaseLookup) {
            switch (map_msg->eid_prefix.afi) {
            case AF_INET:
                if ((formatted_eid = (char *)  inet_ntop(AF_INET,
                                                         &(map_msg->eid_prefix.address.ip.s_addr),
                                                         buf,
                                                         sizeof(buf))) == NULL) {
                    perror("inet_ntop (eid)");
                    exit(-1);
                }
                break;
            case AF_INET6:
                if ((formatted_eid = (char *)  inet_ntop(AF_INET6,
                                                         map_msg->eid_prefix.address.ipv6.s6_addr,
                                                         buf,
                                                         sizeof(buf))) == NULL) {
                    perror("inet_ntop (eid)");
                    exit(-1);
                }
                break;
            default:
                printf("Unknown address family in response\n");
                continue;
                break;
            }

            printf("%s/%d, ", formatted_eid, map_msg->eid_prefix_length);

            tmp_loc = map_msg->locators;
            if (map_msg->num_locators) {
                printf("\n      Locator       Weight/Priority\n");

                // Loop through the locators and print each
                while (loc_count < map_msg->num_locators) {
                    switch (tmp_loc->locator.afi) {
                    case AF_INET:
                        if ((formatted_rloc = (char *) inet_ntop(AF_INET,
                                                                 &(tmp_loc->locator.address.ip.s_addr),
                                                                 buf,
                                                                 sizeof(buf))) == NULL) {
                            perror("inet_ntop (rloc)");
                            exit(-1);
                        }
                        break;
                    case AF_INET6:
                        if ((formatted_rloc = (char *) inet_ntop(AF_INET6,
                                                                 tmp_loc->locator.address.ipv6.s6_addr,
                                                                 buf,
                                                                 sizeof(buf))) == NULL) {
                            perror("inet_ntop (rloc)");
                            exit(-1);
                        }
                        break;
                    default:
                        printf(" Unknown address family in locator");
                        tmp_loc++; loc_count++;
                        continue;
                        break;
                    }

                    // Redo this with proper formatting XXX
                    printf(" %15s ", formatted_rloc);
                    printf("      %3d/%-3d\n", tmp_loc->weight, tmp_loc->priority);
                    tmp_loc++;
                    loc_count++;
                }
                printf("\n");
            }
            loc_count = 0;
            continue;
        } else {
            printf("Unexpected message type from kernel %d\n", cmd->type);
            break;
        }
    }
    return 0;
}

#define LISP_DCACHE_PATH_MAX 100
#define LISP_DCACHE_FILE "/data/data/com.le.lispmon/lispd_dcache"

int make_dsock_addr(const char *dsock_name, struct sockaddr_un *dsock_addr, socklen_t *dsock_len)
{
        int namelen = strlen(dsock_name);

        if ( namelen >= ( (int)sizeof(dsock_addr->sun_path) - 1 ) ) {
               printf("namelen greater than allowed");
                return -1;
        }

        strcpy(dsock_addr->sun_path, dsock_name);

        dsock_addr->sun_family = AF_LOCAL;
	*dsock_len = strlen(dsock_addr->sun_path) + sizeof(dsock_addr->sun_family);

        return 0;
}

/*
 * send_print_command
 *
 * Send a request to the kernel module to print the contents
 * of the static mapping table. If eidprefix is given, the search
 * will list all entries as and/or more specfic that match.
 */
int send_print_command(struct gengetopt_args_info *args_info)
{
    lisp_lookup_msg_t prt_msg;
    lisp_cmd_t        *cmd;
    int cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_lookup_msg_t);
    int retval;
    lisp_addr_t eid_prefix;
    int eid_prefix_len;
    int eid_af;
    char *token;
    int cache = true;

    struct sockaddr_un dsock_addr;
    socklen_t dsock_len;
    int dsock_fd, dclient_fd;
    int ret, msize=200;
    char msg[200], *tok;
 
    cmd = (lisp_cmd_t *)malloc(cmd_length);
    if (!cmd) {
        return -1;
    }

    if (args_info->filter_prefix_given) {
        /*
         * Parse the EID addr/prefix length first
         */

        /*
         * Detect address family
         */
        eid_af = detect_af(args_info->filter_prefix_arg);
        eid_prefix.afi = eid_af;
        token = strtok(args_info->filter_prefix_arg, "/");
        if (!token) {
            printf("Improper format for EID (x.x.x.x/p) or (xxxx:xxxx:xxxx:xxxx/p)\n");
            exit(1);
        }

        if (eid_af == AF_INET) {
            inet_pton(eid_af, token, &eid_prefix.address.ip);
            token = strtok(NULL, "/");

            if (!token) {
                eid_prefix_len = 0;
            } else {
                eid_prefix_len = atoi(token);
                if (eid_prefix_len > 32 || eid_prefix_len < 1) {
                    printf("Prefix length must be between 1 and 32\n");
                    exit(1);
                }
            }
    	} else { 
            inet_pton(eid_af, token, eid_prefix.address.ipv6.s6_addr);
            token = strtok(NULL, "/");
            if (!token) {
                eid_prefix_len = 0;
            } else {
                eid_prefix_len = atoi(token);
                if (eid_prefix_len > 128 || eid_prefix_len < 1) {
                    printf("Prefix length must be between 1 and 128\n");
                    exit(1);
                }
            }
        }
    }

    // Lookup in the cache or the database
    if (!strncmp(args_info->print_arg, "cache", strlen("cache"))) {
        cmd->type = LispMapCacheLookup;
        cache = true;
    }
    else if (!strncmp(args_info->print_arg, "dcache", strlen("dcache"))) {

        memset((char *)&dsock_addr, 0 ,sizeof(struct sockaddr_un));

        if ( make_dsock_addr(LISP_DCACHE_FILE, &dsock_addr, &dsock_len) < 0 ) {
                printf("make_dsock failed");
                return 0;
        }

        if ( (dsock_fd = socket(AF_UNIX, SOCK_STREAM, 0) ) < 0) {
                printf("socket creation failed %s", strerror(errno));
                return 0;
        }

	if ( connect(dsock_fd, (struct sockaddr *)&dsock_addr, dsock_len) < 0 ) {
		printf("connect call failed, %s", strerror(errno));
		return 0;	
	}

	if ( send(dsock_fd, "DCACHE", 10, 0) < 0 ) {
		printf("send call failed, %s", strerror(errno));
		return 0;
	}

	printf("LISP Data Cache \n\n");
	printf("Destination EID Prefix                      Nonce\n\n");
	do {
		if ( ret = recv(dsock_fd, msg, msize, 0) > 0 ) {
			tok = strtok(msg, "#");
			if ( tok ) printf("%s\/", tok);
			tok = strtok(NULL, "#");
			if ( tok ) printf("%s            ", tok);
			tok = strtok(NULL, "#");
			while( tok != NULL ) {
				printf("%s          ", tok);
				tok = strtok(NULL, "#");
			}
			printf("\n");
		}
		else if ( ret < 0) {
			printf("recv error!");
		}
		else {
			//printf("Data receiving done!");
			;
		}
		
	}while (ret > 0);

	close(dsock_fd);
 
	return 0;
    }
    else if (!strncmp(args_info->print_arg, "ccache", strlen("ccache"))) {

        memset((char *)&dsock_addr, 0 ,sizeof(struct sockaddr_un));

        if ( make_dsock_addr(LISP_DCACHE_FILE, &dsock_addr, &dsock_len) < 0 ) {
                printf("make_dsock failed");
                return 0;
        }

        if ( (dsock_fd = socket(AF_UNIX, SOCK_STREAM, 0) ) < 0) {
                printf("socket creation failed %s", strerror(errno));
                return 0;
        }

	if ( connect(dsock_fd, (struct sockaddr *)&dsock_addr, dsock_len) < 0 ) {
		printf("connect call failed, %s", strerror(errno));
		return 0;	
	}

	if ( send(dsock_fd, "CCACHE", 10, 0) < 0 ) {
		printf("send call failed, %s", strerror(errno));
		return 0;
	}
	
	printf("LISP IP Map Cache cleared!");

	close(dsock_fd);
		
	return 0;
    }
    else {

        cmd->type = LispDatabaseLookup;
        cache = false;
    }

    cmd->length = sizeof(lisp_lookup_msg_t);
    memset((char *)&prt_msg, 0, sizeof(lisp_lookup_msg_t));
    if (!args_info->filter_prefix_given) {
        prt_msg.all_entries = 1;
        prt_msg.exact_match = 0;
    } else {
        prt_msg.all_entries = 0;
        prt_msg.exact_match = 0;
        memcpy(&prt_msg.prefix, &eid_prefix, sizeof(lisp_addr_t));
        prt_msg.prefix_length = eid_prefix_len;
    }
    memcpy(cmd->val, (char *)&prt_msg, sizeof(lisp_lookup_msg_t));

    retval = send_command(cmd, cmd_length);
    
    if (cache) {
        process_print_cache_responses();
    } else {
        process_print_db_responses();
    }
    return retval;
}

/*
 * send_list_command
 *
 * Send a request to the kernel module to print the contents
 * of the static mapping table, only including the prefixes or rlocs.
 * This is primarily for testing the kernel interfaces, not for
 * user debug.
 */
int send_list_command(struct gengetopt_args_info *args_info)
{
    lisp_cmd_t        *cmd;
    int cmd_length = sizeof(lisp_cmd_t);
    int retval;

    cmd = (lisp_cmd_t *)malloc(cmd_length);
    if (!cmd) {
        return -1;
    }

    // List EIDs or RLOCs
    if (!strncmp(args_info->list_arg, "eids", strlen("eids"))) {
        printf("Current map cache EIDs:\n");
        cmd->type = LispMapCacheEIDList;
    } else {
        printf("Current map cache RLOCs:\n");
        cmd->type = LispMapCacheRLOCList;
    }
    cmd->length = 0;

    retval = send_command(cmd, cmd_length);

    process_list_responses();
    return retval;
}

int set_rloc_interface(struct gengetopt_args_info *args_info)
{
    int s;
    struct ifreq ifr;
    lisp_set_rloc_msg_t *rloc_msg;
    lisp_cmd_t          *cmd;
    int cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_set_rloc_msg_t);
    int retval;

    /*
     * Look up the given inteface in the kernel and get the ip address
     */
    s = socket(AF_INET, SOCK_DGRAM, 0);

    /*
     * IPV4 for now XXX
     */
    ifr.ifr_addr.sa_family = AF_INET;

    /*
     * Pass in the device string
     */
    strncpy(ifr.ifr_name, args_info->interface_arg, IFNAMSIZ - 1);
    retval = ioctl(s, SIOCGIFADDR, &ifr);
    close(s);

    if (retval != 0) {
        printf("Failed to find active interface %s\n", ifr.ifr_name);
        return -1;
    }

    cmd = (lisp_cmd_t *)malloc(cmd_length);
    if (!cmd) {
        return -1;
    }

    cmd->type = LispSetRLOC;
    cmd->length = sizeof(lisp_set_rloc_msg_t);
    memset((char *)&rloc_msg, 0, sizeof(lisp_set_rloc_msg_t));
    rloc_msg = (lisp_set_rloc_msg_t *)cmd->val;
    rloc_msg->addr.address.ip.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    retval = send_command(cmd, cmd_length + sizeof(lisp_cmd_t));

    return retval;
}

int detect_af(char *str)
{
    if (!strstr(str,":")) {
        return AF_INET;
    }
    return AF_INET6;
}

void add_entry(struct gengetopt_args_info *args_info)
{
    char *token;
    struct in_addr  eid4;
    struct in6_addr eid6;
    lisp_addr_t     eid;
    int plen;
    struct in_addr  rloc4;
    struct in6_addr rloc6;
    lisp_addr_t rloc;
    uint32_t priority;
    uint32_t weight;
    uint32_t ttl;
    int      eid_af, rloc_af;

    /*
     * Parse the EID addr/prefix length first
     */
    
    /*
     * Detect address family
     */
    eid_af = detect_af(args_info->eid_arg);

    token = strtok(args_info->eid_arg, "/");
    if (!token) {
        printf("Improper format for EID (x.x.x.x/p) or (xxxx:xxxx:xxxx:xxxx/p)\n");
        exit(1);
    }

    if (eid_af == AF_INET) {
        inet_pton(eid_af, token, &eid4);
        token = strtok(NULL, "/");
        plen = atoi(token);
        if (plen > 32 || plen < 1) {
            printf("Prefix length must be between 1 and 32\n");
            exit(1);
        }
    } else {
        inet_pton(eid_af, token, &eid6);
        token = strtok(NULL, "/");
        plen = atoi(token);
        if (plen > 128 || plen < 1) {
            printf("Prefix length must be between 1 and 128\n");
            exit(1);
        }
    }

    rloc_af = detect_af(args_info->rloc_arg);
    if (rloc_af == AF_INET) {
        inet_pton(rloc_af, args_info->rloc_arg, &rloc4);
        rloc.address.ip.s_addr = rloc4.s_addr;
    } else {
        inet_pton(rloc_af, args_info->rloc_arg, &rloc6);
        // Investigate: couldn't get memcpy to work without crashing
        // elsewhere. XXX
        rloc.address.ipv6.s6_addr32[0] = rloc6.s6_addr32[0];
        rloc.address.ipv6.s6_addr32[1] = rloc6.s6_addr32[1];
        rloc.address.ipv6.s6_addr32[2] = rloc6.s6_addr32[2];
        rloc.address.ipv6.s6_addr32[3] = rloc6.s6_addr32[3];
    }

    // Range check these xxx
    priority = args_info->priority_arg;
    weight   = args_info->weight_arg;
    ttl      = args_info->ttl_arg;

    /*
     * Cache or database
     */
    if (!strncmp(args_info->add_entry_arg, "cache", strlen("cache"))) {
        if (eid_af == AF_INET) {
            //send_map_cache_msg_v4(eid4.s_addr, plen, rloc, rloc_af, priority,
            //                      weight, ttl);
        } else {
            // send_map_cache_msg_v6(eid6, plen, rloc, rloc_af, priority,
            //                      weight, ttl);
        }
    } else {
        if (eid_af == AF_INET) {
          //  send_map_db_msg_v4(eid4.s_addr, plen, rloc, rloc_af, priority,
          //                     weight);
        } else {
          //  send_map_db_msg_v6(eid6, plen, rloc, rloc_af, priority, weight);
        }
    }
}

int main(int argc, char **argv) 
{

    struct gengetopt_args_info args_info;

    int i;

    /*
     * Parse command line options
     */
    if (cmdline_parser(argc, argv, &args_info) != 0) {
        exit(1);
    }
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = getpid();  /* self pid */
    src_addr.nl_groups = 0;  /* not in mcast groups */

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid    = 0;   /* For Linux Kernel */
    dst_addr.nl_groups = 0; /* unicast */

    /*
     * Connect to the kernel module
     */
    if ((sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_LISP)) < 0) {
        perror("socket");
        exit(-1);
    }
    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind: ");
        exit(-1);
    }

    if (args_info.add_entry_given) {
        add_entry(&args_info);
        exit(0);
    }

    if (args_info.print_given) {
        send_print_command(&args_info);
        exit(0);
    }

    if (args_info.interface_given) {
        set_rloc_interface(&args_info);
        exit(0);
    }

    if (args_info.list_given) {
        send_list_command(&args_info);
        exit(0);
    }
    return 0;
}
