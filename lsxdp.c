/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#include "lsxdp.h"

#include "libbpf/src/bpf.h"
#include "poll.h"
#include <linux/if_ether.h>
#include "linux/in.h"
#include "linux/icmp.h"

#define TRACE_BUFFER_PRINTF
#include "traceBuffer.h"

#define DEBUG_MESSAGE(...) printf(__VA_ARGS__)

static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | // Does a force if not set */
                           /*XDP_FLAGS_SKB_MODE | // Generic or emulated (slow)*/
                           /*XDP_FLAGS_DRV_MODE | // Native XDP mode*/
                           /* XDP_FLAGS_HW_MODE |   // Hardware offload*/
                           0;
static __u16 opt_xdp_bind_flags = /* XDP_SHARED_UMEM | //? */
                                  /* XDP_COPY | // Force copy mode */
                                  /* XDP_ZEROCOPY | // Force zero copy */
                                  0;/*XDP_USE_NEED_WAKEUP;// For same cpu for force yield*/

static int xsk_configure_umem(void *buffer, xdp_socket_t *sock, u64 size)
{
	struct xsk_umem_config cfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = sock->m_xdp_prog->m_max_frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	};
	int ret;

	sock->m_umem = calloc(1, sizeof(*sock->m_umem));
	if (!sock->m_umem)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "calloc of %ld bytes error: %s", sizeof(*sock->m_umem),
                 strerror(errno));
        return -1;
    }

	ret = xsk_umem__create(&sock->m_umem->umem, buffer, size, &sock->m_umem->fq,
                           &sock->m_umem->cq, &cfg);
	if (ret)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xsk_umem__create error %s, size: %llu, max_frame_size: %d",
                 strerror(-ret), size, sock->m_xdp_prog->m_max_frame_size);
        return -1;
    }
	sock->m_umem->buffer = buffer;
	return 0;
}

static int xsk_configure_socket(xdp_socket_t *sock)
{
	struct xsk_socket_config cfg;
	int ret;
	int ifindex = sock->m_reqs->m_ifindex;

	sock->m_sock_info = calloc(1, sizeof(*sock->m_sock_info));
	if (!sock->m_sock_info)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Insufficient memory in calloc of sock_info: %s",
                 strerror(errno));
        return -1;
    }
    sock->m_sock_info->umem = sock->m_umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;
	ret = xsk_socket__create(&sock->m_sock_info->xsk,
                             sock->m_xdp_prog->m_if[ifindex].m_ifname,
                             sock->m_queue, sock->m_umem->umem,
                             &sock->m_sock_info->rx, &sock->m_sock_info->tx, &cfg);
	if (ret)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xsk_socket__create error %s index: %d name: %s", strerror(-ret),
                 ifindex, sock->m_xdp_prog->m_if[ifindex].m_ifname);
        return -1;
    }
    sock->m_xdp_prog->m_if[ifindex].m_socket_attached = 1;
	ret = bpf_get_link_xdp_id(ifindex, &sock->m_progid,
                              opt_xdp_flags);
    DEBUG_MESSAGE("After xsk_socket__create (ret: %d), xdp_id prog: %d\n", ret,
                  sock->m_progid);
	if (ret)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "bpf_get_link_xdp_id error %s", strerror(-ret));
		return -1;
    }
    /*
	ret = xsk_ring_prod__reserve(&sock->m_umem->fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xsk_ring_prod__reserve error %s", strerror(-ret));
		return -1;
    }
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&sock->m_sock_info->umem->fq, idx++) =
			i * sock->m_xdp_prog->m_max_frame_size;
	xsk_ring_prod__submit(&sock->m_umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	*/
	return 0;
}

static int get_ifs(char *prog_init_err, int prog_init_err_len, xdp_prog_t *prog)
{
    struct if_nameindex *names;
    int index = 0;
    int ret = 0;
    names = if_nameindex();
    if (!names)
    {
        snprintf(prog_init_err, prog_init_err_len, "if_nameindex error: %s",
                 strerror(errno));
        return -1;
    }
    while (names[index].if_index)
    {
        if (names[index].if_index >= MAX_IF)
        {
            snprintf(prog_init_err, prog_init_err_len,
                     "Too many interfaces for the program to process (max %d)",
                     MAX_IF - 1);
            ret = -1;
            break;
        }
        strncpy(prog->m_if[names[index].if_index].m_ifname, names[index].if_name,
                sizeof(prog->m_if[names[index].if_index].m_ifname));
        if (names[index].if_index > prog->m_max_if)
            prog->m_max_if = names[index].if_index;
        if (!strcmp(prog->m_if[names[index].if_index].m_ifname, "lo"))
            prog->m_if[names[index].if_index].m_disable = 1;
        DEBUG_MESSAGE("Interface #%d, idx: %d, max: %d: %s %s\n", index,
                      names[index].if_index, prog->m_max_if,
                      prog->m_if[names[index].if_index].m_ifname,
                      prog->m_if[names[index].if_index].m_disable ? "DISABLE":"");
        ++index;
    }
    if_freenameindex(names);
    return ret;
}

xdp_prog_t *xdp_prog_init(char *prog_init_err, int prog_init_err_len,
                          int max_frame_size)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int ret;
    xdp_prog_t *prog;

    if (setrlimit(RLIMIT_MEMLOCK, &r)) 
    {
        snprintf(prog_init_err, prog_init_err_len, "setrlimit(RLIMIT_MEMLOCK) \"%s\"",
                 strerror(errno));
        return NULL;
    }
    prog = malloc(sizeof(xdp_prog_t));
    if (!prog)
    {
        snprintf(prog_init_err, prog_init_err_len, "Insufficient memory");
        return NULL;
    }
    memset(prog, 0, sizeof(*prog));
    if (max_frame_size <= 2048)
        max_frame_size = 2048;
    else
        max_frame_size = 4096;
    prog->m_max_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
    if (get_ifs(prog_init_err, prog_init_err_len, prog))
    {
        xdp_prog_done(prog, 0, 0);
        return NULL;
    }
    if (prog->m_max_frame_size <= 0 ||
        prog->m_max_frame_size > LSXDP_MAX_FRAME_SIZE)
    {
        snprintf(prog_init_err, prog_init_err_len,
                 "Invalid max frame size must be <= %d", LSXDP_MAX_FRAME_SIZE);
        xdp_prog_done(prog, 0, 0);
        return NULL;
    }
	ret = posix_memalign(&prog->m_bufs, getpagesize(), /* PAGE_SIZE aligned */
			             NUM_FRAMES * prog->m_max_frame_size);
    if (ret)
    {
        snprintf(prog_init_err, prog_init_err_len,
                 "Insufficient memory allocating big buffer: %s", strerror(errno));
        xdp_prog_done(prog, 0, 0);
        return NULL;
    }
    DEBUG_MESSAGE("prog_init, %d bytes\n", NUM_FRAMES * prog->m_max_frame_size);
    return prog;
}

void xdp_socket_close ( xdp_socket_t* socket )
{
    DEBUG_MESSAGE("xdp_socket_close: %p\n", socket);
    if (!socket)
        return;
    if (socket->m_sock_info)
    {
        if (socket->m_sock_info->xsk)
        {
            DEBUG_MESSAGE("Doing xsk_socket__delete\n");
            xsk_socket__delete(socket->m_sock_info->xsk);
        }
        DEBUG_MESSAGE("free sock_info\n");
        free(socket->m_sock_info);
    }
    if (socket->m_umem)
    {
        if (socket->m_umem->umem)
        {
            DEBUG_MESSAGE("Doing xdk_umem__delete\n");
            xsk_umem__delete(socket->m_umem->umem); //
        }
        DEBUG_MESSAGE("Doing free of umem\n");
        free(socket->m_umem);
    }
    DEBUG_MESSAGE("freeing socket\n");
    socket->m_xdp_prog->m_num_socks--;
    free(socket);
}

static void detach_ping(xdp_prog_t *prog, int force_unload)
{
    int i;
    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (prog->m_if[i].m_ping_attached || prog->m_if[i].m_socket_attached ||
            force_unload)
        {
            prog->m_if[i].m_ping_attached = 0;
            int rc = xdp_link_detach(prog, i, opt_xdp_flags,
                                     0/*prog->m_if[i].m_progfd*/);
            if (rc)
                DEBUG_MESSAGE("xdp_link_detach failed: %s\n", prog->m_err);
            else
                DEBUG_MESSAGE("xdp_link_detach worked\n");
        }
    }
}

static int xsk_load_kern(xdp_socket_t *sock)
{
	struct bpf_program *bpf_prog;
    int ifindex = sock->m_reqs->m_ifindex;
    if (!sock->m_xdp_prog->m_if[ifindex].m_socket_attached)
    {
        int err;
        struct bpf_prog_load_attr prog_load_attr =
        {
            .prog_type = BPF_PROG_TYPE_XDP,
            .ifindex   = (opt_xdp_flags & XDP_FLAGS_HW_MODE) ? ifindex : 0,
        };
        prog_load_attr.file = "xdpsock_kern.o";
        sock->m_xdp_prog->m_if[ifindex].m_bpf_prog_fd = -1;
        err = bpf_prog_load_xattr(&prog_load_attr,
                                  &sock->m_xdp_prog->m_if[ifindex].m_bpf_object,
                                  &sock->m_xdp_prog->m_if[ifindex].m_bpf_prog_fd);
        if (err)
        {
            snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Error loading kernel object file(%s) (%d): %s",
                     prog_load_attr.file, err, strerror(-err));
            return -1;
        }
        // Find a matching BPF prog section name
        const char *prog_sec = "xdp_sock";
        DEBUG_MESSAGE("Kernel bpf_object__find_program_by_title: %s, "
                      "obj ptr: %p, prog_fd: %d, index: %d\n",
                      prog_sec, sock->m_xdp_prog->m_if[ifindex].m_bpf_object,
                      sock->m_xdp_prog->m_if[ifindex].m_bpf_prog_fd, ifindex);
        bpf_prog = bpf_object__find_program_by_title(sock->m_xdp_prog->m_if[ifindex].m_bpf_object,
                                                     prog_sec);
        if (!bpf_prog)
        {
            snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Kernel load error finding progsec: %s\n", prog_sec);
            return -1;
	    }
        sock->m_xdp_prog->m_if[ifindex].m_progfd = bpf_program__fd(bpf_prog);
        if (sock->m_xdp_prog->m_if[ifindex].m_progfd <= 0)
        {
            snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Kernel load error bpf_program__fd failed");
            return -1;
	    }
        DEBUG_MESSAGE("bpf_program__fd using prog ptr: %p progfd: %d\n",
                      bpf_prog, sock->m_xdp_prog->m_if[ifindex].m_progfd);
        int ret = bpf_set_link_xdp_fd(ifindex,
                                      sock->m_xdp_prog->m_if[ifindex].m_progfd,
                                      opt_xdp_flags);
        if (ret < 0)
        {
            snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Kernel load error bpf_set_link_xdp_id: %s", strerror(-ret));
            return -1;
	    }
    }
    return 0;
}

xdp_socket_t *xdp_socket(xdp_prog_t *prog, lsxdp_socket_reqs_t *reqs, int port)
{
    xdp_socket_t *socket;

    detach_ping(prog, 0); // Incompatible with sockets
    socket = malloc(sizeof(xdp_socket_t));
    if (!socket)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Insufficient memory to allocate socket structure");
        return NULL;
    }
    memset(socket, 0, sizeof(xdp_socket_t));
    socket->m_xdp_prog = prog;
    socket->m_reqs = reqs;
    socket->m_reqs->m_port = port;
    prog->m_num_socks++;
	if (xsk_configure_umem(prog->m_bufs, socket,
                           NUM_FRAMES * prog->m_max_frame_size))
    {
        xdp_socket_close(socket);
        return NULL;
    }
    if (xsk_load_kern(socket))
    {
        xdp_socket_close(socket);
        return NULL;
    }
	if (xsk_configure_socket(socket))
    {
        xdp_socket_close(socket);
        return NULL;
    }
    prog->m_xsks[prog->m_num_socks - 1] = socket;
    return socket;
}

static int load_obj(xdp_prog_t *prog, const char *ifport)
{
	int err;
	struct bpf_program *bpf_prog;
    int i;
    int enabled_one = 0;

    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (!prog->m_if[i].m_ifname[0] || (!ifport && prog->m_if[i].m_disable))
            continue;
        if (ifport && strcmp(ifport, prog->m_if[i].m_ifname))
        {
            DEBUG_MESSAGE("ifport specified and %s does not match, disabling\n",
                          prog->m_if[i].m_ifname);
            prog->m_if[i].m_disable = 1;
            continue;
        }
        else if (ifport)
            prog->m_if[i].m_disable = 0;
        if (prog->m_if[i].m_bpf_object)
            return 0; // Already done!
        DEBUG_MESSAGE("For prog[%d], if: %d, name: %s\n", i,
                      if_nametoindex(prog->m_if[i].m_ifname),
                      prog->m_if[i].m_ifname);
        struct bpf_prog_load_attr prog_load_attr =
        {
            .prog_type = BPF_PROG_TYPE_XDP,
            .ifindex   = (opt_xdp_flags & XDP_FLAGS_HW_MODE) ? i : 0,
        };
        prog_load_attr.file = "xdpsock_kern.o";

        /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
         * loading this into the kernel via bpf-syscall */
        DEBUG_MESSAGE("bpf_prog_load_xattr, ifindex: %d\n", prog_load_attr.ifindex);
        prog->m_if[i].m_bpf_object = NULL;
        prog->m_if[i].m_bpf_prog_fd = -1;
        err = bpf_prog_load_xattr(&prog_load_attr, &prog->m_if[i].m_bpf_object,
                                  &prog->m_if[i].m_bpf_prog_fd);
        if (err)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Error loading BPF-OBJ file(%s) (%d): %s",
                     prog_load_attr.file, err, strerror(-err));
            prog->m_if[i].m_disable = 1;
            continue;
        }
        /* Find a matching BPF prog section name */
        const char *prog_sec = "xdp_ping";
        DEBUG_MESSAGE("bpf_object__find_program_by_title: %s, obj ptr: %p, prog_fd: %d\n",
                      prog_sec, prog->m_if[i].m_bpf_object, prog->m_if[i].m_bpf_prog_fd);
        bpf_prog = bpf_object__find_program_by_title(prog->m_if[i].m_bpf_object,
                                                     prog_sec);
        if (!bpf_prog)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "ERR: finding progsec: %s\n", prog_sec);
            prog->m_if[i].m_disable = 1;
		    continue;
	    }
        DEBUG_MESSAGE("bpf_program__fd using prog ptr: %p\n", bpf_prog);
        prog->m_if[i].m_progfd = bpf_program__fd(bpf_prog);
        if (prog->m_if[i].m_progfd <= 0)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "ERR: bpf_program__fd failed");
            prog->m_if[i].m_disable = 1;
            continue;
	    }

        DEBUG_MESSAGE("xdp_link_attach, if_index: %d %s, new prog_fd: %d\n", i,
                      prog->m_if[i].m_ifname, prog->m_if[i].m_progfd);
        err = xdp_link_attach(prog, i, opt_xdp_flags, prog->m_if[i].m_progfd);
        if (err)
        {
            prog->m_if[i].m_disable = 1;
            continue;
        }
        prog->m_if[i].m_ping_attached = 1;
        enabled_one = 1;
    }
    if (!enabled_one)
        // let the last error stand!
        return -1;
    return 0;
}

static unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

static int send_connect(xdp_prog_t *prog, const struct sockaddr *addr,
                        socklen_t addrLen, const struct sockaddr *addr_bind)
{
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Error creating socket to get socket requirements: %s",
                 strerror(errno));
        return -1;
    }
    if (addr_bind)
    {
        DEBUG_MESSAGE("Doing bind\n");
        if (bind(sockfd, addr_bind, addrLen) < 0)
            DEBUG_MESSAGE("BIND FAILED: %s, but continue anyway\n",
                          strerror(errno));
    }
    DEBUG_MESSAGE("Doing connect\n");
    if (connect(sockfd, addr, addrLen) < 0)
        DEBUG_MESSAGE("connect failed: %s, but not necessarily bad\n",
                      strerror(errno));
    else
        DEBUG_MESSAGE("connect worked\n");
    close(sockfd);
    return 0;
}

int find_map_fd(xdp_prog_t *prog, struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);
    if (!map)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Can not find map by name: %s", mapname);
        return -1;
    }

	return bpf_map__fd(map);
}

static int set_map(xdp_prog_t *prog, const struct sockaddr *addr,
                   socklen_t addrLen)
{
    int i;
    struct packet_rec rec;
    lsxdp_socket_reqs_t *reqs;
    int found = 0;
    memset(&rec, 0, sizeof(rec));
    rec.m_addr_set = 1;
    if (addrLen == sizeof(struct sockaddr_in))
    {
        rec.m_addr_set  = 1;
        rec.m_ip4       = 1;
        rec.m_addr.in6_u.u6_addr32[0] = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
        rec.m_port      = ((struct sockaddr_in *)addr)->sin_port;
    }
    else
    {
        DEBUG_MESSAGE("Not supporting IP6 yet\n");
        return -1;
    }
    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (!prog->m_if[i].m_disable &&
            prog->m_if[i].m_bpf_object)
        {
            int map_fd;
            int key = 0; // Separate maps for each IF for now, all with key 0
            map_fd = find_map_fd(prog, prog->m_if[i].m_bpf_object,
                                 "packet_rec_def");
            if (map_fd == -1)
            {
                DEBUG_MESSAGE("Can't find map fd\n");
                return -1;
            }

            if (bpf_map_update_elem(map_fd, &key, &rec, 0) == 0)
                found = 1;
            else
                DEBUG_MESSAGE("ERROR IN BPF_MAP_UPDATE_ELEM %d\n", errno);
        }
    }
    if (!found)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Can not find map to set update");
        return -1;
    }
    return 0;
}

static lsxdp_socket_reqs_t *check_map(xdp_prog_t *prog,
                                      const struct sockaddr *addr,
                                      socklen_t addrLen)
{
    int i;
    struct packet_rec rec;
    int found_index = 0;
    lsxdp_socket_reqs_t *reqs;

    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (!prog->m_if[i].m_disable &&
            prog->m_if[i].m_bpf_object)
        {
            int map_fd;
            int key = 0; // Separate maps for each IF for now, all with key 0
            map_fd = find_map_fd(prog, prog->m_if[i].m_bpf_object,
                                 "packet_rec_def");
            if (map_fd == -1)
                return NULL;
            int rc = bpf_map_lookup_elem(map_fd, &key, &rec);
            if ((rc == 0 && rec.m_ip4 &&
                ((struct iphdr *)&rec.m_header[rec.m_ip_index])->daddr == ((struct sockaddr_in *)addr)->sin_addr.s_addr))
            {
                DEBUG_MESSAGE("Found index at device #%d %s\n", i,
                              prog->m_if[i].m_ifname);
                found_index = i;
                break;
            }
            else if (rc != 0)
                DEBUG_MESSAGE("bpf_map_lookup_elem failed: %d\n", errno);
            else if (rec.m_ip4)
                DEBUG_MESSAGE("Unexpected IP daddr: %u.%u.%u.%u\n",
                              ((unsigned char *)&((struct iphdr *)&rec.m_header[rec.m_ip_index])->daddr)[0],
                              ((unsigned char *)&((struct iphdr *)&rec.m_header[rec.m_ip_index])->daddr)[1],
                              ((unsigned char *)&((struct iphdr *)&rec.m_header[rec.m_ip_index])->daddr)[2],
                              ((unsigned char *)&((struct iphdr *)&rec.m_header[rec.m_ip_index])->daddr)[3]);
            else
                DEBUG_MESSAGE("NOT IP 4!\n");

        }
    }
    if (!found_index)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Can not find map entry of successful connect");
        return NULL;
    }
    reqs = malloc(sizeof(lsxdp_socket_reqs_t));
    if (!reqs)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Insufficient memory to allocate required data");
        return NULL;
    }
    reqs->m_ifindex = found_index;
    reqs->m_port = ((struct sockaddr_in *)addr)->sin_port;
    memcpy(&reqs->m_rec, &rec, sizeof(rec));
    return reqs;
}

lsxdp_socket_reqs_t *xdp_get_socket_reqs(xdp_prog_t *prog,
                                         const struct sockaddr *addr,
                                         socklen_t addrLen,
                                         const struct sockaddr *addr_bind,
                                         const char *ifport)
{
    lsxdp_socket_reqs_t *reqs;

    DEBUG_MESSAGE("xdp_get_socket_reqs - load_obj\n");
    if (load_obj(prog, ifport))
        return NULL;
    DEBUG_MESSAGE("xdp_get_socket_reqs - set_map\n");
    if (set_map(prog, addr, addrLen) == -1)
        return NULL;
    DEBUG_MESSAGE("xdp_get_socket_reqs - send_tcp\n");
    if (send_connect(prog, addr, addrLen, addr_bind))
        return NULL;
    DEBUG_MESSAGE("xdp_get_socket_reqs - check_map\n");
    reqs = check_map(prog, addr, addrLen);
    if (!reqs)
        return NULL;
    DEBUG_MESSAGE("xdp_get_socket_reqs - WORKED! header size %d "
                  "source mac: %02x:%02x:%02x:%02x:%02x:%02x "
                  "dest mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                  reqs->m_rec.m_header_size,
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_source[0],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_source[1],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_source[2],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_source[3],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_source[4],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_source[5],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_dest[0],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_dest[1],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_dest[2],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_dest[3],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_dest[4],
                  ((struct ethhdr *)reqs->m_rec.m_header)->h_dest[5]);
    return reqs;
}

void xdp_prog_done ( xdp_prog_t* prog, int unload, int force_unload )
{
    if (!prog)
        return;
    if (unload)
        detach_ping(prog, force_unload);
    if (prog->m_num_socks)
        fprintf(stderr, "%d Sockets remain open!\n", prog->m_num_socks);
    if (prog->m_bufs)
        free(prog->m_bufs);
    free(prog);
}

int xdp_get_poll_fd(xdp_socket_t *sock)
{
    return xsk_socket__fd(sock->m_sock_info->xsk);
}

static int get_index_from_buffer(xdp_socket_t *sock, void *buffer)
{
    /* Given a buffer location, return the index */
    return (int)(((char *)buffer - (char *)sock->m_umem->buffer) / sock->m_xdp_prog->m_max_frame_size);
}

static int kick_tx(xdp_socket_t *sock)
{
	int ret;

	ret = sendto(xsk_socket__fd(sock->m_sock_info->xsk), NULL, 0, MSG_DONTWAIT,
                 NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
    {
        DEBUG_MESSAGE("sendto returned %d, errno: %d\n", ret, errno);
		return 0;
    }
    snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
             "Error in send: %s", strerror(errno));
    return -1;
}

static inline int complete_tx_only(xdp_socket_t *sock)
{
	unsigned int rcvd;
	u32 idx;

	if (!sock->m_sock_info->outstanding_tx)
    {
        DEBUG_MESSAGE("complete_tx_only - leave early no packets to send\n");
		return 0;
    }
    if (kick_tx(sock))
        return -1;

    rcvd = xsk_ring_cons__peek(&sock->m_umem->cq, 1, &idx);
    if (rcvd > 0)
    {
        xsk_ring_cons__release(&sock->m_umem->cq, rcvd);
        DEBUG_MESSAGE("Completion queue has %d, idx: %d\n", rcvd, idx);
        sock->m_sock_info->outstanding_tx -= rcvd;
        sock->m_sock_info->tx_npkts += rcvd;
    }
    else
        DEBUG_MESSAGE("Completion queue Empty\n");

	return 0;
}

static int tx_only(xdp_socket_t *sock, void *buffer, int len, int last)
{
    struct xdp_desc *desc;
    u32 idx;
    int ret;
    ret = xsk_ring_prod__reserve(&sock->m_sock_info->tx, 1, &idx);
    if (ret != 1)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Can't reserve a single packet (%d)", ret);
        return -1;
    }
    desc = xsk_ring_prod__tx_desc(&sock->m_sock_info->tx, idx);
    traceBuffer(buffer, len);
    desc->addr = get_index_from_buffer(sock, buffer) * sock->m_xdp_prog->m_max_frame_size;
    desc->len = len;

	xsk_ring_prod__submit(&sock->m_sock_info->tx, 1);
    sock->m_sock_info->outstanding_tx += 1;
    if (last && complete_tx_only(sock))
        return -1;
    return 0;
}

void *xdp_get_send_buffer(xdp_socket_t *sock)
{
    /* The key is the number of outstanding_tx packets.  If it's >=
     * NUM_FRAMES, we need to kick the sender to get them out. */
    int prod_reserve;
    u32 index;
    void *buffer;
    if (sock->m_sock_info->outstanding_tx >= NUM_FRAMES * sock->m_xdp_prog->m_max_frame_size &&
        complete_tx_only(sock))
        return NULL; // Error already in buffer
    if (sock->m_sock_info->outstanding_tx >= NUM_FRAMES * sock->m_xdp_prog->m_max_frame_size)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "All packets still outstanding.  Do a poll first");
        return NULL;
    }
	prod_reserve = xsk_ring_prod__reserve(&sock->m_umem->fq, 1, &index);
    DEBUG_MESSAGE("last_tx_index_gotten: %d, prod_reserve: %d\n",
                  index, prod_reserve);
    if (prod_reserve == 1)
        buffer = xsk_umem__get_data(sock->m_umem->buffer,
                                    index * sock->m_xdp_prog->m_max_frame_size);
    else
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Unable to reserve a packet for a full frame size.  Poll?");
        return NULL;
    }
    memcpy(buffer, sock->m_reqs->m_rec.m_header, xdp_send_udp_headroom(sock));
    return (void *)((char *)buffer + xdp_send_udp_headroom(sock));
}

int xdp_send(xdp_socket_t *sock, void *data, int len, int last)
{
    int headroom = xdp_send_udp_headroom(sock);
    char *send_buffer;
    char *data_char = data;

    if (data_char > (char *)sock->m_umem->buffer &&
        data_char < (char *)sock->m_umem->buffer + sock->m_xdp_prog->m_max_frame_size * NUM_FRAMES)
    {
        DEBUG_MESSAGE("Data in buffer range - assume it was gotten correctly\n");
        send_buffer = data_char - headroom;
    }
    else
    {
        DEBUG_MESSAGE("xdp_send, NOT zero copy, copy in the data\n");
        send_buffer = xdp_get_send_buffer(sock);
        if (!send_buffer)
            return -1;
        memcpy(send_buffer + headroom, data, len);
    }
    return xdp_send_zc(sock, send_buffer, len, last);
}

int xdp_send_zc(xdp_socket_t *sock, void *buffer, int len, int last)
{
    int ip_index;
    struct udphdr *udphdr;
    char *buffer_char = buffer;
    int headroom = xdp_send_udp_headroom(sock);
    if (buffer_char >= (char *)sock->m_umem->buffer &&
        buffer_char < (char *)sock->m_umem->buffer + sock->m_xdp_prog->m_max_frame_size * NUM_FRAMES &&
        (unsigned long)buffer_char % sock->m_xdp_prog->m_max_frame_size == 0)
        DEBUG_MESSAGE("Buffer in range - assume it was gotten correctly\n");
    else
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Require that the packet be acquired with a xdp_get_send_buffer()"
                 " or a call to xdp_send()");
        return -1;
    }
    ip_index = sock->m_reqs->m_rec.m_ip_index;
    if (sock->m_reqs->m_rec.m_ip4)
    {
        struct iphdr *iphdr = (struct iphdr *)&buffer_char[ip_index];
        DEBUG_MESSAGE("ip_index begins at %d\n", ip_index);
        iphdr->ihl = 5;
        iphdr->tot_len = __constant_htons(20 + sizeof(struct udphdr) + len);
        iphdr->ttl = 20;
        iphdr->protocol = 17; // UDP
        iphdr->check = 0;
        iphdr->check = checksum(iphdr, sizeof(struct iphdr));
        udphdr = (struct udphdr *)(iphdr + 1);
    }
    else
    {
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)&((char *)buffer)[ip_index];
        ipv6hdr->payload_len = __constant_htons(sizeof(struct udphdr) + len);
        ipv6hdr->nexthdr = 17; // UDP
        ipv6hdr->hop_limit = 20;
        udphdr = (struct udphdr *)(ipv6hdr + 1);
    }
    udphdr->source = 0;
    udphdr->dest = sock->m_reqs->m_port;
    udphdr->len = __constant_htons(sizeof(*udphdr) + len);
    udphdr->check = 0;
    if (!sock->m_reqs->m_rec.m_ip4)
        udphdr->check = checksum(udphdr, sizeof(*udphdr) + len);
    return tx_only(sock, buffer, len + headroom, last);
}

int xdp_send_udp_headroom(xdp_socket_t *sock)
{
    return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
}

int xdp_recv_raw(xdp_socket_t *sock, char **buffer, int *sz,
                 xdp_recv_raw_details_t *details)
{
	unsigned int rcvd;
	u32 idx_rx = 0, idx_fq = 0;
	int ret;

    *buffer = NULL;
    *sz = 0;
	rcvd = xsk_ring_cons__peek(&sock->m_sock_info->rx, 1, &idx_rx);
	if (!rcvd)
		return 0; // Actually, since a poll should have been done this shouldn't happen!

	ret = xsk_ring_prod__reserve(&sock->m_sock_info->umem->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
        {
            snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "xsk_ring_prod__reserve failed on receive: %s",
                     strerror(-ret));
            return -1;
        }
        DEBUG_MESSAGE("Looping on receive finished queue?\n");
		ret = xsk_ring_prod__reserve(&sock->m_sock_info->umem->fq, rcvd, &idx_fq);
	}
    details->m_idx_fq = idx_fq;
    u64 addr = xsk_ring_cons__rx_desc(&sock->m_sock_info->rx, idx_rx)->addr;
    details->m_addr = addr;
    u32 len = xsk_ring_cons__rx_desc(&sock->m_sock_info->rx, idx_rx++)->len;
    char *pkt = xsk_umem__get_data(sock->m_sock_info->umem->buffer, addr);
    *buffer = pkt;
    *sz = len;

    traceBuffer(*buffer, *sz);
    return 0;
}

int xdp_recv_raw_return(xdp_socket_t *sock, xdp_recv_raw_details_t *details)
{
    *xsk_ring_prod__fill_addr(&sock->m_sock_info->umem->fq, details->m_idx_fq++) = details->m_addr;

	xsk_ring_prod__submit(&sock->m_sock_info->umem->fq, 1);
	xsk_ring_cons__release(&sock->m_sock_info->rx, 1);
	sock->m_sock_info->rx_npkts += 1;
    return 0;
}

int xdp_send_completed(xdp_socket_t *sock, int *still_pending)
{
    int ret;
    *still_pending = 0;
	if (sock->m_sock_info->outstanding_tx)
    {
        ret = complete_tx_only(sock);
        if (ret)
            return ret;
        *still_pending = sock->m_sock_info->outstanding_tx;
    }
    return 0;
}

const char *xdp_get_last_error(xdp_prog_t *prog)
{
    return prog->m_err;
}
