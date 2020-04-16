/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#include "lsxdp.h"

#include "ifaddrs.h"
#include "libbpf/src/bpf.h"
#include "poll.h"
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "linux/in.h"
#include "linux/icmp.h"
#include "linux/ioctl.h"
#include "linux/rtnetlink.h"
#include "linux/sockios.h"
#include "linux/tcp.h"
#include "net/if.h"
#include "sys/ioctl.h"
#include "sys/mman.h"
#include "sys/stat.h"
#include "fcntl.h"

#include "ip2mac.h"
#include "sendbufs.h"

static int s_xdp_debug = 0;
#define DEBUG_ON    s_xdp_debug
int debug_message(const char *format, ...)
{
    if (!DEBUG_ON)
        return 0;
    struct timeval tv;
    char buffer[4096];
    va_list args;
    struct tm *ptm;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    gettimeofday(&tv, NULL);
    ptm = localtime(&tv.tv_sec);
    fprintf(stderr, "%02u:%02u:%02u.%03lu [PID: %d] %s", ptm->tm_hour,
            ptm->tm_min, ptm->tm_sec, tv.tv_usec / 1000, getpid(), buffer);
}
#define DEBUG_MESSAGE debug_message
//#define DEBUG_MESSAGE(...) if (s_xdp_debug) fprintf(stderr, __VA_ARGS__)

#define TRACE_BUFFER_DEBUG_MESSAGE
#include "traceBuffer.h"

#define USE_SHARED_MEM

static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | // Does a force if not set */
                           /*XDP_FLAGS_SKB_MODE | // Generic or emulated (slow)*/
                           /*XDP_FLAGS_DRV_MODE | // Native XDP mode*/
                           /*XDP_FLAGS_HW_MODE |   // Hardware offload*/
                           0;
static __u16 opt_xdp_bind_flags = /*XDP_SHARED_UMEM |*/ //?
                                  /* XDP_COPY | // Force copy mode */
                                  /* XDP_ZEROCOPY | // Force zero copy */
                                  0;/*XDP_USE_NEED_WAKEUP;// For same cpu for force yield*/

static u32 max_send(xdp_prog_t *prog)
{
    if (prog->m_multi_queue || !prog->m_shards)
        return prog->m_send_only ? prog->m_max_frames : (prog->m_max_frames / 2);

    if (prog->m_shards % 2)
        // No odd numbers!
        return (prog->m_send_only ? prog->m_max_frames : (prog->m_max_frames / 2)) / (prog->m_shards + 1);
    return (prog->m_send_only ? prog->m_max_frames : (prog->m_max_frames / 2)) / prog->m_shards;
}

static u32 pending_recv(xdp_prog_t *prog)
{
    if (prog->m_multi_queue || !prog->m_shards)
        return prog->m_send_only ? 0 : prog->m_max_frames / 2;

    if (prog->m_shards % 2)
        // No odd numbers!
        return prog->m_send_only ? 0 : (prog->m_max_frames / 2 / (prog->m_shards + 1));
    return prog->m_send_only ? 0 : (prog->m_max_frames / 2 / prog->m_shards);
}

static u32 shard_base(xdp_prog_t *prog)
{
    // Where to start counting for the range.
    if (prog->m_multi_queue || !prog->m_shards)
        return 0;
    return (prog->m_shard - 1) * (max_send(prog) + pending_recv(prog));
}

void xdp_debug(int on)
{
    s_xdp_debug = on;
}

int xdp_get_debug(void)
{
    return s_xdp_debug;
}

static int xsk_configure_umem(xdp_prog_t *prog, int queue, u64 size)
{
	struct xsk_umem_config cfg = {
		.fill_size = prog->m_max_frames,
		.comp_size = prog->m_max_frames,
		.frame_size = prog->m_max_frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	};
	int ret;

    if (queue >= MAX_QUEUES)
    {
        DEBUG_MESSAGE("Can't use queue larger than %d\n", MAX_QUEUES);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Queue #%d specified larger too large (%d)", queue, MAX_QUEUES);
        return -1;
    }
    if (prog->m_umem[queue].buffer)
    {
        DEBUG_MESSAGE("Memory already created and configured for queue %d\n",
                      queue);
        return 0;
    }
    DEBUG_MESSAGE("xsk_configure_umem: %d bytes, allocate max_memory: %ld\n",
                  size, prog->m_max_memory);
#ifndef USE_SHARED_MEM
	ret = posix_memalign(&prog->m_umem[queue].buffer, getpagesize(),
			             prog->m_max_memory);
    if (ret)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Insufficient memory allocating big buffer: %s", strerror(errno));
        return -1;
    }
#else
    prog->m_umem[queue].buffer = mmap(NULL, prog->m_max_memory,
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!prog->m_umem[queue].buffer)
    {
        int err = errno;
        DEBUG_MESSAGE("Error creating buffer memory: %s\n", strerror(err));
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Error creating buffer memory: %s", strerror(err));
        return -1;
    }
#endif
    prog->m_queues++;
    if (prog->m_multi_queue && prog->m_queues > prog->m_max_queues)
    {
        DEBUG_MESSAGE("Exceeded specified number of queues: %d\n",
                      prog->m_max_queues);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Exceeded specified number of queues: %d", prog->m_max_queues);
        return -1;
    }
	ret = xsk_umem__create(&prog->m_umem[queue].umem,
                           prog->m_umem[queue].buffer, size,
                           &prog->m_umem[queue].fq,
                           &prog->m_umem[queue].cq, &cfg);
	if (ret)
    {
        DEBUG_MESSAGE("Error in xsk_umem__create: %s\n", strerror(-ret));
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xsk_umem__create error %s, size: %llu, max_frame_size: %d",
                 strerror(-ret), size, prog->m_max_frame_size);
        return -1;
    }
	return 0;
}

static int find_map_fd(xdp_socket_t *sock, const char *mapname)
{
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;
    struct bpf_map *map;
    int fd;

    map = bpf_object__find_map_by_name(prog->m_if[queue].m_bpf_object, mapname);
    if (!map)
    {
        DEBUG_MESSAGE("Can not find map by name: %s\n", mapname);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Can not find map by name: %s", mapname);
        return -1;
    }

    errno = 0;
	fd = bpf_map__fd(map);
    if (fd < 0)
    {
        int err = errno;
        DEBUG_MESSAGE("Error get fd from map name: %s\n", strerror(err));
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Error get fd from map name: %s\n", strerror(err));
        return -1;
    }
    return fd;
}

#ifdef ADD_MAP_MANUALLY
static int add_to_socket_map(xdp_socket_t *sock)
{
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;
    int pollfd;
    int err;

    /* Does the job that turning off XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD would
       do for a multi-queue environment without breaking if a child close is
       done. */
    DEBUG_MESSAGE("Add queue: %d to map\n", queue);
    if (prog->m_if[queue].m_xsks_map_fd <= 0)
    {
        prog->m_if[queue].m_xsks_map_fd = find_map_fd(sock, "xsks_map");
        if (prog->m_if[queue].m_xsks_map_fd < 0)
            return -1;
    }
    pollfd = xdp_get_poll_fd(sock);
    err = bpf_map_update_elem(prog->m_if[queue].m_xsks_map_fd, &queue, &pollfd,
                              0);
    close(prog->m_if[queue].m_xsks_map_fd);
    prog->m_if[queue].m_xsks_map_fd = -1;
    if (err)
    {
        DEBUG_MESSAGE("Can not update map element: %d \n", err);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Error updating map element");
        return -1;
    }
    return 0;
}
#endif

static int xsk_configure_socket(xdp_socket_t *sock)
{
	struct xsk_socket_config cfg;
	int ret;
	int ifindex = sock->m_reqs->m_ifindex;
    u32 idx;
    int i;
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;

	sock->m_sock_info = calloc(1, sizeof(*sock->m_sock_info));
	if (!sock->m_sock_info)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Insufficient memory in calloc of sock_info: %s",
                 strerror(errno));
        return -1;
    }
	cfg.rx_size = pending_recv(prog);
	cfg.tx_size = max_send(prog);
#ifdef ADD_MAP_MANUALLY
    cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
#else
    cfg.libbpf_flags = (prog->m_multi_queue || !prog->m_if[ifindex].m_socket_attached) ? 0 : XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
#endif
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags/* | child ? XDP_SHARED_UMEM : 0*/;
    DEBUG_MESSAGE("xsk_socket__create queue: %d, send_only: %d, libbpf_flags: "
                  "0x%x, xdp_flags: 0x%x, bind_flags: 0x%x\n",
                  sock->m_queue, prog->m_send_only, cfg.libbpf_flags,
                  cfg.xdp_flags, cfg.bind_flags);
	ret = xsk_socket__create(&sock->m_sock_info->xsk,
                             prog->m_if[ifindex].m_ifname,
                             sock->m_queue,
                             sock->m_xdp_prog->m_umem[sock->m_queue].umem,
                             prog->m_send_only ? NULL : &sock->m_sock_info->rx,
                             &sock->m_sock_info->tx, &cfg);
	if (ret)
    {
        DEBUG_MESSAGE("xsk_socket__create error %s (%d) ifindex: %d name: %s\n",
                      strerror(-ret), -ret, ifindex,
                      sock->m_xdp_prog->m_if[ifindex].m_ifname);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xsk_socket__create error %s ifindex: %d name: %s", strerror(-ret),
                 ifindex, prog->m_if[ifindex].m_ifname);
        return -1;
    }

    prog->m_if[ifindex].m_socket_attached = 1;
	ret = bpf_get_link_xdp_id(ifindex, &sock->m_progid, opt_xdp_flags);
    DEBUG_MESSAGE("After xsk_socket__create (ret: %d), xdp_id prog: %d, fd: %d\n",
                  ret, sock->m_progid, xsk_socket__fd(sock->m_sock_info->xsk));
	if (ret)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "bpf_get_link_xdp_id error %s", strerror(-ret));
		return -1;
    }
#ifdef ADD_MAP_MANUALLY
    if (sock->m_xdp_prog->m_if[ifindex].m_bpf_object && add_to_socket_map(sock))
        return -1;
#endif
    sock->m_pending_recv = pending_recv(prog);
    sock->m_tx_base = shard_base(prog) + pending_recv(prog);
    sock->m_tx_max = max_send(prog);
    if (!prog->m_send_only)
    {
        ret = xsk_ring_prod__reserve(&prog->m_umem[queue].fq,
                                     pending_recv(prog), &idx);
        DEBUG_MESSAGE("Put a lot packets into the fill queue so they can be used "
                      "for recv, starting at index: %d\n", idx);
        if (ret != pending_recv(prog))
        {
            DEBUG_MESSAGE("xsk_ring_prod__reserve: ret: %d != pending_recv: %d\n",
                          ret, pending_recv(prog));
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "xsk_ring_prod__reserve error %s", strerror(-ret));
            return -1;
        }
        DEBUG_MESSAGE("pending_recv: %d, tx_base: %d rx buffer range: %d..%d\n",
                      sock->m_pending_recv,
                      sock->m_tx_base,
                      shard_base(prog),
                      shard_base(prog) + pending_recv(prog) + max_send(prog));
        for (i = 0; i < pending_recv(prog); i++)
            *xsk_ring_prod__fill_addr(&prog->m_umem[queue].fq, idx++) =
                (i + shard_base(prog)) * prog->m_max_frame_size;
        xsk_ring_prod__submit(&prog->m_umem[queue].fq,
                              pending_recv(prog));
    }
    if (send_bufs_init(sock))
        return -1;

	return 0;
}

static int get_mac(xdp_prog_t *prog, const char *ifport, char mac[])
{
    int fd;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        int err = errno;
        DEBUG_MESSAGE("Error getting mac: %s for %s - get socket\n",
                      strerror(err), ifport);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Error getting mac: %s for %s - can't get socket",
                 strerror(err), ifport);
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifport, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFHWADDR, &ifr))
    {
        int err = errno;
        close(fd);
        DEBUG_MESSAGE("Error getting mac: %s for %s - ioctl\n",
                      strerror(err), ifport);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Error getting mac: %s for %s - can't use ioctl",
                 strerror(err), ifport);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
    close(fd);
    DEBUG_MESSAGE("Mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                  (unsigned char)mac[0],
                  (unsigned char)mac[1],
                  (unsigned char)mac[2],
                  (unsigned char)mac[3],
                  (unsigned char)mac[4],
                  (unsigned char)mac[5]);
    return 0;
}

static int get_addrs(char *prog_init_err, int prog_init_err_len, xdp_prog_t *prog)
{
    struct ifaddrs *ifap, *ifa;

    if (getifaddrs(&ifap))
    {
        int err = errno;
        DEBUG_MESSAGE("getifaddrs error: %s\n", strerror(err));
        snprintf(prog_init_err, prog_init_err_len, "getifaddrs error: %s",
                 strerror(err));
        return -1;
    }
    ifa = ifap;
    while (ifa)
    {
        int i;
        for (i = 1; i < MAX_IF; ++i)
        {
            if (!(strcmp(prog->m_if[i].m_ifname, ifa->ifa_name)))
            {
                if (prog->m_if[i].m_disable)
                {
                    DEBUG_MESSAGE("Ignore addrs for disabled if: %s\n",
                                  ifa->ifa_name);
                    break;
                }
                if (((struct sockaddr_in *)ifa->ifa_addr)->sin_family == AF_INET)
                {
                    memcpy(&prog->m_if[i].m_sa_in, ifa->ifa_addr,
                           sizeof(prog->m_if[i].m_sa_in));
                    DEBUG_MESSAGE("%s is ipv4: %u.%u.%u.%u\n", ifa->ifa_name,
                                  ((unsigned char *)&prog->m_if[i].m_sa_in.sin_addr.s_addr)[0],
                                  ((unsigned char *)&prog->m_if[i].m_sa_in.sin_addr.s_addr)[1],
                                  ((unsigned char *)&prog->m_if[i].m_sa_in.sin_addr.s_addr)[2],
                                  ((unsigned char *)&prog->m_if[i].m_sa_in.sin_addr.s_addr)[3]);
                    break;
                }
                else if (((struct sockaddr_in *)ifa->ifa_addr)->sin_family == AF_INET6)
                {
                    memcpy(&prog->m_if[i].m_sa_in6, ifa->ifa_addr,
                           sizeof(prog->m_if[i].m_sa_in6));
                    DEBUG_MESSAGE("%s is ipv6\n", ifa->ifa_name);
                    break;
                }
            }
        }
        ifa = ifa->ifa_next;
    }
    freeifaddrs(ifap);
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
        int err = errno;
        DEBUG_MESSAGE("if_nameindex error: %s\n", strerror(err));
        snprintf(prog_init_err, prog_init_err_len, "if_nameindex error: %s",
                 strerror(err));
        return -1;
    }
    while (names[index].if_index)
    {
        if (names[index].if_index >= MAX_IF)
        {
            DEBUG_MESSAGE("Too many interfaces!\n");
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
        else if (get_mac(prog, names[index].if_name,
                         prog->m_if[names[index].if_index].m_mac))
            prog->m_if[names[index].if_index].m_disable = 1;
        DEBUG_MESSAGE("Interface #%d, idx: %d, max: %d: %s %s\n", index,
                      names[index].if_index, prog->m_max_if,
                      prog->m_if[names[index].if_index].m_ifname,
                      prog->m_if[names[index].if_index].m_disable ? "DISABLE":"");
        ++index;
    }
    if_freenameindex(names);
    if (ret == 0)
        ret = get_addrs(prog_init_err, prog_init_err_len, prog);
    return ret;
}

xdp_prog_t *xdp_prog_init(char *prog_init_err, int prog_init_err_len,
                          int max_frame_size, __u64 max_memory, int send_only,
                          int multi_queue, int multi_shard, int max_queues_shards)
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
#ifndef USE_SHARED_MEM
	prog = malloc(sizeof(xdp_prog_t));
#else
    prog = mmap(NULL, sizeof(xdp_prog_t), PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
#endif
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
    if (!max_memory)
        prog->m_max_memory = prog->m_max_frame_size * 8192; // Arbitrary
    else
        prog->m_max_memory = max_memory;
    prog->m_max_frames = prog->m_max_memory / prog->m_max_frame_size;
    prog->m_max_memory = prog->m_max_frames * prog->m_max_frame_size;
    prog->m_multi_queue = multi_queue;
    prog->m_pid_parent = getpid();
    if (multi_shard)
        prog->m_shards = max_queues_shards;
    if (multi_queue)
        prog->m_max_queues = max_queues_shards;
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
    if (prog->m_max_memory < prog->m_max_frame_size * 20 || // arbitrary
        prog->m_max_memory > 0x10000000000ul) // arbitrary as well
    {
        snprintf(prog_init_err, prog_init_err_len, "Invalid max memory size %llu",
                 prog->m_max_memory);
        xdp_prog_done(prog, 0, 0);
        return NULL;
    }
    prog->m_send_only = send_only;
    prog->m_ip2mac_fd = ip2mac_init(100);
    if (prog->m_ip2mac_fd < 0)
    {
        snprintf(prog_init_err, prog_init_err_len,
                 "Error creating IP to Mac table: %s", strerror(errno));
        xdp_prog_done(prog, 0, 0);
        return NULL;
    }
    return prog;
}

static void x_socket_close( xdp_socket_t* socket, int child )
{
    DEBUG_MESSAGE("xdp_socket_close%s: %p\n", child ? "_child" : "", socket);
    if (!socket)
        return;

    send_bufs_done(socket);

    if (socket->m_sock_info)
    {
        if (socket->m_sock_info->xsk)
        {
#ifdef ADD_MAP_MANUALLY
            DEBUG_MESSAGE("Doing xsk_socket__delete\n");
            xsk_socket__delete(socket->m_sock_info->xsk);
#else
            if (!child)
            {
                DEBUG_MESSAGE("Doing xsk_socket__delete\n");
                xsk_socket__delete(socket->m_sock_info->xsk);
            }
            else
            {
                close(xdp_get_poll_fd(socket));
            }
#endif
        }
        DEBUG_MESSAGE("free sock_info\n");
        free(socket->m_sock_info);
    }
    DEBUG_MESSAGE("freeing socket\n");
    if (!child)
        socket->m_xdp_prog->m_num_socks--;
    free(socket);
}

void xdp_socket_close_child ( xdp_socket_t* socket )
{
    x_socket_close(socket, 1);
}

void xdp_socket_close ( xdp_socket_t* socket )
{
    x_socket_close(socket, 0);
}

#ifdef ADD_MAP_MANUALLY
static void detach_xdp_obj(xdp_prog_t *prog, int force_unload)
{
    int i;
    if (prog->m_pid_parent != getpid())
    {
        DEBUG_MESSAGE("Child: DO NOT detach_xdp_obj\n");
        return;
    }
    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (prog->m_if[i].m_progfd > 0)
        {
            close(prog->m_if[i].m_progfd);
            prog->m_if[i].m_progfd = -1;
        }
        if (prog->m_if[i].m_xsks_map_fd > 0)
        {
            close(prog->m_if[i].m_xsks_map_fd);
            prog->m_if[i].m_xsks_map_fd = -1;
        }
        if (prog->m_if[i].m_socket_attached || force_unload)
        {
            int rc = xdp_link_detach(prog, i, opt_xdp_flags,
                                     0/*prog->m_if[i].m_progfd*/);
            if (rc)
                DEBUG_MESSAGE("xdp_link_detach failed: %s\n", prog->m_err);
            else
                DEBUG_MESSAGE("xdp_link_detach worked\n");
        }
    }
}
#endif

static int xsk_load_kern(xdp_socket_t *sock)
{
    xdp_prog_t *prog = sock->m_xdp_prog;
	struct bpf_program *bpf_prog;
    int ifindex = sock->m_reqs->m_ifindex;
    if (!prog->m_send_only && !prog->m_if[ifindex].m_socket_attached)
    {
        int err;
        struct bpf_prog_load_attr prog_load_attr =
        {
            .prog_type = BPF_PROG_TYPE_XDP,
            .ifindex   = (opt_xdp_flags & XDP_FLAGS_HW_MODE) ? ifindex : 0,
        };
        prog_load_attr.file = "xdpsock_kern.o";
        err = bpf_prog_load_xattr(&prog_load_attr,
                                  &prog->m_if[ifindex].m_bpf_object,
                                  &prog->m_if[ifindex].m_bpf_prog_fd);
        if (err)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Error loading kernel object file(%s) (%d): %s",
                     prog_load_attr.file, err, strerror(-err));
            return -1;
        }
        // Find a matching BPF prog section name
        const char *prog_sec = "xdp_sock";
        DEBUG_MESSAGE("Kernel bpf_object__find_program_by_title: %s, "
                      "obj ptr: %p, prog_fd: %d, index: %d\n",
                      prog_sec, prog->m_if[ifindex].m_bpf_object,
                      prog->m_if[ifindex].m_bpf_prog_fd, ifindex);
        bpf_prog = bpf_object__find_program_by_title(prog->m_if[ifindex].m_bpf_object,
                                                     prog_sec);
        if (!bpf_prog)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Kernel load error finding progsec: %s\n", prog_sec);
            return -1;
	    }
        prog->m_if[ifindex].m_progfd = bpf_program__fd(bpf_prog);
        if (prog->m_if[ifindex].m_progfd <= 0)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Kernel load error bpf_program__fd failed");
            return -1;
	    }
        DEBUG_MESSAGE("bpf_program__fd using prog ptr: %p progfd: %d\n",
                      bpf_prog, sock->m_xdp_prog->m_if[ifindex].m_progfd);
        int ret = bpf_set_link_xdp_fd(ifindex,
                                      prog->m_if[ifindex].m_progfd,
                                      opt_xdp_flags);
        if (ret < 0)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Kernel load error bpf_set_link_xdp_fd: %s", strerror(-ret));
            return -1;
	    }
    }
    return 0;
}

static xdp_socket_t *xdp_sock(xdp_prog_t *prog, lsxdp_socket_reqs_t *reqs,
                              int port, int queue)
{
    xdp_socket_t *socket;

    DEBUG_MESSAGE("xdp_socket, port: %d, queue: %d\n", __constant_htons(port),
                  queue);
    if (queue >= MAX_QUEUES || queue < 0)
    {
        DEBUG_MESSAGE("Invalid queue #%d\n", queue);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Invalid queue (%d not in 0..%d)", queue, MAX_QUEUES - 1);
        return NULL;
    }
    if (!prog->m_umem[queue].buffer &&
        xsk_configure_umem(prog, queue, prog->m_max_memory))
    {
        xdp_prog_done(prog, 0, 0);
        return NULL;
    }

    socket = malloc(sizeof(xdp_socket_t));
    if (!socket)
    {
        DEBUG_MESSAGE("Insufficient memory allocating socket structure\n");
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Insufficient memory to allocate socket structure");
        return NULL;
    }
    DEBUG_MESSAGE("Creating xdp_socket: %p for port: %d\n", socket,
                  __constant_htons(port));
    memset(socket, 0, sizeof(xdp_socket_t));
    socket->m_xdp_prog = prog;
    socket->m_reqs = reqs;
    socket->m_reqs->m_port = port;
    socket->m_filter_map = -1;
    prog->m_num_socks++;
    if (xsk_load_kern(socket))
    {
        xdp_socket_close(socket);
        return NULL;
    }
    socket->m_queue = queue;
    socket->m_in_port = port;
    if (xsk_configure_socket(socket))
    {
        xdp_socket_close(socket);
        return NULL;
    }
    prog->m_xsks[prog->m_num_socks - 1] = socket;
    return socket;
}

xdp_socket_t *xdp_socket(xdp_prog_t *prog, lsxdp_socket_reqs_t *reqs, int port,
                         int queue)
{
    return xdp_sock(prog, reqs, port, queue);
}

static int addr_bind_to_ifport(xdp_prog_t *prog,
                               const struct sockaddr *addr_bind,
                               char ifport[])
{
    int i;
    ifport[0] = 0;
    if (!addr_bind || !addr_bind->sa_family)
    {
        DEBUG_MESSAGE("addr_bind_to_ifport NO addr_bind specified\n");
        return 0;
    }
    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if ((addr_bind->sa_family == AF_INET &&
             prog->m_if[i].m_sa_in.sin_family == AF_INET &&
             ((struct sockaddr_in *)addr_bind)->sin_addr.s_addr == prog->m_if[i].m_sa_in.sin_addr.s_addr) ||
            (addr_bind->sa_family == AF_INET6 &&
             prog->m_if[i].m_sa_in6.sin6_family == AF_INET6 &&
             ((struct sockaddr_in6 *)addr_bind)->sin6_addr.in6_u.u6_addr32[0] == prog->m_if[i].m_sa_in6.sin6_addr.in6_u.u6_addr32[0] &&
             ((struct sockaddr_in6 *)addr_bind)->sin6_addr.in6_u.u6_addr32[0] == prog->m_if[i].m_sa_in6.sin6_addr.in6_u.u6_addr32[1] &&
             ((struct sockaddr_in6 *)addr_bind)->sin6_addr.in6_u.u6_addr32[0] == prog->m_if[i].m_sa_in6.sin6_addr.in6_u.u6_addr32[2] &&
             ((struct sockaddr_in6 *)addr_bind)->sin6_addr.in6_u.u6_addr32[0] == prog->m_if[i].m_sa_in6.sin6_addr.in6_u.u6_addr32[3]))
        {
            if (addr_bind->sa_family == AF_INET)
                DEBUG_MESSAGE("Found addr_bind addr %u.%u.%u.%u on %s\n",
                              ((unsigned char *)&((struct sockaddr_in *)addr_bind)->sin_addr.s_addr)[0],
                              ((unsigned char *)&((struct sockaddr_in *)addr_bind)->sin_addr.s_addr)[1],
                              ((unsigned char *)&((struct sockaddr_in *)addr_bind)->sin_addr.s_addr)[2],
                              ((unsigned char *)&((struct sockaddr_in *)addr_bind)->sin_addr.s_addr)[3],
                              prog->m_if[i].m_ifname);
            else
                DEBUG_MESSAGE("Found addr_bind addr (v6) on %s\n", prog->m_if[i].m_ifname);
            strcpy(ifport, prog->m_if[i].m_ifname);
            break;
        }
    }
    if (!ifport[0])
    {
        DEBUG_MESSAGE("Bind address not found in list of interfaces\n");
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Bind address not found in list of interfaces - respecify");
    }
    return (ifport[0] ? 0 : -1);
}

static int ifport_to_addr_bind(xdp_prog_t *prog,
                               const char ifport[],
                               int ipv4,
                               struct sockaddr *addr_bind)
{
    int i;
    DEBUG_MESSAGE("ifport_to_addr_bind, port: %s, %s\n", ifport,
                  ipv4 ? "IPv4" : "IPv6");

    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (!(strcmp(ifport, prog->m_if[i].m_ifname)))
        {
            if (ipv4 &&
                prog->m_if[i].m_sa_in.sin_family == AF_INET)
            {
                memcpy(addr_bind, &prog->m_if[i].m_sa_in,
                       sizeof(struct sockaddr_in));
                DEBUG_MESSAGE("Addr for port %s is %u.%u.%u.%u\n", ifport,
                              ((unsigned char *)&prog->m_if[i].m_sa_in.sin_addr.s_addr)[0],
                              ((unsigned char *)&prog->m_if[i].m_sa_in.sin_addr.s_addr)[1],
                              ((unsigned char *)&prog->m_if[i].m_sa_in.sin_addr.s_addr)[2],
                              ((unsigned char *)&prog->m_if[i].m_sa_in.sin_addr.s_addr)[3]);
                break;
            }
            if (!ipv4 &&
                prog->m_if[i].m_sa_in6.sin6_family == AF_INET6)
            {
                memcpy(addr_bind, &prog->m_if[i].m_sa_in6,
                       sizeof(struct sockaddr_in6));
                break;
            }
        }
    }
    if (i > prog->m_max_if)
    {
        DEBUG_MESSAGE("Can't find ifname: %s in ifs\n", ifport);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "ifname not found in list of interfaces - respecify");\
    }
    return ((i > prog->m_max_if) ? -1 : 0);
}

static int check_if(xdp_prog_t *prog, const char *ifport,
                    const struct sockaddr *addr_bind, int *enabled_ifindex)
{
    int i;
    int enabled_one = 0;
    char ifp[IF_NAMESIZE];

    if (!ifport || !ifport[0])
    {
        if (addr_bind_to_ifport(prog, addr_bind, ifp))
            return -1;
        ifport = ifp;
    }
    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (!prog->m_if[i].m_ifname[0] ||
            ((!ifport || !ifport[0]) && prog->m_if[i].m_disable))
            continue;
        if (ifport && ifport[0] && strcmp(ifport, prog->m_if[i].m_ifname))
        {
            DEBUG_MESSAGE("ifport specified (%s) and %s does not match, disabling\n",
                          ifport, prog->m_if[i].m_ifname);
            prog->m_if[i].m_disable = 1;
            continue;
        }
        else if (ifport && ifport[0])
            prog->m_if[i].m_disable = 0;
        if (!prog->m_if[i].m_disable)
        {
            if (enabled_one)
            {
                DEBUG_MESSAGE("Attempt to bind to more than one interface\n");
                snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                         "Attempt to bind to more than one interface specify a "
                         "specific interface or bind-to address");
                return -1;
            }
            *enabled_ifindex = i;
            enabled_one = 1;
        }
    }
    if (!enabled_one)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "No interfaces enabled, you must specify an interface");
        return -1;
    }
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

static lsxdp_socket_reqs_t *malloc_reqs(xdp_prog_t *prog, int ifindex)
{
    lsxdp_socket_reqs_t *reqs;
    reqs = malloc(sizeof(lsxdp_socket_reqs_t));
    if (!reqs)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Insufficient memory to allocate required data");
        return NULL;
    }
    memset(reqs, 0, sizeof(*reqs));
    reqs->m_ifindex = ifindex;
    return reqs;
}

static void update_header(lsxdp_socket_reqs_t *reqs)
{
    struct ethhdr *eth;

    DEBUG_MESSAGE("Just updating the header (just addr changes)\n");

    eth = (struct ethhdr *)reqs->m_rec.m_header;
    memcpy(eth->h_dest, &reqs->m_mac, sizeof(eth->h_dest));

    if (reqs->m_rec.m_ip4)
    {
        struct iphdr *iph;
        memcpy(&reqs->m_rec.m_addr.in6_u.u6_addr32[0],
               &reqs->m_sa_in, 4);
        iph = (struct iphdr *)(eth + 1);
        iph->daddr = reqs->m_sa_in.sin_addr.s_addr;
    }
    //TODO
    //else
    //    memcpy(&reqs->m_rec.m_addr, sockaddr, sizeof(struct in6_addr));
    traceBuffer(reqs->m_rec.m_header, reqs->m_rec.m_header_size);
}

static int send_udp_headroom(void)
{
    return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
}

int xdp_send_udp_headroom(xdp_socket_t *sock)
{
    return send_udp_headroom();
}

static void rebuild_header(lsxdp_socket_reqs_t *reqs, char *pkt,
                           struct sockaddr *sockaddr)
{
    int header_pos;

    reqs->m_sendable = 1;
    reqs->m_rec.m_addr_set = 1;
    reqs->m_rec.m_ip4 = ((struct sockaddr_in *)sockaddr)->sin_family == AF_INET;
    if (reqs->m_rec.m_ip4)
        memcpy(&reqs->m_rec.m_addr.in6_u.u6_addr32[0],
               &((struct sockaddr_in *)sockaddr)->sin_addr, 4);
    else
        memcpy(&reqs->m_rec.m_addr, sockaddr, sizeof(struct in6_addr));
    // m_port has already been set.
    reqs->m_rec.m_ip_index = sizeof(struct ethhdr);
    reqs->m_rec.m_header_size = send_udp_headroom();
    memcpy(reqs->m_rec.m_header, pkt, reqs->m_rec.m_header_size);
    DEBUG_MESSAGE("recv, build sendable header %s, raw:\n",
                  reqs->m_rec.m_ip4 ? "ipv4" : "ipv6");
    traceBuffer(reqs->m_rec.m_header, reqs->m_rec.m_header_size);
    // Reverse the fields where appropriate.
    memcpy(reqs->m_rec.m_header, ((struct ethhdr *)pkt)->h_source,
           sizeof(((struct ethhdr *)pkt)->h_source));
    memcpy(((struct ethhdr *)reqs->m_rec.m_header)->h_source, pkt,
           sizeof(((struct ethhdr *)pkt)->h_source));
    header_pos = sizeof(struct ethhdr);
    if (reqs->m_rec.m_ip4)
    {
        struct iphdr *iphdr_save, *iphdr_pkt;
        iphdr_save = (struct iphdr *)(reqs->m_rec.m_header + header_pos);
        iphdr_pkt = (struct iphdr *)(pkt + header_pos);
        iphdr_save->saddr = iphdr_pkt->daddr;
        iphdr_save->daddr = iphdr_pkt->saddr;
        header_pos += sizeof(struct iphdr);
    }
    else
    {
        struct ipv6hdr *ipv6hdr_save, *ipv6hdr_pkt;
        ipv6hdr_save = (struct ipv6hdr *)(reqs->m_rec.m_header + header_pos);
        ipv6hdr_pkt = (struct ipv6hdr *)(pkt + header_pos);
        memcpy(&ipv6hdr_save->saddr, &ipv6hdr_pkt->daddr, sizeof(struct in6_addr));
        memcpy(&ipv6hdr_save->daddr, &ipv6hdr_pkt->saddr, sizeof(struct in6_addr));
        header_pos += sizeof(struct ipv6hdr);
    }
    {
        struct udphdr *udphdr_save, *udphdr_pkt;
        udphdr_save = (struct udphdr *)(reqs->m_rec.m_header + header_pos);
        udphdr_pkt = (struct udphdr *)(pkt + header_pos);
        udphdr_save->source = udphdr_pkt->dest;
        udphdr_save->dest = udphdr_pkt->source;
        header_pos += sizeof(struct udphdr);
    }
    traceBuffer(reqs->m_rec.m_header, reqs->m_rec.m_header_size);
}

static int set_reqs(xdp_prog_t *prog, lsxdp_socket_reqs_t *reqs,
                    struct sockaddr *addr)
{
    char pkt[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)];
    struct ethhdr *eth;
    struct iphdr *iph;
    ip2mac_data_t data;
    unsigned char *mac = data.m_mac;

    // TODO Don't forget IP6!
    if (ip2mac_lookup(prog->m_ip2mac_fd,
                      ((struct sockaddr_in *)addr)->sin_addr.s_addr, &data))
    {
        int err = errno;
        DEBUG_MESSAGE("Can't lookup address: %s\n", strerror(err));
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Can't lookup address: %s", strerror(err));
        errno = err;
        return -1;
    }
    memcpy(&reqs->m_sa_in, addr, sizeof(reqs->m_sa_in));
    memcpy(&reqs->m_mac, mac, sizeof(reqs->m_mac));
    DEBUG_MESSAGE("Hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    // TODO: If the address type changes I must rebuild the header as well
    if (reqs->m_sendable)
    {
        //printf("Change remote addr to %u.%u.%u.%u\n",
        //       ((unsigned char *)&sock->m_reqs->m_sa_in.sin_addr.s_addr)[0],
        //       ((unsigned char *)&sock->m_reqs->m_sa_in.sin_addr.s_addr)[1],
        //       ((unsigned char *)&sock->m_reqs->m_sa_in.sin_addr.s_addr)[2],
        //       ((unsigned char *)&sock->m_reqs->m_sa_in.sin_addr.s_addr)[3]);
        update_header(reqs);
    }
    else
    {
        memset(pkt, 0, sizeof(pkt));
        eth = (struct ethhdr *)pkt;
        memcpy(eth->h_source, mac, sizeof(eth->h_dest));
        memcpy(eth->h_dest, prog->m_if[reqs->m_ifindex].m_mac,
               sizeof(eth->h_source));
        eth->h_proto = __constant_htons(ETH_P_IP);
        iph = (struct iphdr *)(eth + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->ttl = 20;
        iph->protocol = 17; // UDP
        iph->daddr = prog->m_if[reqs->m_ifindex].m_sa_in.sin_addr.s_addr;
        iph->saddr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
        rebuild_header(reqs, pkt, addr);
    }
    return 0;
}

lsxdp_socket_reqs_t *xdp_get_socket_reqs(xdp_prog_t *prog,
                                         const struct sockaddr *addr,
                                         socklen_t addrLen,
                                         const struct sockaddr *addr_bind,
                                         const char *ifport)
{
    lsxdp_socket_reqs_t *reqs;
    int enabled_if;

    DEBUG_MESSAGE("xdp_get_socket_reqs - check_if\n");
    if (check_if(prog, ifport, addr_bind, &enabled_if))
        return NULL;

    if (!prog->m_send_only)
    {
        DEBUG_MESSAGE("xdp_get_socket_reqs - forcably detach any loaded XDP progs "
                      "on if #%d: %s!\n", enabled_if, prog->m_if[enabled_if].m_ifname);
        if (xdp_link_detach(prog, enabled_if, opt_xdp_flags, 0))
            DEBUG_MESSAGE("xdp_link_detach failed: %s\n", prog->m_err);
    }
    reqs = malloc_reqs(prog, enabled_if);
    if (!reqs)
        return NULL;
    reqs->m_sendable = 0;
    if (!addr)
        return reqs;
    if (set_reqs(prog, reqs, (struct sockaddr *)addr))
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
    traceBuffer(reqs->m_rec.m_header, reqs->m_rec.m_header_size);
    return reqs;
}

int xdp_get_local_addr(xdp_prog_t *prog,
                       lsxdp_socket_reqs_t *reqs,
                       int ipv4,
                       struct sockaddr *addr)
{
    return ifport_to_addr_bind(prog, prog->m_if[reqs->m_ifindex].m_ifname, ipv4,
                               addr);
}

void xdp_prog_done ( xdp_prog_t* prog, int unload, int force_unload )
{
    if (!prog)
        return;
    if (prog->m_ip2mac_fd > 0)
        ip2mac_done(prog->m_ip2mac_fd);
#ifdef ADD_MAP_MANUALLY
    if (unload)
        detach_xdp_obj(prog, 1/*force_unload*/);
#endif
    if (prog->m_num_socks)
        fprintf(stderr, "%d Sockets remain open!\n", prog->m_num_socks);
    int umem = 0;
    int umem_index = 0;
    while (umem_index < MAX_QUEUES && umem < prog->m_queues)
    {
        if (prog->m_umem[umem_index].buffer)
        {
            ++umem;
#ifndef USE_SHARED_MEM
            free(prog->m_umem[umem_index].buffer);
#else
            munmap(prog->m_umem[umem_index].buffer, prog->m_max_memory);
#endif
        }
        if (prog->m_umem[umem_index].umem)
        {
            DEBUG_MESSAGE("Doing xdk_umem__delete\n");
            xsk_umem__delete(prog->m_umem[umem_index].umem); //
        }
        ++umem_index;
    }
#ifndef USE_SHARED_MEM
    free(prog);
#else
    munmap(prog, sizeof(xdp_prog_t));
#endif
}

int xdp_get_poll_fd(xdp_socket_t *sock)
{
    return xsk_socket__fd(sock->m_sock_info->xsk);
}

static int get_index_from_buffer(xdp_socket_t *sock, void *buffer)
{
    /* Given a buffer location, return the index */
    int index = (int)(((char *)buffer - (char *)sock->m_xdp_prog->m_umem[sock->m_queue].buffer) / sock->m_xdp_prog->m_max_frame_size);
    DEBUG_MESSAGE("get_index_from_buffer, base: %p, buffer: %p, max_frame: %d, index: %d\n",
                  sock->m_xdp_prog->m_umem[sock->m_queue].buffer, buffer,
                  sock->m_xdp_prog->m_max_frame_size, index);
    return index;
}

static int kick_tx(xdp_socket_t *sock)
{
	int ret;

    if (sock->m_busy_send)
        DEBUG_MESSAGE("busy_send retry\n");

    /*
    {
        int rc;
        struct pollfd p;
        memset(&p, 0, sizeof(p));
        p.fd = xdp_get_poll_fd(sock);
        p.events = POLLOUT;
        rc = poll(&p, 1, 0);
        DEBUG_MESSAGE("xdp_get_send_buffer, Ok to send: %s\n",
                      (rc == 1) ? "YES" : ((rc == 0) ? "NO" : strerror(errno)));
    }
    */
	ret = sendto(xsk_socket__fd(sock->m_sock_info->xsk), NULL, 0, MSG_DONTWAIT,
                 NULL, 0);
    int orig_errno = errno;
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
    {
        if (ret != 0)
        {
            DEBUG_MESSAGE("sendto returned %d, errno: %d: %s - setting busy_send sock: %p\n",
                          ret, orig_errno, strerror(orig_errno), sock);
            /**
             * Explanation: I can do this because I control access to buffers
             * and make sure that I don't overwrite data.  Thus I'm just
             * buffering like mad and not waiting until I really have an
             * exhausted resource.
             **/
            //errno = EAGAIN;
            sock->m_busy_send = 1;
            //return -1;
            return 0;
        }
        if (sock->m_busy_send)
        {
            DEBUG_MESSAGE("Clearing busy_send sock: %p\n", sock);
            sock->m_busy_send = 0;
        }
		return 0;
    }
    if (sock->m_busy_send)
    {
        DEBUG_MESSAGE("Clearing busy_send sock: %p\n", sock);
        sock->m_busy_send = 0;
    }
    DEBUG_MESSAGE("Error in send: %s\n", strerror(orig_errno));
    snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
             "Error in send: %s", strerror(orig_errno));
    errno = orig_errno;
    return -1;
}

static inline int complete_tx_only(xdp_socket_t *sock, int *released)
{
	unsigned int rcvd;
	u32 idx;
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;

    *released = 0;
    if (kick_tx(sock))
        return -1;
    rcvd = xsk_ring_cons__peek(&prog->m_umem[queue].cq, MAX_PEEK, &idx);
    if (rcvd > 0)
    {
        *released = 1;
        xsk_ring_cons__release(&prog->m_umem[queue].cq, rcvd);
        if (sock->m_tx_outstanding)
        {
            if (sock->m_tx_outstanding >= rcvd)
                sock->m_tx_outstanding -= rcvd;
            else
            {
                sock->m_tx_outstanding = 0;
                DEBUG_MESSAGE("TX: Completion queue forced to zero (would go lower)\n");
            }
        }
        else
            DEBUG_MESSAGE("TX: Completion queue forced to zero (already zero: %d)\n", rcvd);
        DEBUG_MESSAGE("TX: Completion queue has %d, idx: %d, outstanding: %d\n",
                      rcvd, idx, sock->m_tx_outstanding);
    }
    //else
    //    DEBUG_MESSAGE("TX: Completion queue Empty\n");

	return 0;
}

static int tx_only(xdp_socket_t *sock, void *buffer, int len, int last)
{
    struct xdp_desc *desc;
    u32 idx;
    int ret;
    int released;
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;

    if (sock->m_busy_send)
        return complete_tx_only(sock, &released);
    DEBUG_MESSAGE("TX: tx_only %p\n", buffer);
    ret = xsk_ring_prod__reserve(&sock->m_sock_info->tx, 1, &idx);
    if (ret != 1)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Can't reserve a single packet (%d)", ret);
        return -1;
    }
    desc = xsk_ring_prod__tx_desc(&sock->m_sock_info->tx, idx);
    desc->addr = get_index_from_buffer(sock, buffer) * prog->m_max_frame_size;
    desc->len = len;
    DEBUG_MESSAGE("TX: sent (addr offset: %ld):\n", desc->addr);
    traceBuffer(buffer, len);

	xsk_ring_prod__submit(&sock->m_sock_info->tx, 1);
    sock->m_tx_outstanding += 1;
    if (last && complete_tx_only(sock, &released))
        return -1;
    return 0;
}

void *xdp_get_send_buffer(xdp_socket_t *sock)
{
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;
    int index = -1;
    void *buffer;

    /*
    {
        int rc;
        struct pollfd p;
        memset(&p, 0, sizeof(p));
        p.fd = xdp_get_poll_fd(sock);
        p.events = POLLIN;
        rc = poll(&p, 1, 0);
        DEBUG_MESSAGE("xdp_get_send_buffer, pending recv: %s\n",
                      (rc == 1) ? "YES" : ((rc == 0) ? "NO" : strerror(errno)));
        if (rc == 1 && p.revents != POLLIN)
            DEBUG_MESSAGE("UNEXPECTED RECEIVED EVENT: %d\n", p.revents);
    }
    */
    if (send_bufs_get_one_free(sock, &index))
    {
        int released;
        int rc;
        struct pollfd p;
        DEBUG_MESSAGE("Kick and Poll to see if a packet can be coaxed out\n");
        memset(&p, 0, sizeof(p));
        p.fd = xdp_get_poll_fd(sock);
        p.events = POLLOUT;
        rc = poll(&p, 1, 0);
        if (rc == 0)
        {
            DEBUG_MESSAGE("TX: Poll had no success\n");
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "poll had no success getting sending buffer");
            errno = EAGAIN;
            return NULL;
        }
        else if (rc == -1)
        {
            int err = errno;
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "poll for send failed: %s", strerror(errno));
            DEBUG_MESSAGE("TX: %s\n", sock->m_xdp_prog->m_err);
            errno = err;
            return NULL;
        }
        if (complete_tx_only(sock, &released))
            return NULL; // Error in buffer
        if (send_bufs_get_one_free(sock, &index))
            return NULL;
    }

    buffer = xsk_umem__get_data(prog->m_umem[queue].buffer,
                                (index + sock->m_tx_base) * prog->m_max_frame_size);
    sock->m_last_send_buffer = buffer;
    DEBUG_MESSAGE("TX: xdp_get_send_buffer: buffer_index: %d (header size: %d), "
                  "last_send_buffer Addr: %p\n",
                  index, sock->m_reqs->m_rec.m_header_size, buffer);
    return (void *)((char *)buffer + xdp_send_udp_headroom(sock));
}

int xdp_release_send_buffer(xdp_socket_t *sock, void *buffer)
{
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;
    int index = get_index_from_buffer(sock, buffer);
    int zero_based_index = index - sock->m_tx_base;
    DEBUG_MESSAGE("TX: release_send_buffer: %d\n", zero_based_index);
    send_bufs_freed_one(sock, zero_based_index);
    return 0;
}

static int get_remote_info(xdp_socket_t *sock, struct sockaddr *addr)
{
    return set_reqs(sock->m_xdp_prog, sock->m_reqs, addr);
}

static int check_send_addr(xdp_socket_t *sock, struct sockaddr *addr)
{
    if (((struct sockaddr_in *)addr)->sin_family == AF_INET6)
    {
    	DEBUG_MESSAGE("IPv4 only supported for separate send/recv\n");
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "IPv4 only supported for separate send/recv");
        return -1;
    }
    if (sock->m_reqs->m_sendable &&
        (!((struct sockaddr_in *)addr)->sin_addr.s_addr ||
         ((struct sockaddr_in *)addr)->sin_addr.s_addr == sock->m_reqs->m_sa_in.sin_addr.s_addr))
        // Use the one in cache
        return 0;

    DEBUG_MESSAGE("check_send_addr: family: %u addr: %u.%u.%u.%u port: %d\n",
                  ((struct sockaddr_in *)addr)->sin_family,
                  ((unsigned char *)&((struct sockaddr_in *)addr)->sin_addr.s_addr)[0],
                  ((unsigned char *)&((struct sockaddr_in *)addr)->sin_addr.s_addr)[1],
                  ((unsigned char *)&((struct sockaddr_in *)addr)->sin_addr.s_addr)[2],
                  ((unsigned char *)&((struct sockaddr_in *)addr)->sin_addr.s_addr)[3],
                  __constant_htons(((struct sockaddr_in *)addr)->sin_port));
    return get_remote_info(sock, addr);
}

static int x_send_zc(xdp_socket_t *sock, void *buffer, int len, int last,
                     struct sockaddr *addr)
{
    int ip_index;
    struct udphdr *udphdr;
    char *buffer_char = buffer;
    __u16 port = sock->m_in_port;
    int headroom = xdp_send_udp_headroom(sock);
    /* Fill in the headroom header (ethernet, IP, UDP) */
    memcpy(buffer, sock->m_reqs->m_rec.m_header, xdp_send_udp_headroom(sock));
    ip_index = sock->m_reqs->m_rec.m_ip_index;
    if (sock->m_reqs->m_rec.m_ip4)
    {
        struct ethhdr *ethhdr = (struct ethhdr *)buffer_char;
        memcpy(ethhdr->h_dest, sock->m_reqs->m_mac, sizeof(ethhdr->h_dest));
        struct iphdr *iphdr = (struct iphdr *)&buffer_char[ip_index];
        DEBUG_MESSAGE("TX: ip_index begins at %d\n", ip_index);
        iphdr->ihl = 5;
        iphdr->tot_len = __constant_htons(20 + sizeof(struct udphdr) + len);
        iphdr->id = 0;
        iphdr->frag_off = 0;
        iphdr->ttl = 20;
        iphdr->protocol = 17; // UDP
        iphdr->daddr = sock->m_reqs->m_sa_in.sin_addr.s_addr;
        iphdr->check = 0;
        iphdr->check = checksum(iphdr, sizeof(struct iphdr));
        DEBUG_MESSAGE("TX: addr: %p, port: %d, in_port: %d\n", addr,
                      addr ? __constant_htons(((struct sockaddr_in *)addr)->sin_port) : 0,
                      __constant_htons(port));
        if (addr && ((struct sockaddr_in *)addr)->sin_port)
        {
            port = ((struct sockaddr_in *)addr)->sin_port;
            DEBUG_MESSAGE("TX: Override port to %d\n", __constant_htons(port));
        }
        udphdr = (struct udphdr *)(iphdr + 1);
    }
    else
    {
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)&((char *)buffer)[ip_index];
        ipv6hdr->payload_len = __constant_htons(sizeof(struct udphdr) + len);
        ipv6hdr->nexthdr = 17; // UDP
        ipv6hdr->hop_limit = 20;
        if (addr && ((struct sockaddr_in6 *)addr)->sin6_port)
        {
            port = ((struct sockaddr_in6 *)addr)->sin6_port;
            DEBUG_MESSAGE("TX: Override port to %d (ipv6)\n", __constant_htons(port));
        }
        udphdr = (struct udphdr *)(ipv6hdr + 1);
    }
    udphdr->source = sock->m_in_port;
    udphdr->dest = port;
    udphdr->len = __constant_htons(sizeof(*udphdr) + len);
    udphdr->check = 0;
    if (!sock->m_reqs->m_rec.m_ip4)
        udphdr->check = checksum(udphdr, sizeof(*udphdr) + len);
    return tx_only(sock, buffer, len + headroom, last);
}

static int x_send(xdp_socket_t *sock, void *data, int len, int last,
                  struct sockaddr *addr, int must_zero_copy)
{
    int headroom = xdp_send_udp_headroom(sock);
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;
    char *send_buffer;
    char *data_char = data;
    int released;

    if (sock->m_busy_send)
    {
        int rc;
        send_buffer = data - headroom;
        if (!sock->m_last_send_buffer)
        {
            DEBUG_MESSAGE("TX: in busy send in xdp_send, just retry for now\n");
            return complete_tx_only(sock, &released);
        }
        DEBUG_MESSAGE("TX: in busy send in xdp_send, but a pending buffer %p"
                      ", current buffer: %p\n",
                      sock->m_last_send_buffer, send_buffer);
        rc = complete_tx_only(sock, &released);
        if (rc)
            return rc;
        if (send_buffer == sock->m_last_send_buffer)
        {
            DEBUG_MESSAGE("TX: busy send but NEW DATA to send!\n");
        }
        else
        {
            DEBUG_MESSAGE("TX: busy send but probably no new data to send\n");
            return 0;
        }
    }
    if (check_send_addr(sock, addr))
        return -1;
    sock->m_last_send_buffer = NULL;
    if (!sock->m_reqs->m_sendable)
    {
        DEBUG_MESSAGE("TX: socket can't be used for sending\n");
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "This socket can not yet be used for sending (must be setup"
                 " as documented");
        return -1;
    }
    if (data_char > (char *)prog->m_umem[queue].buffer &&
        data_char < (char *)prog->m_umem[queue].buffer + prog->m_max_memory)
    {
        DEBUG_MESSAGE("TX: Data in buffer range - assume it was gotten correctly\n");
        send_buffer = data_char - headroom;
    }
    else if (must_zero_copy)
    {
        DEBUG_MESSAGE("TX: Require that the packet be aquired with get_send_buffer\n");
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Require that the packet be acquired with a xdp_get_send_buffer()"
                 " or a call to xdp_send() - %p not in range %p..%p (test 1: %d, test 2: %d)",
                 data_char, prog->m_umem[queue].buffer,
                 prog->m_umem[queue].buffer + prog->m_max_memory,
                 data_char >= (char *)prog->m_umem[queue].buffer,
                 data_char < (char *)prog->m_umem[queue].buffer + prog->m_max_memory);
        return -1;
    }
    else
    {
        DEBUG_MESSAGE("TX: xdp_send, NOT zero copy, copy in the data\n");
        send_buffer = xdp_get_send_buffer(sock);
        if (!send_buffer)
            return -1;
        memcpy(send_buffer + headroom, data, len);
    }
    return x_send_zc(sock, send_buffer, len, last, addr);
}

int xdp_send(xdp_socket_t *sock, void *data, int len, int last,
             struct sockaddr *addr)
{
    return x_send(sock, data, len, last, addr, 0);
}

int xdp_send_zc(xdp_socket_t *sock, void *data, int len, int last,
                struct sockaddr *addr)
{
    return x_send(sock, data, len, last, addr, 1);
}

static int parse_recv_ip_hdr(xdp_socket_t *sock, char *pkt, int len,
                             int *header_pos, struct sockaddr *addr,
                             socklen_t *addrlen)
{
    /* Note to return 1 to ignore packet, 0 to continue processing, and -1 for
     * an error.  */
    if (len < xdp_send_udp_headroom(sock))
    {
        DEBUG_MESSAGE("Recv Packet too small to be UDP\n");
        return 1;
    }
    *header_pos = sizeof(struct ethhdr);
    if (((struct ethhdr *)pkt)->h_proto == __constant_htons(ETH_P_IP))
    {
        struct iphdr *iph = (struct iphdr *)(pkt + *header_pos);
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        int hdrsize = iph->ihl * 4;
        *header_pos += hdrsize;
        if (len < *header_pos)
        {
            DEBUG_MESSAGE("Recv Packet too small to be UDP IPv4\n");
            return 1;
        }
        if (iph->protocol != IPPROTO_UDP)
        {
            DEBUG_MESSAGE("Recv not UDP (protocol: %d)\n",iph->protocol);
            return 1;
        }
        if (addr && addrlen && *addrlen >= sizeof(struct sockaddr_in))
        {
            ((struct sockaddr_in *)addr)->sin_family = AF_INET;
            ((struct sockaddr_in *)addr)->sin_addr.s_addr = iph->saddr;
            ((struct sockaddr_in *)addr)->sin_port = udph->source;
            DEBUG_MESSAGE("Recv save address and port to %p\n", addr);
        }
        DEBUG_MESSAGE("Recv Remote addr %u.%u.%u.%u:%d\n",
                      ((unsigned char *)&iph->saddr)[0],
                      ((unsigned char *)&iph->saddr)[1],
                      ((unsigned char *)&iph->saddr)[2],
                      ((unsigned char *)&iph->saddr)[3],
                      __constant_htons(udph->source));
    }
    else if (((struct ethhdr *)pkt)->h_proto == __constant_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(pkt + *header_pos);
        struct udphdr *udph = (struct udphdr *)(ip6h + 1);
        *header_pos += sizeof(struct ipv6hdr);
        if (len < *header_pos)
        {
            DEBUG_MESSAGE("Recv Packet too small to be UDP IPv6\n");
            return 1;
        }
        if (ip6h->nexthdr != IPPROTO_UDP)
        {
            DEBUG_MESSAGE("Recv not UDP (IPv6) protocol: %d\n", ip6h->nexthdr);
            return 1;
        }
        if (addr && addrlen && *addrlen > sizeof(struct sockaddr_in6))
        {
            ((struct sockaddr_in6 *)addr)->sin6_family = AF_INET6;
            memcpy(&((struct sockaddr_in6 *)addr)->sin6_addr, &ip6h->saddr,
                   sizeof(struct in6_addr));
            ((struct sockaddr_in6 *)addr)->sin6_port = udph->source;
            DEBUG_MESSAGE("Recv save address and port (%d)\n",
                          __constant_htons(udph->source));
        }
    }
    else
    {
        DEBUG_MESSAGE("Recv not IPv4 or IPv6 or ARP\n");
        return 1;
    }
    return 0;
}

static int parse_recv_udp_hdr(xdp_socket_t *sock, char *pkt, int *len,
                              int *header_pos, struct sockaddr *addr)
{
    struct udphdr *udp = (struct udphdr *)((unsigned char *)pkt + *header_pos);
    if (*header_pos + sizeof(struct udphdr) > *len)
    {
        DEBUG_MESSAGE("Recv buffer too small for UDP\n");
        return 1;
    }
    if (udp->dest && udp->dest != sock->m_reqs->m_port)
    {
        /* Check both send and recv ports because I don't know an ACK from a
         * true receive (for now).  */
        DEBUG_MESSAGE("Recv port mismatch (%d != %d)\n",
                      __constant_htons(udp->dest),
                      __constant_htons(sock->m_reqs->m_port));
        return 1;
    }
    if (*len < (*header_pos) + __constant_htons(udp->len))
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Received packet: %d smaller than UDP length allows: %d",
                 *len, (*header_pos) + __constant_htons(udp->len));
        return 1;
    }
    if (addr)
    {
        if (((struct sockaddr_in *)addr)->sin_family == AF_INET)
            ((struct sockaddr_in *)addr)->sin_port = udp->source;
        else
            ((struct sockaddr_in6 *)addr)->sin6_port = udp->source;
    }
    DEBUG_MESSAGE("Recv source port %d\n",  __constant_htons(udp->source));
    *len = (*header_pos) + __constant_htons(udp->len);
    *header_pos += sizeof(struct udphdr);
    return 0;
}

static int recv_return_raw(xdp_socket_t *sock, void *buffer)
{
    int ret;
    __u32 idx, idx_fq = 0;
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;

    idx = get_index_from_buffer(sock, buffer);
    DEBUG_MESSAGE("recv_return_raw: Buffer: %p, buffer_index: %d, pending_recv: %d\n",
                  buffer, idx, sock->m_pending_recv);
	ret = xsk_ring_prod__reserve(&prog->m_umem[queue].fq, 1, &idx_fq);
    DEBUG_MESSAGE("Return into idx_fq: %d\n", idx_fq);
	if (ret != 1)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "recv_return_raw error returning %p (%d)", buffer, ret);
		return -1;
    }
    sock->m_pending_recv++;
    *xsk_ring_prod__fill_addr(&prog->m_umem[queue].fq, idx_fq) = idx * prog->m_max_frame_size;
	xsk_ring_prod__submit(&prog->m_umem[queue].fq, 1);
    return 0;
}


int xdp_recv(xdp_socket_t *sock, void **data, int *sz, struct sockaddr *sockaddr,
             socklen_t *addrlen)
{
	unsigned int rcvd;
	u32 idx_rx = 0;
	int ret;
    int was_recv = 0;
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;

    *data = NULL;
    *sz = 0;
    if (prog->m_send_only)
    {
        DEBUG_MESSAGE("ATTEMPT TO xdp_recv ON SEND_ONLY SOCKET!\n");
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "ATTEMPT TO xdp_recv ON SEND_ONLY SOCKET!");
        return -1;
    }
	while ((rcvd = xsk_ring_cons__peek(&sock->m_sock_info->rx, 1, &idx_rx)))
    {
        u64 addr = xsk_ring_cons__rx_desc(&sock->m_sock_info->rx, idx_rx)->addr;
        u32 len = xsk_ring_cons__rx_desc(&sock->m_sock_info->rx, idx_rx)->len;
        char *pkt = xsk_umem__get_data(prog->m_umem[queue].buffer, addr);
        xsk_ring_cons__release(&sock->m_sock_info->rx, rcvd);
        int res;
        int header_pos = 0;

        was_recv = 1;
        sock->m_pending_recv--;
        DEBUG_MESSAGE("Recv raw packet: Addr: %p, pending_recv: %d, idx_rx: %d\n"
                      "no_effect: %d\n", pkt, sock->m_pending_recv);
        traceBuffer(pkt, len);
        res = parse_recv_ip_hdr(sock, pkt, len, &header_pos, sockaddr, addrlen);
        if (res)
        {
            recv_return_raw(sock, pkt);
            continue;
        }
        res = parse_recv_udp_hdr(sock, pkt, &len, &header_pos, sockaddr);
        if (res)
        {
            recv_return_raw(sock, pkt);
            continue;
        }
        if (!sock->m_reqs->m_sendable)
            rebuild_header(sock->m_reqs, pkt, sockaddr);

        *data = (pkt + header_pos);
        *sz = len - header_pos;
        DEBUG_MESSAGE("recv, data: %p, buffer: %p\n", data, pkt);
        //traceBuffer(*data, *sz);

        return 1; // Something received.
    }
    return 0;
}

int xdp_recv_return(xdp_socket_t *sock, void *data)
{
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;
    void *buffer;

    if (prog->m_send_only)
    {
        DEBUG_MESSAGE("ATTEMPT TO xdp_recv_return ON SEND_ONLY SOCKET!\n");
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "ATTEMPT TO xdp_recv_return ON SEND_ONLY SOCKET!");
        return -1;
    }
	if (data < prog->m_umem[queue].buffer ||
        data >= prog->m_umem[queue].buffer + sock->m_tx_base * prog->m_max_frame_size)
    {
        DEBUG_MESSAGE("xdp_recv_return invalid buffer\n");
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xdp_recv_return invalid buffer (data: %p, buffer: %p)",
                 data, prog->m_umem[queue].buffer);
        return -1;
    }
    buffer = (void *)(((__u64)data / prog->m_max_frame_size) * prog->m_max_frame_size);
    DEBUG_MESSAGE("recv_return, data: %p, Addr: %p\n", data, buffer);
    recv_return_raw(sock, buffer);
    return 0;
}

int xdp_send_completed(xdp_socket_t *sock, int *still_pending)
{
    int ret;
    int released;
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;

    *still_pending = 0;
	if (sock->m_tx_outstanding)
    {
        ret = complete_tx_only(sock, &released);
        if (ret)
            return ret;
        *still_pending = sock->m_tx_outstanding;
    }
    return 0;
}

int xdp_add_ip_filter(xdp_socket_t *socket, struct ip_key *ipkey, int shard)
{
    int value = 0;//socket->m_sock_info->xsk;
    if (socket->m_filter_map == -1)
    {
        socket->m_filter_map = find_map_fd(socket, "ip_key_map");
        if (socket->m_filter_map == -1)
        {
            DEBUG_MESSAGE("xdp_add_ip_filter can't find map\n");
            snprintf(socket->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "xdp_add_ip_filter can't find map");
            return -1;
        }
    }
    DEBUG_MESSAGE("xdp_add_ip_filter, family: %d, addr: 0x%x\n", ipkey->family, ipkey->v4_addr);

    if (bpf_map_update_elem(socket->m_filter_map, ipkey, &value, 0) != 0)
    {
        int err = errno;
        DEBUG_MESSAGE("Can't add IP address to map: %s\n", strerror(err));
        snprintf(socket->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xdp_add_ip_filter Can't add IP address to map: %s",
                 strerror(err));
        return -1;
    }
    return 0;
}

void xdp_assign_shard(xdp_prog_t *prog, int shard)

{
    prog->m_shard = shard;
}

int xdp_get_shard(xdp_prog_t *prog)

{
    return prog->m_shard;
}

const char *xdp_get_last_error(xdp_prog_t *prog)
{
    return prog->m_err;
}


void xdp_change_in_port ( xdp_socket_t* sock, __u16 port )
{
    DEBUG_MESSAGE("xdp_change_in_port from %d to %d\n", sock->m_in_port, port);
    if (!port)
    {
        port = sock->m_in_port | __constant_htons(0x8000);
        DEBUG_MESSAGE("   Change to 0, so set high order on to 0x%x\n",
                      __constant_htons(port));
    }
    sock->m_in_port = port;
    sock->m_reqs->m_port = port;
}
