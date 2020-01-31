/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#include "lsxdp.h"

#include "poll.h"
#include <linux/if_ether.h>
#include "linux/in.h"
#include "linux/icmp.h"

#define PING_PKT_S 64

// ping packet structure
struct ping_pkt
{
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};

static u32 opt_xdp_flags = /* XDP_FLAGS_UPDATE_IF_NOEXIST | // Does a force if not set */
                           /* XDP_FLAGS_SKB_MODE | // Generice or emulated (slow) */
                           XDP_FLAGS_DRV_MODE | // Native XDP mode
                           XDP_FLAGS_HW_MODE;   // Hardware offload
static __u16 opt_xdp_bind_flags = /* XDP_SHARED_UMEM | //? */
                                  /* XDP_COPY | // Force copy mode */
                                  /* XDP_ZEROCOPY | // Force zero copy */
                                  XDP_USE_NEED_WAKEUP;// For same cpu for force yield

static int xsk_configure_umem(void *buffer, xdp_socket_t *sock, u64 size)
{
	struct xsk_umem_config cfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = sock->m_xdp_prog->m_max_frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	};
	int ret;

	ret = xsk_umem__create(&sock->m_umem.umem, buffer, size, &sock->m_umem.fq,
                           &sock->m_umem.cq, &cfg);
	if (ret)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xsk_umem__create error %s", strerror(-ret));
        return -1;
    }
	sock->m_umem.buffer = buffer;
	return 0;
}

static int xsk_configure_socket(xdp_socket_t *sock)
{
	struct xsk_socket_config cfg;
	int ret;
	u32 idx;
	int i;

    sock->m_sock_info.umem = &sock->m_umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;
	ret = xsk_socket__create(&sock->m_sock_info.xsk,
                             sock->m_xdp_prog->m_if[sock->m_reqs->m_ifindex].m_ifname,
                             sock->m_queue, sock->m_umem.umem,
                             &sock->m_sock_info.rx, &sock->m_sock_info.tx, &cfg);
	if (ret)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xsk_socket__create error %s", strerror(-ret));
        return -1;
    }
	ret = bpf_get_link_xdp_id(sock->m_reqs->m_ifindex, &sock->m_progid,
                              opt_xdp_flags);
	if (ret)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "bpf_get_link_xdp_id error %s", strerror(-ret));
		return -1;
    }

	ret = xsk_ring_prod__reserve(&sock->m_umem.fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xsk_ring_prod__reserve error %s", strerror(-ret));
		return -1;
    }
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&sock->m_sock_info.umem->fq, idx++) =
			i * sock->m_xdp_prog->m_max_frame_size;
	xsk_ring_prod__submit(&sock->m_umem.fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

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
        ++index;
        if (names[index].if_index > prog->m_max_if)
            prog->m_max_if = names[index].if_index;
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
    prog->m_max_frame_size = max_frame_size;
    if (get_ifs(prog_init_err, prog_init_err_len, prog))
    {
        xdp_prog_done(prog);
        return NULL;
    }
    if (max_frame_size <= 0 || max_frame_size > LSXDP_MAX_FRAME_SIZE)
    {
        snprintf(prog_init_err, prog_init_err_len,
                 "Invalid max frame size must be <= %d", LSXDP_MAX_FRAME_SIZE);
        xdp_prog_done(prog);
        return NULL;
    }
	ret = posix_memalign(&prog->m_bufs, getpagesize(), /* PAGE_SIZE aligned */
			             NUM_FRAMES * max_frame_size);
    if (ret)
    {
        snprintf(prog_init_err, prog_init_err_len,
                 "Insufficient memory allocating big buffer: %s", strerror(errno));
        xdp_prog_done(prog);
        return NULL;
    }
    return prog;
}

void xdp_socket_close ( xdp_socket_t* socket )
{
    if (!socket)
        return;
    //if (socket->m_xdp_prog->m_bpf_prog_fd)
    //    xdp_link_detach(socket, socket->m_ifindex, opt_xdp_flags, 0);

    if (socket->m_sock_info.xsk)
        xsk_socket__delete(socket->m_sock_info.xsk);
    if (socket->m_umem.umem)
        xsk_umem__delete(socket->m_umem.umem);
    socket->m_xdp_prog->m_num_socks--;
    free(socket);
}

xdp_socket_t *xdp_socket(xdp_prog_t *prog, lsxdp_socket_reqs_t *reqs)
{
    xdp_socket_t *socket;

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
    prog->m_num_socks++;
	if (xsk_configure_umem(prog->m_bufs, socket,
                           NUM_FRAMES * prog->m_max_frame_size))
    {
        xdp_socket_close(socket);
        return NULL;
    }
	if (xsk_configure_socket(socket))
    {
        xdp_socket_close(socket);
        return NULL;
    }
    prog->m_xsks[prog->m_num_socks] = socket;
}

static int load_obj(xdp_prog_t *prog)
{
	int err;
	struct bpf_program *bpf_prog;
    int i;

    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (!prog->m_if[i].m_ifname[0])
            continue;
        if (prog->m_if[i].m_bpf_object)
            return 0; // Already done!
        struct bpf_prog_load_attr prog_load_attr =
        {
            .prog_type	= BPF_PROG_TYPE_XDP,
            .ifindex	= i,
        };
        prog_load_attr.file = "xdpsock_kern.o";

        /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
         * loading this into the kernel via bpf-syscall */
        err = bpf_prog_load_xattr(&prog_load_attr, &prog->m_if[i].m_bpf_object,
                                  &prog->m_if[i].m_bpf_prog_fd);
        if (err)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Error loading BPF-OBJ file(%s) (%d): %s",
                     prog_load_attr.file, err, strerror(-err));
            return -1;
        }
        /* Find a matching BPF prog section name */
        const char *prog_sec = "xdp_ping";
        bpf_prog = bpf_object__find_program_by_title(prog->m_if[i].m_bpf_object,
                                                     prog_sec);
        if (!bpf_prog)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "ERR: finding progsec: %s\n", prog_sec);
		    return -1;
	    }

        prog->m_if[i].m_progfd = bpf_program__fd(bpf_prog);
        if (prog->m_if[i].m_progfd <= 0)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "ERR: bpf_program__fd failed");
            return -1;
	    }

        err = xdp_link_attach(prog, i, opt_xdp_flags, prog->m_if[i].m_progfd);
        if (err)
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

static int send_icmp(xdp_prog_t *prog, const struct sockaddr *addr,
                     socklen_t addrLen)
{
    int sockfd;
    struct timeval tv_out;
    struct ping_pkt ping;
    int i;
    int ret = 0;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Error creating raw socket to get socket requirements: %s",
                 strerror(errno));
        return -1;
    }
    tv_out.tv_sec = 5;
    tv_out.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out,
               sizeof tv_out);
    memset(&ping, 0, sizeof(ping));
    ping.hdr.type = ICMP_ECHO;
    ping.hdr.un.echo.id = getpid();
    for ( i = 0; i < sizeof(ping.msg)-1; i++ )
        ping.msg[i] = i+'0';
    ping.msg[i] = 0;
    ping.hdr.un.echo.sequence = 0;
    ping.hdr.checksum = checksum(&ping, sizeof(ping));
    ret = sendto(sockfd, &ping, sizeof(ping), 0, addr, addrLen);
    if (ret <= 0)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Error sending ping to remote system: %s", strerror(errno));
        ret = -1;
    }
    if (ret >= 0)
    {
        struct sockaddr r_addr;
        socklen_t addr_len;
        ret = recvfrom(sockfd, &ping, sizeof(ping), 0, &r_addr, &addr_len);
        if (ret <= 0)
        {
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Error receiving ping response from remote system: %s",
                     strerror(errno));
            ret = -1;
        }
    }
    if (ret >= 0)
        ret = 0;
    close(sockfd);
    return ret;
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

static lsxdp_socket_reqs_t *check_map(xdp_prog_t *prog,
                                      const struct sockaddr *addr,
                                      socklen_t addrLen)
{
    int i;
    struct packet_rec rec;
    int found = 0;
    lsxdp_socket_reqs_t *reqs;

    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (prog->m_if[i].m_bpf_object)
        {
            int map_fd;
            int key = 0; // Separate maps for each IF for now, all with key 0
            map_fd = find_map_fd(prog, prog->m_if[i].m_bpf_object,
                                 "packet_rec_def");
            if (map_fd == -1)
                return NULL;
            if (((bpf_map_lookup_elem(map_fd, &key, &rec)) != 0) &&
                (rec.m_ip4 &&
                 ((struct iphdr *)&rec.m_header[rec.m_ip_index])->saddr == ((struct sockaddr_in *)addr)->sin_addr.s_addr))
            {
                found = 1;
                break;
            }
        }
    }
    if (!found)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Can not find map entry for successful ping");
        return NULL;
    }
    reqs = malloc(sizeof(lsxdp_socket_reqs_t));
    if (!reqs)
    {
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Insufficient memory to allocate required data");
        return NULL;
    }
    reqs->m_ifindex = i;
    reqs->m_port = ((struct sockaddr_in *)addr)->sin_port;
    memcpy(&reqs->m_rec, &rec, sizeof(rec));
    return reqs;
}

lsxdp_socket_reqs_t *xdp_get_socket_reqs(xdp_prog_t *prog,
                                         const struct sockaddr *addr,
                                         socklen_t addrLen)
{
    lsxdp_socket_reqs_t *reqs;

    if (load_obj(prog))
        return NULL;
    if (send_icmp(prog, addr, addrLen))
        return NULL;
    reqs = check_map(prog, addr, addrLen);
    if (!reqs)
        return NULL;
    return reqs;
}

void xdp_prog_done ( xdp_prog_t* prog )
{
    int i;
    if (!prog)
        return;
    for (i = 1; i <= prog->m_max_if; ++i)
    {
        if (prog->m_if[i].m_progfd)
            xdp_link_detach(prog, i, opt_xdp_flags, prog->m_if[i].m_progfd);
    }
    if (prog->m_num_socks)
        fprintf(stderr, "%d Sockets remain open!\n", prog->m_num_socks);
    if (prog->m_bufs)
        free(prog->m_bufs);
    free(prog);
}

int xdp_get_poll_fd(xdp_socket_t *sock)
{
    return xsk_socket__fd(sock->m_sock_info.xsk);
}

static int kick_tx(xdp_socket_t *sock)
{
	int ret;

	ret = sendto(xsk_socket__fd(sock->m_sock_info.xsk), NULL, 0, MSG_DONTWAIT,
                 NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
		return 0;
    snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
             "Error in send: %s", strerror(errno));
    return -1;
}

static inline int complete_tx_only(xdp_socket_t *sock)
{
	unsigned int rcvd;
	u32 idx;

	if (!sock->m_sock_info.outstanding_tx)
		return 0;

	if (kick_tx(sock))
        return -1;

	rcvd = xsk_ring_cons__peek(&sock->m_umem.cq, BATCH_SIZE, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&sock->m_umem.cq, rcvd);
		sock->m_sock_info.outstanding_tx -= rcvd;
		sock->m_sock_info.tx_npkts += rcvd;
	}
	return 0;
}

static int tx_only(xdp_socket_t *sock)
{
    struct xdp_desc *desc;
	desc = xsk_ring_prod__tx_desc(&sock->m_sock_info.tx, sock->m_last_tx_index_gotten);
    desc->addr = sock->m_last_tx_frame_size * sock->m_xdp_prog->m_max_frame_size;
    desc->len = sock->m_last_tx_frame_size;

	xsk_ring_prod__submit(&sock->m_sock_info.tx, sock->m_last_tx_frame_size);
    sock->m_sock_info.outstanding_tx += sock->m_last_tx_frame_size;
    sock->m_last_tx_buffer_gotten = NULL;
    sock->m_last_tx_frame_size = 0;
    sock->m_last_tx_index_gotten = 0;
    if (complete_tx_only(sock))
        return -1;
    return 0;
}

void *xdp_get_send_buffer(xdp_socket_t *sock)
{
    /* The key is the number of outstanding_tx packets.  If it's >=
     * NUM_FRAMES, we need to kick the sender to get them out. */
    if (sock->m_sock_info.outstanding_tx >= NUM_FRAMES * sock->m_xdp_prog->m_max_frame_size &&
        complete_tx_only(sock))
        return NULL; // Error already in buffer
    if (sock->m_sock_info.outstanding_tx >= NUM_FRAMES * sock->m_xdp_prog->m_max_frame_size)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "All packets still outstanding.  Do a poll first");
        return NULL;
    }
    if (xsk_ring_prod__reserve(&sock->m_sock_info.tx,
                               sock->m_xdp_prog->m_max_frame_size,
                               &sock->m_last_tx_index_gotten) == sock->m_xdp_prog->m_max_frame_size)
        sock->m_last_tx_buffer_gotten =
            xsk_umem__get_data(sock->m_umem.umem,
                               sock->m_last_tx_index_gotten * sock->m_xdp_prog->m_max_frame_size);
    else
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Unable to reserve a packet for a full frame size.  Poll?");
        return NULL;
    }
    return sock->m_last_tx_buffer_gotten;
}

int xdp_send(xdp_socket_t *sock, void *data, int len)
{
    int headroom = xdp_send_udp_headroom(sock);
    char *send_buffer;
    char *data_char = data;
    if (sock->m_last_tx_buffer_gotten &&
        sock->m_last_tx_buffer_gotten + headroom == data_char)
        // Already using a buffer gotten - assume data is already copied to it
        send_buffer = sock->m_last_tx_buffer_gotten;
    else
    {
        send_buffer = xdp_get_send_buffer(sock);
        if (!send_buffer)
            return -1;

        memcpy(send_buffer + headroom, data, len);
    }
    return xdp_send_zc(sock, send_buffer, len);
}

int xdp_send_zc(xdp_socket_t *sock, void *buffer, int len)
{
    int ip_index;
    struct udphdr *udphdr;
    int headroom = xdp_send_udp_headroom(sock);
    if (buffer != sock->m_last_tx_buffer_gotten)
    {
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "Require that the packet be acquired with a xdp_get_send_buffer()"
                 " or a call to xdp_send()");
        return -1;
    }
    ip_index = sock->m_reqs->m_rec.m_ip_index;
    if (sock->m_reqs->m_rec.m_ip4)
    {
        struct iphdr *iphdr = (struct iphdr *)&sock->m_reqs->m_rec.m_header[ip_index];
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
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)&sock->m_reqs->m_rec.m_header[ip_index];
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
    sock->m_last_tx_frame_size = headroom + len;
    return tx_only(sock);
}

int xdp_send_udp_headroom(xdp_socket_t *sock)
{
    return sock->m_reqs->m_rec.m_header_size;
}
