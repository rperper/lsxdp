/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#ifndef __LSXDP_PRIVATE_H__
#define __LSXDP_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @file
 * private definitions not to be used outside of the API.
 *
 */

#define LSXDP_PRIVATE_MAX_ERR_LEN   256

#define BATCH_SIZE 64
#define MAX_SOCKS  16

#define DEBUG_HEXDUMP 0
#define MAC_LEN       6

#include "xdpsock.h"

typedef __u64 u64;
typedef __u32 u32;

#define MAX_PEEK   16

struct send_bufs_s;

/* One of these xsk_umem_info structures per send and receive queue */
/* See m_umem below and the queue number is the index into this array.  */
struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_socket *xsk;
};

struct xdp_prog_s;

typedef struct lsxdp_socket_reqs_s
{
    int                 m_ifindex;
    __u16               m_port;
    int                 m_sendable;
    char                m_mac[MAC_LEN];
    struct sockaddr_in  m_sa_in;
    struct packet_rec   m_rec;
} lsxdp_socket_reqs_t;

typedef  struct xdp_socket_s
{
    struct xdp_prog_s      *m_xdp_prog;
    struct xsk_socket_info *m_sock_info;
    lsxdp_socket_reqs_t    *m_reqs;
    int                     m_queue;
    __u32                   m_progid;
    int                     m_busy_send;
    int                     m_filter_map;
    __u16                   m_in_port;
    /* These are here because the memory is broken up by shard/queue (thus socket) */
    struct send_bufs_s     *m_send_bufs;
    int                     m_tx_base;
    int                     m_tx_max;
    int                     m_tx_count;
    int                     m_tx_last;
    int                     m_tx_outstanding;     // By network
    int                     m_tx_allocated;       // By application
    int                     m_pending_recv;
    void                   *m_last_send_buffer;
} xdp_socket_t;

typedef struct xdp_if_s
{
    int                     m_disable;
    char                    m_ifname[IF_NAMESIZE];
    struct bpf_object      *m_bpf_object;
    int                     m_bpf_prog_fd;
    int                     m_progfd;
    int                     m_socket_attached;
    char                    m_mac[MAC_LEN];
    struct sockaddr_in      m_sa_in;
    struct sockaddr_in6     m_sa_in6;
} xdp_if_t;

typedef struct xdp_prog_s
{
    int                     m_send_only;
    struct xsk_umem_info   *m_umem; // An array, by queue, set at prog_init (less than recv for virtio)
    char                    m_err[LSXDP_PRIVATE_MAX_ERR_LEN];
    int                     m_max_if;
    xdp_if_t                m_if[MAX_IF]; // ifindex is the index to this array - numbers start at 1 so 0 is meaningless
    xdp_socket_t           *m_xsks[MAX_SOCKS];
    int                     m_num_socks;
    int                     m_max_frame_size;
    int                     m_shards;
    int                     m_shard; // 0 for parent or only task.
    pid_t                   m_pid_parent;
    int                     m_ip2mac_fd;
    __u64                   m_max_memory;
    int                     m_max_frames; // To avoid redoing the math all of the time.
    int                     m_multi_queue;
    int                     m_max_queues;
    int                     m_virtio;
    int                     m_virtio_cpus;
    int                     m_send_shards;
    const char             *m_virtio_ifname;
    int                     m_hardware;
} xdp_prog_t;


#include "bpf_xdp.h"

#ifdef __cplusplus
}
#endif

#endif // __LSXDP_PRIVATE_H__
