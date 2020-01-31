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

#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64
#define MAX_SOCKS  8

#define DEBUG_HEXDUMP 0

#include "xdpsock.h"

typedef __u64 u64;
typedef __u32 u32;

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_npkts;
	u32 outstanding_tx;
};

struct xdp_prog_s;

typedef struct lsxdp_socket_reqs_s
{
    int               m_ifindex;
    __u16             m_port;
    struct packet_rec m_rec;
} lsxdp_socket_reqs_t;

typedef  struct xdp_socket_s
{
    struct xdp_prog_s      *m_xdp_prog;
    struct xsk_umem_info    m_umem;
    struct xsk_socket_info  m_sock_info;
    lsxdp_socket_reqs_t    *m_reqs;
    int                     m_queue;
    __u32                   m_progid;
    __u32                   m_last_tx_index_gotten;
    void                   *m_last_tx_buffer_gotten;
    int                     m_last_tx_frame_size;
} xdp_socket_t;

typedef struct xdp_if_s
{
    char                    m_ifname[IF_NAMESIZE];
    struct bpf_object      *m_bpf_object;
    int                     m_bpf_prog_fd;
    int                     m_progfd;
} xdp_if_t;

typedef struct xdp_prog_s
{
    char                    m_err[LSXDP_PRIVATE_MAX_ERR_LEN];
    int                     m_max_if;
    xdp_if_t                m_if[MAX_IF]; // ifindex is the index to this array - numbers start at 1 so 0 is meaningless
    xdp_socket_t           *m_xsks[MAX_SOCKS];
    int                     m_num_socks;
    void                   *m_bufs;
    int                     m_max_frame_size;
} xdp_prog_t;

#include "bpf_xdp.h"

#ifdef __cplusplus
}
#endif

#endif // __LSXDP_PRIVATE_H__
