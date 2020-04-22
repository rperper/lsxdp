/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#ifndef __SendBufs__
#define __SendBufs__

#ifdef __cplusplus
extern "C" {
#endif

/* For now, this is a bit map of the size m_tx_max */
typedef struct send_bufs_s
{
    union
    {
        unsigned char   m_cbuf[8];
        unsigned short  m_sbuf[4];
        unsigned int    m_ibuf[2];
        unsigned long   m_lbuf[1];
    };
} send_bufs_t;

int send_bufs_init(xdp_socket_t *sock);
int send_bufs_get_one_free(xdp_socket_t *sock, int *index);
int send_bufs_freed_one(xdp_socket_t *sock, int index);
void send_bufs_done(xdp_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif
