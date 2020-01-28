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

typedef _struct xdp_prog_s 
{
    char  m_err[LSXDP_PRIVATE_MAX_ERR_LEN];
    void *m_bufs;
} xdp_prog_t;

typedef  struct xdp_socket_s
{
    xdp_prog_t  *m_xdp_prog;
} xdp_socket_t;

#ifdef __cplusplus
}
#endif

#endif // __LSXDP_PRIVATE_H__
