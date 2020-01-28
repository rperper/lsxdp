/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#ifndef __LSXDP_H__
#define __LSXDP_H__

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @file
 * public API for using lsxdp is defined in this file.
 *
 */
#include "lsxdp_private.h"

xdp_prog xdp_prog_init(char *prog_init_err, int prog_init_err_len);
xdp_socket xdp_socket(xdp_prog prog)

#ifdef __cplusplus
}
#endif

#endif // __LSXDP_H__
