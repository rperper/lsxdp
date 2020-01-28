/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#include <sys/resource.h>
#include <sys/time.h>

#include "lsxdp.h"

xdp_prog xdp_prog_init(char *prog_init_err, int prog_init_err_len)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct xsk_umem_info *umem;
    int ret;

    if (setrlimit(RLIMIT_MEMLOCK, &r)) 
    {
        snprintf(prog_init_err, prog_init_err_len, "setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", 
                 strerror(errno));
        return NULL;
    }


}

