# Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE.
SET(lsxdp_STAT_SRCS
    lsxdp.c
)

include_directories(libbpf)

add_library(lsxdp STATIC ${lsxdp_STAT_SRCS} )

