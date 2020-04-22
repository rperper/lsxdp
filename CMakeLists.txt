# Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 2.8)

SET(lsxdp_STAT_SRCS
    lsxdp.c
    bpf_xdp.c
    ip2mac.c
    sendbufs.c
    virtio_info.c
)

add_custom_target(xdp_sock_kern ALL
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMAND clang -S -O2 -target bpf -D __BPF_TRACING__ -I headers -I libbpf/src -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -emit-llvm -c -g xdpsock_kern.c -o xdpsock_kern.ll
    COMMAND llc -march=bpf -filetype=obj xdpsock_kern.ll -o xdpsock_kern.o
)

include_directories(libbpf)
include_directories(libbpf/src)
include_directories(libbpf/include/uapi)

add_library(lsxdp STATIC ${lsxdp_STAT_SRCS} )

