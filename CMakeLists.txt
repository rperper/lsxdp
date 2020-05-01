# Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 2.8)

SET(lsxdp_STAT_SRCS
    lsxdp.c
    bpf_xdp.c
    ip2mac.c
    sendbufs.c
    virtio_info.c
)

SET(libbpf_STAT_OBJS
    libbpf/src/staticobjs/bpf.o
    libbpf/src/staticobjs/bpf_prog_linfo.o
    libbpf/src/staticobjs/btf_dump.o
    libbpf/src/staticobjs/btf.o
    libbpf/src/staticobjs/hashmap.o
    libbpf/src/staticobjs/libbpf_errno.o
    libbpf/src/staticobjs/libbpf.o
    libbpf/src/staticobjs/libbpf_probes.o
    libbpf/src/staticobjs/netlink.o
    libbpf/src/staticobjs/nlattr.o
    libbpf/src/staticobjs/str_error.o
    libbpf/src/staticobjs/xsk.o
)

add_custom_target(xdp_sock_kern ALL
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMAND clang -S -O2 -target bpf -D __BPF_TRACING__ -I headers -I libbpf/src -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -emit-llvm -c -g xdpsock_kern.c -o xdpsock_kern.ll
    COMMAND llc -march=bpf -filetype=obj xdpsock_kern.ll -o xdpsock_kern.o
)

include_directories(libbpf)
include_directories(libbpf/src)
include_directories(libbpf/include/uapi)

add_library(lsxdp STATIC ${lsxdp_STAT_SRCS} ${libbpf_STAT_OBJS})
#add_library(lsxdp STATIC ${lsxdp_STAT_SRCS})


