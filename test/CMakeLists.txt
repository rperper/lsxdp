# Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 2.8)
SET(testxdp_STAT_SRCS
    testxdp.c
)

set (libs lsxdp elf z)
include_directories(libbpf)
include_directories(libbpf/src)
include_directories(libbpf/include/uapi)

add_executable(testxdp
    ${testxdp_STAT_SRCS}
)

set (lib_path ".")
find_library(${libs} NAMES ${libs})
target_link_libraries(testxdp ${libs} -L${CMAKE_CURRENT_SOURCE_DIR} -L${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src)

