# Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 2.8)
SET(socketudprecv_STAT_SRCS
    socketudprecv.c
)

add_executable(socketudprecv
    ${socketudprecv_STAT_SRCS}
)


