/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright(c) 2019 Intel Corporation.
 */

#ifndef XDPSOCK_H_
#define XDPSOCK_H_

#define MAX_IF  8

#define XDPSOCK_ETH_LEN 6
#define MAX_SOCKS       8

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

struct vlan_hdr_l {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

#define MAX_PACKET_HEADER_SIZE sizeof(struct ethhdr) + \
                               sizeof(struct vlan_hdr_l) * VLAN_MAX_DEPTH + \
                               sizeof(struct ipv6hdr) + \
                               sizeof(struct udphdr)

struct packet_rec
{
    /* Input to the lower layer */
    unsigned char   m_addr_set;
	unsigned char   m_ip4;
    struct in6_addr m_addr; /* u6_addr32[0] is used for v4 addresses, network order */
    __u16           m_port; /* Network order */
    /* Output from the lower layer */
    char            m_header[MAX_PACKET_HEADER_SIZE];
    __u16           m_header_size;
    __u16           m_ip_index;
};

/* USED FOR IP KEY MAP! */
struct ip_key {
    union {
        __u32 v4_addr;
        __u8 v6_addr[16];
    };
    __u8 family; // 2 for IPv4
};

#endif /* XDPSOCK_H */
