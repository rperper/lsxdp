/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright(c) 2019 Intel Corporation.
 */

#ifndef XDPSOCK_H_
#define XDPSOCK_H_

#define MAX_IF  8

#define XDPSOCK_ETH_LEN 6
#define MAX_SOCKS       8

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
    char            m_header[MAX_PACKET_HEADER_SIZE];
    int             m_header_size;
    int             m_ip_index;
	unsigned char   m_ip4;
};

#endif /* XDPSOCK_H */
