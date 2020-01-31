// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "parsing_helpers.h"
#include "xdpsock.h"

/* This XDP program is only needed for the XDP_SHARED_UMEM mode.
 * If you do not use this mode, libbpf can supply an XDP program for you.
 */

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_IF);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct packet_rec));
} packet_rec_def SEC(".maps");


static unsigned int rr;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	rr = (rr + 1) & (MAX_SOCKS - 1);

	return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}

static __always_inline void my_memcpy(void *dest, void *src, int len)
{
    char *cpdest = (char *)dest;
    char *cpsrc = (char *)src;
    while (len)
    {
        *cpdest = *cpsrc;
        ++cpdest;
        ++cpsrc;
    }
}

SEC("xdp_ping") int xdp_ping_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    int key = 0;
    struct packet_rec *rec;
    int h_proto;
	struct ethhdr *eth;
    struct ipv6hdr *ipv6hdr;
    struct iphdr *iphdr;
    struct icmphdr_common  *icmphdr;
    int ip_index;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */
        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
    int ip_type;
    int icmp_type;
    void *header_end;

	rec = bpf_map_lookup_elem(&packet_rec_def, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup XDP_PASS always will succeed.
	 */
	if (!rec)
    {
        bpf_printk("xdp_ping_func map entry not found");
        goto out;
    }
	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	h_proto = parse_ethhdr(&nh, data_end, &eth);
    ip_index = (int)(nh.pos - data);
    if (h_proto == bpf_htons(ETH_P_IP))
    {
   		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
        {
            bpf_printk("xdp_ping_func IP NOT ICMP: %d", ip_type);
			goto out;
        }
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6))
    {
  		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
        {
            bpf_printk("xdp_ping_func IPv6 NOT ICMPv6: %d", ip_type);
			goto out;
        }
    }
    else
    {
        bpf_printk("parse_ethhdr failed\n");
        goto out;
    }
    header_end = nh.pos;
  	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
    if (icmp_type == -1)
    {
        bpf_printk("parse_icmphdr_common failed\n");
        goto out;
    }
    // Copy what we need and fix what we can
    rec->m_header_size = (int)(header_end - data);
    my_memcpy(rec->m_header, data, rec->m_header_size);
    my_memcpy(((struct ethhdr *)rec->m_header)->h_source, eth->h_dest, sizeof(eth->h_source));
    my_memcpy(((struct ethhdr *)rec->m_header)->h_dest, eth->h_source, sizeof(eth->h_source));
    rec->m_ip_index = ip_index;
    if (h_proto == bpf_htons(ETH_P_IPV6))
    {
        rec->m_ip4 = 0;
        my_memcpy(&((struct ipv6hdr *)(rec->m_header + ip_index))->saddr,
                  &ipv6hdr->daddr, sizeof(struct in6_addr));
        my_memcpy(&((struct ipv6hdr *)(rec->m_header + ip_index))->daddr,
                  &ipv6hdr->saddr, sizeof(struct in6_addr));
    }
    else
    {
        rec->m_ip4 = 1;
        ((struct iphdr *)(rec->m_header + ip_index))->saddr = ((struct iphdr *)(rec->m_header + ip_index))->daddr;
        ((struct iphdr *)(rec->m_header + ip_index))->daddr = ((struct iphdr *)(rec->m_header + ip_index))->saddr;
    }
	action = XDP_PASS;
out:

    return action;
}
