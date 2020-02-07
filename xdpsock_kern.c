// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "parsing_helpers.h"
#include "xdpsock.h"

/* This XDP program is only needed for the XDP_SHARED_UMEM mode.
 * If you do not use this mode, libbpf can supply an XDP program for you.
 */

struct bpf_map_def SEC("maps") xsks_map = {
	.type        = BPF_MAP_TYPE_XSKMAP,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
	.max_entries = MAX_SOCKS,
};


static unsigned int rr;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	rr = (rr + 1) & (MAX_SOCKS - 1);

	return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}

/* NEVER FORGET THAT eBPF ONLY SUPPORTS UNROLLED STATIC SIZED LOOPS!!! */
/* NO memcpy EXCEPT FOR SPECIFIC SIZES!!! */
/* Use this instead, requires a label of 'out:' to goto if an error */
/* NOPE, just doesn't work.  The verifier gets near it and just stops
 * with a message 'R5 !read_ok'.  So forget it.  Now just copy everything
 * element by element */
/*
#define STATIC_MEMCPY(name, src_end, dest_end, dest, src, len)      \
    {                                                               \
        char *cpdest = (char *)dest;                                \
        char *cpsrc = (char *)src;                                  \
        int i;                                                      \
        if (cpsrc + len >= (char *)src_end)                         \
        {                                                           \
            bpf_printk(#name "_memcpy, source out of range\n");     \
            goto out;                                               \
        }                                                           \
        if (cpdest + len >= (char *)dest_end)                       \
        {                                                           \
            bpf_printk(#name "_memcpy, dest out of range");         \
            goto out;                                               \
        }                                                           \
        _Pragma("unroll")                                           \
        for (i = 0; i < len; i++)                                   \
            *(cpdest + i) = *(cpsrc + i);                           \
    }
*/
struct bpf_map_def SEC("maps") packet_rec_def = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(struct packet_rec),
	.max_entries = MAX_IF,
};


struct ethhdr_simple
{
    __u32 dest_addr1;
    __u16 dest_addr2;
    __u32 src_addr1;
    __u16 src_addr2;
	__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));

static __always_inline int copy_ethhdr(void *src_end, void *dest_end,
                                       struct ethhdr_simple *dest,
                                       struct ethhdr_simple *src)
{
    char *cpdest = (char *)dest;
    char *cpsrc = (char *)src;
    if (cpsrc + sizeof(struct ethhdr_simple) >= (char *)src_end)
    {
        bpf_printk("copy_ethhdr, source out of range\n");
        return -1;
    }
    if (cpdest + sizeof(struct ethhdr_simple) >= (char *)dest_end)
    {
        bpf_printk("copy_ethhdr, dest out of range\n");
        return -1;
    }
    dest->dest_addr1 = src->src_addr1;
    dest->dest_addr2 = src->src_addr2;
    dest->src_addr1 = src->dest_addr1;
    dest->src_addr2 = src->dest_addr2;
    dest->h_proto = src->h_proto;
    return 0;
}

/*
struct ipv6hdr_simple
{
    __u64 prefix;
    __u64 src_addr1;
    __u64 src_addr2;
    __u64 dest_addr1;
    __u64 dest_addr2;
} __attribute__((packed));

static __always_inline int copy_ipv6(void *src_end, void *dest_end,
                                     struct ipv6hdr_simple *dest,
                                     struct ipv6hdr_simple *src)
{
    if ((char *)src + sizeof(struct ipv6hdr_simple) >= (char *)src_end)
    {
        bpf_printk("copy_ipv6, source out of range\n");
        return -1;
    }
    if ((char *)dest + sizeof(struct ipv6hdr_simple) >= (char *)dest_end)
    {
        bpf_printk("copy_ipv6, dest out of range\n");
        return -1;
    }
    dest->prefix = src->prefix;
    dest->src_addr1 = src->dest_addr1;
    dest->src_addr2 = src->dest_addr2;
    dest->dest_addr1 = src->src_addr1;
    dest->dest_addr2 = src->src_addr2;
    return 0;
}
*/

struct iphdr_simple
{
    __u64 prefix1;
    __u32 prefix2;
    __u32 src_addr;
    __u32 dest_addr;
} __attribute__((packed));

static __always_inline int copy_ipv4(void *src_end, void *dest_end,
                                     struct iphdr_simple *dest,
                                     struct iphdr_simple *src)
{
    if ((char *)src + sizeof(struct iphdr_simple) >= (char *)src_end)
    {
        bpf_printk("copy_ipv4, source out of range\n");
        return -1;
    }
    if ((char *)dest + sizeof(struct iphdr_simple) >= (char *)dest_end)
    {
        bpf_printk("copy_ipv4, dest out of range\n");
        return -1;
    }
    dest->prefix1 = src->prefix1;
    dest->prefix2 = src->prefix2;
    dest->src_addr = src->dest_addr;
    dest->dest_addr = src->src_addr;
    return 0;
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
    struct iphdr *iphdr = NULL;
    struct tcphdr  *tcphdr;
    int ip_index;
    void *map_end;
    int ipv4 = 0;

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

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	h_proto = parse_ethhdr(&nh, data_end, &eth);
    ip_index = (int)((char *)nh.pos - (char *)data);
    if (h_proto == bpf_htons(ETH_P_IP))
    {
        ipv4 = 1;
   		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_TCP)
        {
            bpf_printk("xdp_ping_func IP NOT TCP: %d\n", ip_type);
			goto out;
        }
        else
        {
            bpf_printk("xdp_ping_func IP dest: %u.%u",
                       ((unsigned char *)&iphdr->saddr)[0],
                       ((unsigned char *)&iphdr->saddr)[1]);
            bpf_printk("  .%u.%u\n",
                       ((unsigned char *)&iphdr->saddr)[2],
                       ((unsigned char *)&iphdr->saddr)[3]);
        }
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6))
    {
  		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_TCP)
        {
            bpf_printk("xdp_ping_func IPv6 NOT TCP: %d\n", ip_type);
			goto out;
        }
    }
    else
    {
        bpf_printk("parse_ethhdr failed proto: %d\n", bpf_htons(h_proto));
        goto out;
    }
    if (ip_index < 0 ||
        ip_index >= MAX_PACKET_HEADER_SIZE - sizeof(struct ipv6hdr) - sizeof(struct udphdr))
    {
        bpf_printk("xdp_ping_func ip_index OUT OF RANGE: %d\n", ip_index);
        goto out;
    }
    header_end = nh.pos;
  	icmp_type = parse_tcphdr(&nh, data_end, &tcphdr);
    if (icmp_type == -1)
    {
        bpf_printk("parse_tcphdr failed\n");
        goto out;
    }
    // Copy what we need and fix what we can
	rec = bpf_map_lookup_elem(&packet_rec_def, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup XDP_PASS always will succeed.
	 */
	if (!rec)
    {
        bpf_printk("xdp_ping_func map entry not found\n");
        goto out;
    }
	if (!rec->m_addr_set)
    {
        bpf_printk("xdp_ping_func map address not set yet\n");
        goto out;
    }
    if ((rec->m_ip4 && h_proto == bpf_htons(ETH_P_IPV6)) ||
        (!rec->m_ip4 && h_proto != bpf_htons(ETH_P_IPV6)))
    {
        bpf_printk("xdp_ping_func map address wrong IP type\n");
        goto out;
    }
    if (ipv4)
    {
        if (iphdr->saddr != rec->m_addr.in6_u.u6_addr32[0])
        {
            bpf_printk("xdp_ping_func map address wrong IP addr %u.%u",
                       ((unsigned char *)&rec->m_addr.in6_u.u6_addr32[0])[0],
                       ((unsigned char *)&rec->m_addr.in6_u.u6_addr32[0])[1]);
            bpf_printk("  .%u.%u",
                       ((unsigned char *)&rec->m_addr.in6_u.u6_addr32[0])[2],
                       ((unsigned char *)&rec->m_addr.in6_u.u6_addr32[0])[3]);
            goto out;
        }
    }
    else
    {
        bpf_printk("xdp_ping_func ignore IPv6 for now\n");
        goto out;
    }
    if (tcphdr->source != rec->m_port)
    {
        bpf_printk("xdp_ping_func wrong port %d\n", tcphdr->source);
        goto out;
    }
    rec->m_header_size = (int)(header_end - data);
    map_end = (void *)((char *)rec + sizeof(struct packet_rec));
    bpf_printk("Copy the ethernet header\n");
    if (copy_ethhdr(data_end, map_end, (struct ethhdr_simple *)rec->m_header,
                     (struct ethhdr_simple *)eth) == -1)
        goto out;
    rec->m_ip_index = ip_index;
    //if (h_proto == bpf_htons(ETH_P_IPV6))
    if (!ipv4)
    {
        bpf_printk("xdp_ping_func ignore IPv6 for now\n");
        goto out;
        /*
        struct ipv6hdr_simple *map_ipv6hdr;
        rec->m_ip4 = 0;
        map_ipv6hdr = (struct ipv6hdr_simple *)(rec->m_header + sizeof(struct ethhdr));
        if (copy_ipv6(data_end, map_end, map_ipv6hdr,
                      (struct ipv6hdr_simple *)ipv6hdr) == -1)
            goto out;
        */
    }
    else
    {
        struct iphdr_simple *map_iphdr;
        rec->m_ip4 = 1;
        map_iphdr = (struct iphdr_simple *)(rec->m_header + sizeof(struct ethhdr));
        bpf_printk("Copy the IPv4 header\n");
        if (!iphdr)
        {
            bpf_printk("xdp_ping_func UNEXPECTED UNINITIALIZED iphdr\n");
            goto out;
        }
        if (copy_ipv4(data_end, map_end, map_iphdr,
                      (struct iphdr_simple *)iphdr) == -1)
            goto out;
    }
    action = XDP_PASS;
    bpf_printk("xdp_ping_func SUCCESS!!!\n");
out:

    return action;
}


char _license[] SEC("license") = "GPL"; // Required to use bpf_printk

