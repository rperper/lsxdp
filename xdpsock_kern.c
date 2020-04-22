// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "parsing_helpers.h"
#include "xdpsock.h"

/* This XDP program is only needed for the XDP_SHARED_UMEM mode.
 * If you do not use this mode, libbpf can supply an XDP program for you.
 */

//#define USE_PRINTK
struct bpf_map_def SEC("maps") xsks_map = {
	.type        = BPF_MAP_TYPE_XSKMAP,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
	.max_entries = MAX_SOCKS,
};


SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    int h_proto;
	struct hdr_cursor nh;
    struct ethhdr *eth;
    struct iphdr  *iphdr;
    struct udphdr *udphdr;
    struct ip_key ipkey = { 0 };
    //int *ipkey_val = NULL;
    int af_xdp = 0;
	nh.pos = data;

	h_proto = parse_ethhdr(&nh, data_end, &eth);
    if (h_proto == bpf_htons(ETH_P_IP))
    {
   		int ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_UDP)
        {
			goto out;
        }
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6))
    {
		goto out;
    }
    else
    {
        goto out;
    }
  	if (parse_udphdr(&nh, data_end, &udphdr) == -1)
    {
        goto out;
    }
#ifdef USE_PRINTK
    bpf_printk("sock_prog IP source: %u.%u",
               ((unsigned char *)&iphdr->saddr)[0],
               ((unsigned char *)&iphdr->saddr)[1]);
    bpf_printk("  .%u.%u\n",
               ((unsigned char *)&iphdr->saddr)[2],
               ((unsigned char *)&iphdr->saddr)[3]);
    bpf_printk("sock_prog ports: %d %d\n", bpf_htons(udphdr->source),
               bpf_htons(udphdr->dest));
#endif
    af_xdp = 1;
out:
    if (!af_xdp)
        goto no_xdp;

    if (h_proto == bpf_htons(ETH_P_IP))
    {
        ipkey.family = 2;//AF_INET;
        ipkey.v4_addr = iphdr->saddr;
    }
    else
    {
#ifdef USE_PRINTK
        bpf_printk("Only IPv4 support so far.  Drop\n");
#endif
        return XDP_DROP;
    }
    /*
	ipkey_val = bpf_map_lookup_elem(&ip_key_map, &ipkey);
    if (!ipkey_val)
    {
        return XDP_DROP;
    }
    */
#ifdef USE_PRINTK
    bpf_printk("UDP, index: %d\n", index);
#endif
    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &index))
    {
#ifdef USE_PRINTK
        bpf_printk("IS AN AF_XDP SOCKET!\n");
#endif
        return bpf_redirect_map(&xsks_map, index, 0);
    }
#ifdef USE_PRINTK
    bpf_printk("NOT AN AF_XDP SOCKET!\n");
#endif

no_xdp:

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; // Required to use bpf_printk

