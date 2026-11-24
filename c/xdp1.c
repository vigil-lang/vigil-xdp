/* § 5.2.1: xdp1_kern.c of the kernel's samples/bpf.
 *
 * Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Changes to build outside the kernel tree with libbpf 1.x: the UAPI
 * headers, __u16/__u32/__u64 for u16/u32/u64, bpf_htons for htons,
 * struct vlan_hdr defined here (it is not in the UAPI headers), and the
 * map declared with BTF instead of struct bpf_map_def SEC("maps").
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(long));
    __uint(max_entries, 256);
} rxcnt SEC(".maps");

static int parse_ipv4(void *data, __u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if (iph + 1 > data_end)
        return 0;
    return iph->protocol;
}

static int parse_ipv6(void *data, __u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if (ip6h + 1 > data_end)
        return 0;
    return ip6h->nexthdr;
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int rc = XDP_DROP;
    long *value;
    __u16 h_proto;
    __u64 nh_off;
    __u32 ipproto;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return rc;

    h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == bpf_htons(ETH_P_IP))
        ipproto = parse_ipv4(data, nh_off, data_end);
    else if (h_proto == bpf_htons(ETH_P_IPV6))
        ipproto = parse_ipv6(data, nh_off, data_end);
    else
        ipproto = 0;

    value = bpf_map_lookup_elem(&rxcnt, &ipproto);
    if (value)
        *value += 1;

    return rc;
}
char _license[] SEC("license") = "GPL";
