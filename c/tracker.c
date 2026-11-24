// § 5.3: XDP and TC working together, counting the packets and bytes
// exchanged with each pair of IPv4 addresses.
//
// Changes for libbpf 1.x: the map is declared with BTF instead of iproute2's
// struct bpf_elf_map (iproute2/bpf_elf.h); the two programs share it because
// they are in the same object, so no pinning is set (`LIBBPF_PIN_BY_NAME`
// would share it with programs of other objects). <stdlib.h>, which the
// article includes but does not use, is left out: there is no C library for
// the BPF target.
#include <stdbool.h>
#include <stdint.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct pair {
    uint32_t lip; // local IP
    uint32_t rip; // remote IP
};

struct stats {
    uint64_t tx_cnt;
    uint64_t rx_cnt;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct pair));
    __uint(value_size, sizeof(struct stats));
    __uint(max_entries, 2048);
} trackers SEC(".maps");

static bool parse_ipv4(bool is_rx, void* data, void* data_end, struct pair *pair){
    struct ethhdr *eth = data;
    struct iphdr *ip;

    if(data + sizeof(struct ethhdr) > data_end)
        return false;

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    ip = data + sizeof(struct ethhdr);

    if ((void*) ip + sizeof(struct iphdr) > data_end)
        return false;

    pair->lip = is_rx ? ip->daddr : ip->saddr;
    pair->rip = is_rx ? ip->saddr : ip->daddr;

    return true;
}

static void update_stats(bool is_rx, struct pair *key, long long bytes){
    struct stats *stats, newstats = {0,0,0,0};

    stats = bpf_map_lookup_elem(&trackers, key);
    if(stats){
        if(is_rx){
            stats->rx_cnt++;
            stats->rx_bytes += bytes;
        }else{
            stats->tx_cnt++;
            stats->tx_bytes += bytes;
        }
    }else{
        if(is_rx){
            newstats.rx_cnt = 1;
            newstats.rx_bytes = bytes;
        }else{
            newstats.tx_cnt = 1;
            newstats.tx_bytes = bytes;
        }

        bpf_map_update_elem(&trackers, key, &newstats, BPF_NOEXIST);
    }
}

SEC("rx")
int track_rx(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct pair pair;

    if(!parse_ipv4(true,data,data_end,&pair))
        return XDP_PASS;

    // Update RX statistics
    update_stats(true,&pair,data_end-data);

    return XDP_PASS;
}

SEC("tx")
int track_tx(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct pair pair;

    if(!parse_ipv4(false,data,data_end,&pair))
        return TC_ACT_OK;

    // Update TX statistics
    update_stats(false,&pair,data_end-data);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
