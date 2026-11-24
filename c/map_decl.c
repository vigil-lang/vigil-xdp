// Code 2: a map declaration, an array of 256 longs indexed by uint32_t.
//
// The article declares it with `struct bpf_map_def SEC("maps")`, which
// libbpf 1.0 no longer reads; this is the same map with BTF. As in the Vigil
// version, a program counts every packet in entry 0 so that the map is
// used.
#include <linux/bpf.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(long));
    __uint(max_entries, 256);
} mapname SEC(".maps");

SEC("xdp")
int count(struct xdp_md *ctx) {
    uint32_t key = 0;
    long *n = bpf_map_lookup_elem(&mapname, &key);
    if (n)
        *n += 1;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
