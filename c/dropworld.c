// Figure 3 ("dropworld"): an XDP program that drops every packet.
//
// As in the article, except for the license section, which current kernels
// require to load any program.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("drop-all")
int drop(struct xdp_md *ctx) {
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
