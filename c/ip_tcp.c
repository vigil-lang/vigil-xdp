// Code 1: the classic BPF filter for "ip and tcp" (load 2 bytes @ [12],
// jump equal #0x800, load 1 byte @ [23], jump equal #6), as an XDP program.
// Accepting is XDP_PASS, rejecting XDP_DROP; a load past the end of the
// packet rejects, as it ends a classic BPF program with 0.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int ip_tcp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    unsigned char *data = (void *)(long)ctx->data;

    // load 2 bytes @ [12]
    if (data + 14 > (unsigned char *)data_end)
        return XDP_DROP;
    __u16 ethertype = (data[12] << 8) | data[13];
    // jump equal #0x800
    if (ethertype != 0x800)
        return XDP_DROP;
    // load 1 byte @ [23]
    if (data + 24 > (unsigned char *)data_end)
        return XDP_DROP;
    // jump equal #6
    if (data[23] != 6)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
