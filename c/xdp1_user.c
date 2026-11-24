// § 5.2.2: the user-space part of xdp1 (xdp1_user.c of the kernel's
// samples/bpf): loads the program, attaches it to an interface, and prints
// the packets per second of each IP protocol from the per-CPU map `rxcnt`.
//
//   xdp1_user OBJECT IFACE [SECONDS]
//
// The same loader works with the C object and with the Vigil one: both
// have a program `xdp_prog1` and a map `rxcnt` of 256 longs per CPU.
//
// Changes for libbpf 1.x: the object is an argument instead of
// "<argv[0]>_kern.o"; bpf_prog_load_xattr, bpf_map__next and
// bpf_set_link_xdp_fd, removed from libbpf, become bpf_object__open_file,
// bpf_object__find_map_by_name and bpf_xdp_attach; the program is attached
// in generic (SKB) mode, which every interface supports, and detached after
// SECONDS (5 by default) instead of on Ctrl-C; bpf_map_get_next_key now
// returns -errno at the end, not -1, so the loop tests for 0. At the end
// it prints the total of each protocol, for the tests.
//
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2016 PLUMgrid

#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void poll_stats(int map_fd, int interval, int rounds, __u64 *prev) {
    unsigned int nr_cpus = libbpf_num_possible_cpus();
    __u64 values[nr_cpus];
    int i;

    while (rounds-- > 0) {
        __u32 key = UINT32_MAX;

        sleep(interval);

        while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
            __u64 sum = 0;

            assert(bpf_map_lookup_elem(map_fd, &key, values) == 0);
            for (i = 0; i < (int)nr_cpus; i++)
                sum += values[i];
            if (sum > prev[key])
                printf("proto %u: %10llu pkt/s\n", key, (sum - prev[key]) / interval);
            prev[key] = sum;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: xdp1_user OBJECT IFACE [SECONDS]\n");
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    int seconds = argc > 3 ? atoi(argv[3]) : 5;
    unsigned int ifindex = if_nametoindex(argv[2]);
    if (!ifindex) {
        fprintf(stderr, "%s: no such interface\n", argv[2]);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "%s: cannot open: %s\n", argv[1], strerror(errno));
        return 1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_prog1");
    if (!prog) {
        fprintf(stderr, "%s: no program xdp_prog1\n", argv[1]);
        return 1;
    }
    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
    if (bpf_object__load(obj)) {
        fprintf(stderr, "%s: cannot load: %s\n", argv[1], strerror(errno));
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "rxcnt");
    if (!map) {
        printf("finding a map in obj file failed\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;
    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0) {
        printf("link set xdp fd failed\n");
        return 1;
    }

    static __u64 prev[256];
    fprintf(stderr, "attached to %s\n", argv[2]);
    poll_stats(map_fd, 1, seconds, prev);

    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    for (int key = 0; key < 256; key++)
        if (prev[key])
            printf("total proto %d: %llu\n", key, (unsigned long long)prev[key]);
    bpf_object__close(obj);
    return 0;
}
