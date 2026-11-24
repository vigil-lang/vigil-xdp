// Runs the programs of an eBPF object on a list of packets with
// BPF_PROG_TEST_RUN and prints what they did, so that two objects (the C
// and the Vigil version of an example) can be compared line by line.
//
//   xdptest OBJECT PACKETS PROG:TYPE [PROG:TYPE ...]
//
// PROG is a program (function) name and TYPE `xdp` or `tc`; the type is
// set before loading, so the section names of the article ("drop-all",
// "xdp1", "rx", "tx") work too. Each packet goes through each listed
// program, in order; the maps keep their contents across runs, as on a
// real interface. PACKETS has one packet per line, `NAME HEX`; empty
// lines and lines starting with `#` are skipped.
//
// The output, on stdout:
//
//   run NAME K ret R out N HASH     program K (0-based, in the order given)
//                                   returned R and left N bytes whose FNV-1a
//                                   hash is HASH
//   run NAME K error E              BPF_PROG_TEST_RUN failed with -E
//   map MAP KEY VALUE               the map entries after the last packet,
//                                   in hex, sorted; per-CPU values are
//                                   summed over the CPUs (as 64-bit words)
//                                   and entries whose value is all zeros
//                                   are left out
//
// The exit status is 0, or 2 when the object cannot be loaded (the
// verifier's log goes to stderr).

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PACKET 4096
#define MAX_PROGS 8

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint64_t fnv1a(const unsigned char *p, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static void hex(char *out, const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", p[i]);
    out[2 * n] = 0;
}

static int all_zero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i]) return 0;
    return 1;
}

static int is_percpu(enum bpf_map_type t) {
    return t == BPF_MAP_TYPE_PERCPU_ARRAY || t == BPF_MAP_TYPE_PERCPU_HASH ||
           t == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static int cmp_lines(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

// Prints the entries of a map, sorted.
static int dump_map(struct bpf_map *map, int ncpus) {
    int fd = bpf_map__fd(map);
    enum bpf_map_type type = bpf_map__type(map);
    size_t ksize = bpf_map__key_size(map), vsize = bpf_map__value_size(map);
    // a per-CPU value is read as one slot per CPU, each rounded up to 8 bytes
    size_t slot = (vsize + 7) / 8 * 8;
    size_t vbuf = is_percpu(type) ? slot * ncpus : vsize;
    if (is_percpu(type) && vsize % 8) {
        fprintf(stderr, "%s: per-CPU values of %zu bytes are not summed\n", bpf_map__name(map),
                vsize);
        return -1;
    }
    unsigned char *key = calloc(1, ksize), *next = calloc(1, ksize);
    unsigned char *val = calloc(1, vbuf), *sum = calloc(1, vsize);
    size_t cap = 64, n = 0;
    char **lines = malloc(cap * sizeof(char *));
    void *prev = NULL;
    while (bpf_map_get_next_key(fd, prev, next) == 0) {
        memcpy(key, next, ksize);
        prev = key;
        if (bpf_map_lookup_elem(fd, key, val)) continue;
        if (is_percpu(type)) {
            memset(sum, 0, vsize);
            for (int c = 0; c < ncpus; c++)
                for (size_t w = 0; w < vsize / 8; w++) {
                    uint64_t a, b;
                    memcpy(&a, sum + 8 * w, 8);
                    memcpy(&b, val + c * slot + 8 * w, 8);
                    a += b;
                    memcpy(sum + 8 * w, &a, 8);
                }
        } else {
            memcpy(sum, val, vsize);
        }
        if (all_zero(sum, vsize)) continue;
        char *line = malloc(strlen(bpf_map__name(map)) + 2 * (ksize + vsize) + 8);
        char *k = malloc(2 * ksize + 1), *v = malloc(2 * vsize + 1);
        hex(k, key, ksize);
        hex(v, sum, vsize);
        sprintf(line, "map %s %s %s", bpf_map__name(map), k, v);
        free(k);
        free(v);
        if (n == cap) lines = realloc(lines, (cap *= 2) * sizeof(char *));
        lines[n++] = line;
    }
    qsort(lines, n, sizeof(char *), cmp_lines);
    for (size_t i = 0; i < n; i++) {
        puts(lines[i]);
        free(lines[i]);
    }
    free(lines);
    free(key);
    free(next);
    free(val);
    free(sum);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: xdptest OBJECT PACKETS PROG:TYPE [PROG:TYPE ...]\n");
        return 1;
    }
    int nprogs = argc - 3;
    if (nprogs > MAX_PROGS) {
        fprintf(stderr, "at most %d programs\n", MAX_PROGS);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "%s: cannot open: %s\n", argv[1], strerror(errno));
        return 2;
    }
    struct bpf_program *progs[MAX_PROGS];
    for (int i = 0; i < nprogs; i++) {
        char name[128];
        snprintf(name, sizeof(name), "%s", argv[3 + i]);
        char *colon = strchr(name, ':');
        if (!colon) {
            fprintf(stderr, "%s: expected PROG:TYPE\n", argv[3 + i]);
            return 1;
        }
        *colon = 0;
        progs[i] = bpf_object__find_program_by_name(obj, name);
        if (!progs[i]) {
            fprintf(stderr, "%s: no program `%s`\n", argv[1], name);
            return 2;
        }
        if (!strcmp(colon + 1, "xdp"))
            bpf_program__set_type(progs[i], BPF_PROG_TYPE_XDP);
        else if (!strcmp(colon + 1, "tc"))
            bpf_program__set_type(progs[i], BPF_PROG_TYPE_SCHED_CLS);
        else {
            fprintf(stderr, "%s: the type is xdp or tc\n", argv[3 + i]);
            return 1;
        }
    }
    // only the listed programs are loaded
    struct bpf_program *p;
    bpf_object__for_each_program(p, obj) {
        int listed = 0;
        for (int i = 0; i < nprogs; i++) listed |= p == progs[i];
        if (!listed) bpf_program__set_autoload(p, false);
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "%s: cannot load: %s\n", argv[1], strerror(errno));
        return 2;
    }

    FILE *f = fopen(argv[2], "r");
    if (!f) {
        fprintf(stderr, "%s: %s\n", argv[2], strerror(errno));
        return 1;
    }
    static char line[2 * MAX_PACKET + 256];
    static unsigned char packet[MAX_PACKET], out[MAX_PACKET + 256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *name = strtok(line, " \t\n"), *hx = strtok(NULL, " \t\n");
        if (!name) continue;
        size_t len = 0;
        for (char *c = hx; c && c[0] && c[1] && len < MAX_PACKET; c += 2) {
            int hi = hexval(c[0]), lo = hexval(c[1]);
            if (hi < 0 || lo < 0) {
                fprintf(stderr, "%s: bad hex in `%s`\n", argv[2], name);
                return 1;
            }
            packet[len++] = hi << 4 | lo;
        }
        for (int i = 0; i < nprogs; i++) {
            LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = packet, .data_size_in = len,
                        .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
            if (bpf_prog_test_run_opts(bpf_program__fd(progs[i]), &opts)) {
                printf("run %s %d error %d\n", name, i, errno);
                continue;
            }
            printf("run %s %d ret %u out %u %016llx\n", name, i, opts.retval, opts.data_size_out,
                   (unsigned long long)fnv1a(out, opts.data_size_out));
        }
    }
    fclose(f);

    int ncpus = libbpf_num_possible_cpus();
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        if (bpf_map__is_internal(map)) continue;  // .rodata, .bss, ...
        if (dump_map(map, ncpus)) return 1;
    }
    bpf_object__close(obj);
    return 0;
}
