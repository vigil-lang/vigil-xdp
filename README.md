# The examples of "Fast Packet Processing with eBPF and XDP" in Vigil

This repository ports the code examples of Vieira et al., _Fast Packet
Processing with eBPF and XDP: Concepts, Code, Challenges and Applications_
([ACM Computing Surveys 53(1), article 16](https://doi.org/10.1145/3371038)),
from C to [Vigil](https://vigil-lang.github.io), a statically typed language
that compiles to eBPF. The C versions of the paper are next to the Vigil ones. A
differential test runs both versions of each example in the kernel on the same
packets and checks that they do the same thing.

The [Vigil tutorial](https://vigil-lang.github.io/tutorial.html#paper) walks
through these examples, comparing each Vigil program with its C version.

## The examples

| Example     | In the paper                                                                                                              | Vigil                                      | C                                |
| ----------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | -------------------------------- |
| `dropworld` | Fig. 3: drops every packet                                                                                                | [`vigil/dropworld.vg`](vigil/dropworld.vg) | [`c/dropworld.c`](c/dropworld.c) |
| `ip_tcp`    | Code 1: the classic BPF filter for `ip and tcp`, as an XDP program                                                        | [`vigil/ip_tcp.vg`](vigil/ip_tcp.vg)       | [`c/ip_tcp.c`](c/ip_tcp.c)       |
| `map_decl`  | Code 2: a map declaration (an array of 256 `long`s)                                                                       | [`vigil/map_decl.vg`](vigil/map_decl.vg)   | [`c/map_decl.c`](c/map_decl.c)   |
| `is_tcp`    | Code 4 (§5.1): passes TCP segments over IPv4 and drops the rest                                                           | [`vigil/is_tcp.vg`](vigil/is_tcp.vg)       | [`c/is_tcp.c`](c/is_tcp.c)       |
| `xdp1`      | §5.2.1: counts packets per IP protocol, under up to two VLAN tags, in a per-CPU map                                       | [`vigil/xdp1.vg`](vigil/xdp1.vg)           | [`c/xdp1.c`](c/xdp1.c)           |
| `xdp1_user` | §5.2.2: the userspace part of `xdp1`                                                                                      | the same loader for both objects           | [`c/xdp1_user.c`](c/xdp1_user.c) |
| `tracker`   | §5.3: an XDP program (receive) and a TC program (send) count packets and bytes per pair of IPv4 addresses in a shared map | [`vigil/tracker.vg`](vigil/tracker.vg)     | [`c/tracker.c`](c/tracker.c)     |

The comments at the top of each `.vg` file explain how it maps to the C. In
short:

- `ctx.parse[H](offset)` does the bounds check against `data_end` and the
  pointer cast of the C in one step. It returns an `Option`, so a missing check
  cannot be written.
- `?` returns the default verdict of the program type when a header is missing
  (`XDP_PASS` for XDP, `TC_ACT_OK` for TC), like the `return XDP_PASS` after
  each check in the paper.
- Header fields are read in host order, so there are no `bpf_htons` calls.
- Maps are declared with the types of their keys and values
  (`Hash[Pair, Stats](max_entries=2048)`), and `get` returns an optional
  reference into the map.
- The two copies of the VLAN block in `xdp1` become a bounded
  `for _ in range(2)` loop.

The Vigil `dropworld` compiles to the paper's two instructions, `r0 = 1; exit`.

## The C code

The C is the paper's, with the least needed to build it with libbpf 1.x and the
kernel's UAPI headers. Each change is noted at the top of its file:

- Maps are declared with BTF (`SEC(".maps")`). libbpf 1.0 no longer reads
  `struct bpf_map_def SEC("maps")`, nor iproute2's `struct bpf_elf_map`.
- A `license` section is added where the paper does not show one; the kernel
  requires it.
- In `xdp1`: `__u32` and `bpf_htons` replace `u32` and `htons`, and
  `struct vlan_hdr`, which is not in the UAPI headers, is defined in the file.
- In `xdp1_user`:
  - the libbpf functions that were removed (`bpf_prog_load_xattr`,
    `bpf_set_link_xdp_fd`, ...) are replaced by the current ones;
  - the object is a command-line argument;
  - the loop over the map ends when `bpf_map_get_next_key` returns non-zero. It
    now returns `-errno` rather than `-1`, so the paper's `!= -1` never ends.
- Code 1 is classic BPF (cBPF), which is not an eBPF program type. Both versions
  are XDP programs with the same logic: accepting is `XDP_PASS`, rejecting is
  `XDP_DROP`, and a load past the end of the packet rejects, as in cBPF.
- Code 2 only declares a map. Both versions add a program that counts every
  packet in entry 0, so that the map is in the object and can be compared.

The section names of the paper (`"drop-all"`, `"xdp1"`, `"rx"`, `"tx"`) are
kept. The test harness sets the type of each program before loading it.

## The differential test

1. [`tests/packets.py`](tests/packets.py) makes 442 packets, written to
   `build/packets.txt`:
   - 42 hand-made cases for the branches of the examples: TCP, UDP, ICMP, IPv6
     and ARP; one, two and three VLAN tags; headers cut short; the 14-, 23- and
     24-byte limits of Code 1; frames too short to be Ethernet; the same pairs
     of addresses in both directions;
   - 400 random variations of them, with a fixed seed.
2. [`harness/xdptest.c`](harness/xdptest.c) (libbpf) loads an object and runs
   each packet through each program with `BPF_PROG_TEST_RUN`. The maps keep
   their contents between runs. For each run it prints the verdict and the
   length and hash of the output packet. At the end it prints the contents of
   the maps, summed over the CPUs for per-CPU maps.
3. [`tests/examples.txt`](tests/examples.txt) lists, for each example, the
   programs of each version and the maps to compare.
4. [`tests/compare.py`](tests/compare.py) compares the outputs of the C and the
   Vigil version line by line and prints only what differs.

In `tracker`, Vigil stores the addresses of a key in host order, as it reads
header fields, and the C stores them in network order. The comparison swaps the
bytes of each address of the Vigil keys first.

[`tests/user.sh`](tests/user.sh) tests `xdp1_user` with both objects. It
attaches the program to `lo` in generic mode for 3 seconds while 100 UDP
datagrams go to 127.0.0.1, and checks that it counts at least those 100 under
protocol 17.

### Results

With Vigil 0.1.2, on kernels 5.15.211, 6.1.177, 6.6.144, 6.12.96 and 6.18.39,
all examples end with `ALL OK`:

| Example                         | Runs     | Refused in both  | Map entries compared |
| ------------------------------- | -------- | ---------------- | -------------------- |
| `dropworld`, `ip_tcp`, `is_tcp` | 442 each | 27 (0 on 5.15)   | none                 |
| `map_decl`                      | 442      | 27 (0 on 5.15)   | 1                    |
| `xdp1`                          | 442      | 27 (0 on 5.15)   | 39                   |
| `tracker` (two programs)        | 884      | 120 (93 on 5.15) | 137                  |

"Refused" counts the runs that `BPF_PROG_TEST_RUN` rejects with `EINVAL`, the
same ones for both versions. On 6.x kernels these are the 27 XDP runs on frames
shorter than 14 bytes, which 5.15 accepts. In `tracker`, the TC program is also
refused on 93 frames of 0 to 53 bytes, on every kernel. `xdp1_user` counted the
100 UDP datagrams with the C object and with the Vigil object on every kernel.

## Running it

You need the Vigil compiler, `vigil`, on the PATH (or named by `VIGIL`):

```sh
curl -fsSL https://vigil-lang.github.io/install.sh | sh
```

The results above are with Vigil 0.1.2; the examples also build with 0.1.0. The
compiler needs clang 15 or later to make eBPF objects.

### In virtual machines, without root

With Nix (flakes enabled) and KVM:

```sh
nix run .#vm-test                       # all kernels
KERNELS="linux_6_12" nix run .#vm-test  # one kernel
```

This builds the objects, the harness and the packets on the host, then boots one
NixOS VM per kernel (5.15, 6.1, 6.6, 6.12 and 6.18). Each VM runs `tests/run.sh`
on the shared directory and powers off. Each VM writes its output to
`build/vm-KERNEL.log`, and the harness outputs go to `build/results/KERNEL/`.
The command fails unless every kernel ends with `ALL OK`. `VM_TIMEOUT` (1800
seconds by default) limits each VM.

### On this machine

`nix develop` gives clang, libbpf, the kernel headers, bpftool and Python.
Without Nix, set `CLANG`, `LIBBPF` (the prefix of libbpf 1.x) and `KHEADERS`
(the prefix of the kernel headers). The test needs root, or `CAP_BPF` and
`CAP_NET_ADMIN`:

```sh
make             # objects in build/c and build/vigil, harness, xdp1_user, packets
sudo make test   # the differential test on the running kernel
```

## Layout

| Path                 |                                                                       |
| -------------------- | --------------------------------------------------------------------- |
| `vigil/`             | the examples in Vigil                                                 |
| `c/`                 | the examples in C, and `xdp1_user.c`                                  |
| `harness/xdptest.c`  | runs an object's programs on the packets and prints verdicts and maps |
| `tests/packets.py`   | the test packets                                                      |
| `tests/examples.txt` | what the test runs and compares for each example                      |
| `tests/compare.py`   | compares the C and the Vigil outputs                                  |
| `tests/run.sh`       | the whole test, on the running kernel                                 |
| `tests/user.sh`      | the `xdp1_user` test                                                  |
| `Makefile`           | builds everything; `make test` runs the test                          |
| `flake.nix`          | the tools, and the VMs of `nix run .#vm-test`                         |

## Origin of the code

The C programs are from the paper. `c/xdp1.c` and `c/xdp1_user.c` come from the
Linux kernel's `samples/bpf` (Copyright (c) 2016 PLUMgrid, GPL-2.0-only), as the
paper notes.
