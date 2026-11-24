# The examples of "Fast Packet Processing with eBPF and XDP" (Vieira et al.,
# ACM Computing Surveys) in C and in Vigil, and the differential test that
# runs both versions of each example on the same packets.
#
#   make                 objects (build/c, build/vigil), harness, xdp1_user,
#                        packets
#   make test            the differential test on this machine (root)
#   nix run .#vm-test    the same in a VM per kernel (no root, KVM)
#
# In `nix develop` the tools are set; otherwise give LIBBPF, KHEADERS and
# CLANG. VIGIL is the Vigil compiler, `vigil` on the PATH by default.

VIGIL ?= vigil
CLANG ?= clang
LIBBPF ?= /usr
KHEADERS ?=
PYTHON ?= python3

EXAMPLES := dropworld ip_tcp map_decl is_tcp xdp1 tracker

BPF_CFLAGS := -O2 -g -target bpf -Wall -Wno-unused-parameter \
	-Wno-compare-distinct-pointer-types \
	-I$(LIBBPF)/include $(if $(KHEADERS),-idirafter $(KHEADERS)/include)

C_OBJECTS := $(EXAMPLES:%=build/c/%.o)
VIGIL_OBJECTS := $(EXAMPLES:%=build/vigil/%.o)

all: objects packets

objects: $(C_OBJECTS) $(VIGIL_OBJECTS) build/xdptest build/xdp1_user

packets: build/packets.txt

build/c/%.o: c/%.c
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build/vigil/%.o: vigil/%.vg
	@mkdir -p $(dir $@)
	$(VIGIL) build $< -o $@

build/xdptest: harness/xdptest.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -Wall -Wextra -I$(LIBBPF)/include $< -L$(LIBBPF)/lib -lbpf \
		-Wl,-rpath,$(LIBBPF)/lib -o $@

build/xdp1_user: c/xdp1_user.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -Wall -I$(LIBBPF)/include $< -L$(LIBBPF)/lib -lbpf \
		-Wl,-rpath,$(LIBBPF)/lib -o $@

build/packets.txt: tests/packets.py
	@mkdir -p $(dir $@)
	$(PYTHON) tests/packets.py > $@

test: objects packets
	bash tests/run.sh

clean:
	rm -rf build

.PHONY: all objects packets test clean
