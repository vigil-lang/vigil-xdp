"""The packets of the differential test, one per line: `NAME HEX`.

    python3 tests/packets.py [--seed N] [--random N] > build/packets.txt

Hand-made cases first, chosen for the branches of the examples:
- IPv4 TCP, UDP, ICMP and another protocol; IPv4 with options; IPv6 TCP,
  UDP and ICMPv6; ARP;
- one and two VLAN tags (802.1Q, 802.1ad), and three, of which xdp1 skips
  only two;
- headers cut short: the Ethernet header alone, a VLAN tag, an IPv4 or IPv6
  header, and the 14, 23 and 24 bytes around the loads of Code 1;
- a frame shorter than 14 bytes, which BPF_PROG_TEST_RUN refuses for both
  versions alike;
- several packets between the same pair of addresses, both ways, for the
  tracker.

Then random packets (--random, 400 by default) made from those by changing
bytes, the EtherType and the length, with a fixed seed so that every run
tests the same packets. Standard library only.
"""

import argparse
import random
import struct

ETH_P_IP, ETH_P_IPV6, ETH_P_ARP = 0x0800, 0x86DD, 0x0806
ETH_P_8021Q, ETH_P_8021AD = 0x8100, 0x88A8
MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth(proto, payload, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack("!H", proto) + payload


def vlan(tci, proto, payload):
    return struct.pack("!HH", tci, proto) + payload


def ipv4(src, dst, proto, payload, options=b"", ttl=64):
    ihl = 5 + len(options) // 4
    header = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(options) + len(payload), 1, 0,
                         ttl, proto, 0, bytes(src), bytes(dst)) + options
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6(nexthdr, payload, src=b"\x20\x01\x0d\xb8" + b"\0" * 11 + b"\x01",
         dst=b"\x20\x01\x0d\xb8" + b"\0" * 11 + b"\x02"):
    return struct.pack("!IHBB", 0x60000000, len(payload), nexthdr, 64) + src + dst + payload


def tcp(sport, dport, flags=0x02, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(payload=b"ping"):
    return struct.pack("!BBHHH", 8, 0, 0, 1, 1) + payload


def arp():
    return struct.pack("!HHBBH6s4s6s4s", 1, ETH_P_IP, 6, 4, 1, MAC_A, bytes([10, 0, 0, 1]),
                       b"\0" * 6, bytes([10, 0, 0, 2]))


A, B, C = [10, 0, 0, 1], [10, 0, 0, 2], [192, 168, 1, 7]


def cases():
    """The hand-made packets, as (name, bytes)."""
    out = []
    add = lambda name, data: out.append((name, data))

    add("ipv4_tcp", eth(ETH_P_IP, ipv4(A, B, 6, tcp(40000, 80))))
    add("ipv4_tcp_data", eth(ETH_P_IP, ipv4(A, B, 6, tcp(40000, 80, 0x18, b"GET / HTTP/1.1\r\n\r\n"))))
    add("ipv4_udp", eth(ETH_P_IP, ipv4(A, B, 17, udp(5353, 53, b"\x12\x34"))))
    add("ipv4_icmp", eth(ETH_P_IP, ipv4(B, A, 1, icmp_echo())))
    add("ipv4_gre", eth(ETH_P_IP, ipv4(A, C, 47, b"\0" * 8)))
    add("ipv4_options_tcp", eth(ETH_P_IP, ipv4(A, B, 6, tcp(1, 2), options=b"\x01\x01\x01\x00")))
    add("ipv4_version6_tcp", eth(ETH_P_IP, b"\x60" + ipv4(A, B, 6, tcp(1, 2))[1:]))
    add("ipv6_tcp", eth(ETH_P_IPV6, ipv6(6, tcp(40000, 443))))
    add("ipv6_udp", eth(ETH_P_IPV6, ipv6(17, udp(1, 2))))
    add("ipv6_icmpv6", eth(ETH_P_IPV6, ipv6(58, b"\x80\x00\x00\x00\x00\x01\x00\x01")))
    add("ipv6_proto6_in_ipv4_slot", eth(ETH_P_IPV6, ipv4(A, B, 6, tcp(1, 2))))
    add("arp", eth(ETH_P_ARP, arp()))
    add("vlan_ipv4_tcp", eth(ETH_P_8021Q, vlan(10, ETH_P_IP, ipv4(A, B, 6, tcp(1, 2)))))
    add("vlan_ipv4_udp", eth(ETH_P_8021Q, vlan(10, ETH_P_IP, ipv4(A, B, 17, udp(1, 2)))))
    add("vlan_ipv6_udp", eth(ETH_P_8021Q, vlan(10, ETH_P_IPV6, ipv6(17, udp(1, 2)))))
    add("qinq_ipv4_tcp", eth(ETH_P_8021AD, vlan(100, ETH_P_8021Q, vlan(10, ETH_P_IP, ipv4(A, B, 6, tcp(1, 2))))))
    add("qinq_ipv6_icmpv6", eth(ETH_P_8021AD, vlan(100, ETH_P_8021Q, vlan(10, ETH_P_IPV6, ipv6(58, b"\0" * 8)))))
    add("qinq_8021q_twice", eth(ETH_P_8021Q, vlan(1, ETH_P_8021Q, vlan(2, ETH_P_IP, ipv4(A, B, 1, icmp_echo())))))
    add("three_tags", eth(ETH_P_8021AD, vlan(1, ETH_P_8021Q, vlan(2, ETH_P_8021Q, vlan(3, ETH_P_IP, ipv4(A, B, 6, tcp(1, 2)))))))
    add("vlan_cut", eth(ETH_P_8021Q, b"\x00\x0a"))
    add("qinq_cut", eth(ETH_P_8021AD, vlan(100, ETH_P_8021Q, b"\x00")))
    add("vlan_ipv4_cut", eth(ETH_P_8021Q, vlan(10, ETH_P_IP, ipv4(A, B, 6, tcp(1, 2))[:19])))
    add("eth_only_ip", eth(ETH_P_IP, b""))
    add("eth_only_ipv6", eth(ETH_P_IPV6, b""))
    add("ipv4_cut_19", eth(ETH_P_IP, ipv4(A, B, 6, tcp(1, 2))[:19]))
    add("ipv4_cut_9_byte23_missing", eth(ETH_P_IP, ipv4(A, B, 6, tcp(1, 2))[:9]))
    add("ipv4_cut_10_byte23_tcp", eth(ETH_P_IP, ipv4(A, B, 6, tcp(1, 2))[:10]))
    add("ipv4_cut_10_byte23_udp", eth(ETH_P_IP, ipv4(A, B, 17, udp(1, 2))[:10]))
    add("ipv6_cut_39", eth(ETH_P_IPV6, ipv6(6, tcp(1, 2))[:39]))
    add("ipv6_exact_40", eth(ETH_P_IPV6, ipv6(17, b"")))
    add("short_13", eth(ETH_P_IP, b"")[:13])
    add("ethertype_0", eth(0, ipv4(A, B, 6, tcp(1, 2))))
    add("ethertype_ffff", eth(0xFFFF, ipv4(A, B, 6, tcp(1, 2))))
    add("ipv4_tcp_1514", eth(ETH_P_IP, ipv4(A, B, 6, tcp(1, 2, 0x18, bytes(range(256)) * 5 + b"x" * 174))))
    # the tracker: the same pairs several times, in both directions
    for i in range(3):
        add("pair_ab_%d" % i, eth(ETH_P_IP, ipv4(A, B, 6, tcp(40000 + i, 80, 0x18, b"x" * (10 * i)))))
        add("pair_ba_%d" % i, eth(ETH_P_IP, ipv4(B, A, 6, tcp(80, 40000 + i, 0x18, b"y" * (7 * i)))))
    add("pair_ac", eth(ETH_P_IP, ipv4(A, C, 17, udp(1, 2, b"dns"))))
    add("pair_ca", eth(ETH_P_IP, ipv4(C, A, 17, udp(2, 1, b"answer"))))
    return out


def mutate(rng, data):
    """A random variation of a packet."""
    data = bytearray(data)
    choice = rng.randrange(6)
    if choice == 0:  # flip some bytes
        for _ in range(rng.randint(1, 4)):
            if data:
                data[rng.randrange(len(data))] = rng.randrange(256)
    elif choice == 1:  # cut it
        data = data[:rng.randint(0, len(data))]
    elif choice == 2:  # another EtherType
        if len(data) >= 14:
            proto = rng.choice([ETH_P_IP, ETH_P_IPV6, ETH_P_8021Q, ETH_P_8021AD, ETH_P_ARP,
                                rng.randrange(65536)])
            data[12:14] = struct.pack("!H", proto)
    elif choice == 3:  # another IP protocol, at the IPv4 and IPv6 offsets
        for off in (23, 20, 27, 31):
            if len(data) > off and rng.random() < 0.5:
                data[off] = rng.choice([1, 6, 17, 47, 58, rng.randrange(256)])
    elif choice == 4:  # extra bytes
        data += bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
    else:  # random bytes behind an Ethernet header
        data = data[:14] + bytes(rng.randrange(256) for _ in range(rng.randint(0, 80)))
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--seed", type=int, default=2019)
    parser.add_argument("--random", type=int, default=400)
    args = parser.parse_args()
    base = cases()
    print("# hand-made cases")
    for name, data in base:
        print(name, data.hex())
    print("# random variations, seed %d" % args.seed)
    rng = random.Random(args.seed)
    for i in range(args.random):
        name, data = rng.choice(base)
        print("random_%d_%s" % (i, name), mutate(rng, data).hex())


if __name__ == "__main__":
    main()
