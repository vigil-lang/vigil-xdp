"""Compares the output of build/xdptest for the C and the Vigil object of
an example.

    python3 tests/compare.py C_OUT VIGIL_OUT MAPS KEY_SWAP

MAPS and KEY_SWAP are as in tests/examples.txt. The `run` lines must be
the same, line by line: the verdict and the packet the program leaves.
Then the entries of the maps in MAPS must be the same; the other maps
(the compiler's own, such as scratch memory) are ignored. Prints a summary
and exits with 1 on a difference.
"""

import sys


def read(path):
    runs, maps = [], {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if parts and parts[0] == "run":
                runs.append(" ".join(parts[1:]))
            elif parts and parts[0] == "map":
                maps.setdefault(parts[1], []).append((parts[2], parts[3]))
    return runs, maps


def swap32(key):
    """Reverses the bytes of each 32-bit word of a hex key."""
    words = [key[i:i + 8] for i in range(0, len(key), 8)]
    return "".join("".join(reversed([w[j:j + 2] for j in range(0, len(w), 2)])) for w in words)


def main():
    c_out, vigil_out, maps_arg, swap_arg = sys.argv[1:5]
    names = [] if maps_arg == "-" else maps_arg.split(",")
    swap = set() if swap_arg == "-" else set(swap_arg.split(","))
    c_runs, c_maps = read(c_out)
    v_runs, v_maps = read(vigil_out)

    problems = []
    if not c_runs:
        problems.append("no runs in the C output")
    if len(c_runs) != len(v_runs):
        problems.append("%d runs in C, %d in Vigil" % (len(c_runs), len(v_runs)))
    for c, v in zip(c_runs, v_runs):
        if c != v:
            problems.append("C:     %s\n    Vigil: %s" % (c, v))
    entries = 0
    for name in names:
        c = sorted(c_maps.get(name, []))
        v = sorted((swap32(k) if name in swap else k, val) for k, val in v_maps.get(name, []))
        entries += len(c)
        for key, val in sorted(set(c) - set(v)):
            problems.append("map %s: %s = %s only in C" % (name, key, val))
        for key, val in sorted(set(v) - set(c)):
            problems.append("map %s: %s = %s only in Vigil" % (name, key, val))

    errors = sum(" error " in r for r in c_runs)
    summary = "%d runs (%d refused by the kernel in both), %d map entries" % (len(c_runs), errors, entries)
    if problems:
        print("DIFF  %s" % summary)
        for p in problems[:20]:
            print("    " + p)
        if len(problems) > 20:
            print("    ... %d more" % (len(problems) - 20))
        sys.exit(1)
    print("ok    %s" % summary)


if __name__ == "__main__":
    main()
