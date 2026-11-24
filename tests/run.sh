# The differential test: each example of tests/examples.txt, C and Vigil,
# on the packets of build/packets.txt, on the running kernel. Needs root
# (or CAP_BPF and CAP_NET_ADMIN); `make test` builds what it needs first,
# and `nix run .#vm-test` runs it in VMs.
#
# Then tests/user.sh runs the user-space part of xdp1 with both objects.
# The outputs are kept in build/results/KERNEL/. The last line is `ALL OK`
# when every example gives the same verdicts and maps in both languages.
set -u
cd "$(dirname "$0")/.."
kernel=$(uname -r)
out=build/results/$kernel
mkdir -p "$out"
echo "kernel $kernel"
status=0
while read -r name cprogs vprogs maps swap; do
  case $name in ''|'#'*) continue ;; esac
  failed=0
  build/xdptest "build/c/$name.o" build/packets.txt ${cprogs//,/ } \
    > "$out/$name.c.out" 2> "$out/$name.c.err" || failed=1
  build/xdptest "build/vigil/$name.o" build/packets.txt ${vprogs//,/ } \
    > "$out/$name.vigil.out" 2> "$out/$name.vigil.err" || failed=1
  if [ $failed = 1 ]; then
    printf '%-10s FAILED to load or run (see %s/%s.*.err)\n' "$name" "$out" "$name"
    tail -5 "$out/$name.c.err" "$out/$name.vigil.err"
    status=1
    continue
  fi
  printf '%-10s ' "$name"
  python3 tests/compare.py "$out/$name.c.out" "$out/$name.vigil.out" "$maps" "$swap" || status=1
done < tests/examples.txt
# the user-space part of xdp1, with both objects
bash tests/user.sh || status=1
if [ $status = 0 ]; then echo "ALL OK"; else echo "SOME FAILED"; fi
exit $status
