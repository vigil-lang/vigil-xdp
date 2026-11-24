# The user-space part of xdp1 (c/xdp1_user.c) with both objects: attached
# to `lo` in generic mode for 3 s while 100 UDP datagrams go to
# 127.0.0.1, it must count at least those 100 under protocol 17. Other
# traffic on `lo` may add to the count, so the two totals are not compared
# with each other. Needs root; called by tests/run.sh.
set -u
cd "$(dirname "$0")/.."
out=build/results/$(uname -r)
mkdir -p "$out"
status=0
send() {
  python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
time.sleep(1)
for i in range(100):
    s.sendto(b"xdp1 %d" % i, ("127.0.0.1", 9))
PY
}
for lang in c vigil; do
  timeout 30 bash -c "$(declare -f send); send" &
  timeout 30 build/xdp1_user "build/$lang/xdp1.o" lo 3 > "$out/xdp1_user.$lang.out" 2>&1
  echo "xdp1_user exit $?" >> "$out/xdp1_user.$lang.out"
  wait
  udp=$(sed -n 's/^total proto 17: //p' "$out/xdp1_user.$lang.out")
  if [ "${udp:-0}" -ge 100 ]; then
    printf '%-10s ok    %s object: %s UDP packets counted (100 sent)\n' xdp1_user "$lang" "$udp"
  else
    printf '%-10s FAIL  %s object: %s UDP packets counted (100 sent)\n' xdp1_user "$lang" "${udp:-0}"
    cat "$out/xdp1_user.$lang.out"
    status=1
  fi
done
exit $status
