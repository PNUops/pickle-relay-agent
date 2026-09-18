#!/usr/bin/env bash
# Run only inside a fresh outer user-provided network and mount namespace.
set -euo pipefail
[ "${EUID:-$(id -u)}" -eq 0 ] || { echo 'root inside isolated namespace required' >&2; exit 1; }
[ -n "${PICKLE_RELAY_HOST_NETNS_INODE:-}" ] || { echo 'host namespace inode guard missing' >&2; exit 1; }
[ -n "${PICKLE_RELAY_HOST_MNTNS_INODE:-}" ] || { echo 'host mount namespace inode guard missing' >&2; exit 1; }
self_inode=$(stat -Lc %i /proc/self/ns/net)
[ "$self_inode" != "$PICKLE_RELAY_HOST_NETNS_INODE" ] || { echo 'refusing host network namespace' >&2; exit 1; }
self_mnt_inode=$(stat -Lc %i /proc/self/ns/mnt)
[ "$self_mnt_inode" != "$PICKLE_RELAY_HOST_MNTNS_INODE" ] || { echo 'refusing host mount namespace' >&2; exit 1; }
[ "$#" -eq 2 ] || { echo 'usage: test-mapping-retirement-netns.sh NFT_TEST CONNTRACK_TEST' >&2; exit 2; }
nft_test=$1
conntrack_test=$2
[ -x "$nft_test" ] && [ -x "$conntrack_test" ] || { echo 'test binaries must be executable' >&2; exit 1; }

work=$(mktemp -d /tmp/relay-retirement-packet.XXXXXX)
chmod 700 "$work"
server_pids=()
owned_netns=0
cleanup() {
  if [ "$owned_netns" -eq 1 ]; then
    [ ! -f "$work/guest8.jsonl" ] || { echo '--- guest8 payload evidence ---'; cat "$work/guest8.jsonl"; }
    [ ! -f "$work/guest9.jsonl" ] || { echo '--- guest9 payload evidence ---'; cat "$work/guest9.jsonl"; }
    for pid in "${server_pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    ip netns del client 2>/dev/null || true
    ip netns del guest8 2>/dev/null || true
    ip netns del guest9 2>/dev/null || true
    umount /run/netns 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

mount --make-rprivate /
mkdir -p /run/netns
mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /run/netns
owned_netns=1
for ns in client guest8 guest9; do ip netns add "$ns"; done
ip link add pub0 type veth peer name cli0
ip link set cli0 netns client
ip addr add 198.51.100.1/24 dev pub0
ip link set pub0 up
ip -n client addr add 198.51.100.2/24 dev cli0
ip -n client link set lo up
ip -n client link set cli0 up
ip -n client route add default via 198.51.100.1
ip link add br0 type bridge
ip addr add 192.0.2.1/24 dev br0
ip link set br0 up
for suffix in 8 9; do
  ip link add "r${suffix}" type veth peer name g0
  ip link set g0 netns "guest${suffix}"
  ip link set "r${suffix}" master br0
  ip link set "r${suffix}" up
  ip -n "guest${suffix}" addr add "192.0.2.${suffix}/24" dev g0
  ip -n "guest${suffix}" link set lo up
  ip -n "guest${suffix}" link set g0 up
  ip -n "guest${suffix}" route add default via 192.0.2.1
done
sysctl -q -w net.ipv4.ip_forward=1

cat >"$work/server.py" <<'PY'
import json,select,socket,sys
address=sys.argv[1]; ports=[int(v) for v in sys.argv[2].split(',')]; log=sys.argv[3]; ready=sys.argv[4]
sockets=[]
for port in ports:
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((address,port));sockets.append(s)
open(ready,'w').close()
while True:
    ready,_,_=select.select(sockets,[],[],5)
    for s in ready:
        data,peer=s.recvfrom(4096)
        with open(log,'a',encoding='utf-8') as out:
            out.write(json.dumps({'port':s.getsockname()[1],'payload':data.decode(),'peer':peer})+'\n');out.flush()
PY
cat >"$work/send.py" <<'PY'
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('198.51.100.2',int(sys.argv[1])));s.connect(('198.51.100.1',int(sys.argv[2])));s.send(sys.argv[3].encode())
PY
ip netns exec guest8 python3 -u "$work/server.py" 192.0.2.8 53,54,56 "$work/guest8.jsonl" "$work/ready8" & server_pids+=("$!")
ip netns exec guest9 python3 -u "$work/server.py" 192.0.2.9 55 "$work/guest9.jsonl" "$work/ready9" & server_pids+=("$!")
for _ in $(seq 1 30); do [ -e "$work/ready8" ] && [ -e "$work/ready9" ] && break; sleep 0.1; done
[ -e "$work/ready8" ] && [ -e "$work/ready9" ] || { echo 'UDP servers did not become ready' >&2; exit 1; }

apply_phase(){ PICKLE_RELAY_KERNEL_TEST=1 PICKLE_RELAY_TEST_IFACE=pub0 PICKLE_RELAY_TEST_PHASE=$1 "$nft_test" -test.run '^TestIntegrationManagedApplyAndSemanticReadback$'; }
send(){ ip netns exec client python3 "$work/send.py" "$1" "$2" "$3"; }
wait_payload(){ for _ in $(seq 1 30); do grep -Fq "\"payload\": \"$2\"" "$1" 2>/dev/null && return; sleep 0.1; done; echo "missing payload $2" >&2; exit 1; }
reject_payload(){ sleep 0.5; ! grep -Fq "\"payload\": \"$2\"" "$1" 2>/dev/null || { echo "unexpected payload $2" >&2; exit 1; }; }

apply_phase target-seed
send 40002 10055 other-target; wait_payload "$work/guest9.jsonl" other-target
apply_phase initial
send 40000 10053 old-exact; send 40001 10054 other-mark
send 40002 10055 other-target-refresh
wait_payload "$work/guest8.jsonl" old-exact; wait_payload "$work/guest8.jsonl" other-mark; wait_payload "$work/guest9.jsonl" other-target
wait_payload "$work/guest9.jsonl" other-target-refresh
apply_phase retire
send 40000 10053 fenced-old; reject_payload "$work/guest8.jsonl" fenced-old
PICKLE_RELAY_KERNEL_TEST=1 "$conntrack_test" -test.run '^TestIntegrationClearDeletesOnlyExactRetiredFlow$'
apply_phase resume
send 40000 10053 resumed-same-tuple; wait_payload "$work/guest8.jsonl" resumed-same-tuple
apply_phase acl-allow
send 41000 10056 acl-existing-1; wait_payload "$work/guest8.jsonl" acl-existing-1
apply_phase acl-deny
send 41000 10056 acl-existing-2; send 41001 10056 acl-new-denied
wait_payload "$work/guest8.jsonl" acl-existing-2; reject_payload "$work/guest8.jsonl" acl-new-denied
apply_phase quarantine
send 40000 10053 quarantine-resumed; send 41000 10056 quarantine-acl-existing
reject_payload "$work/guest8.jsonl" quarantine-resumed; reject_payload "$work/guest8.jsonl" quarantine-acl-existing
echo 'mapping retirement namespace packet test OK'
