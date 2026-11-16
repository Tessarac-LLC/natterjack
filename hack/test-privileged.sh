#!/usr/bin/env bash
# Runs the data path tests that change a kernel, each in throwaway
# privileged containers so the machine running them is left alone.
#   1. One node: a gateway serving its own pods and itself.
#   2. The eBPF fast path, with a CNI that bypasses netfilter emulated.
#   3. Three containers on one network: a gateway node, a source node that
#      steers through the tunnel (GENEVE, then WireGuard), and an outsider that tries to.
set -euo pipefail

image="alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
net="natterjack-test-$$"
subnet="172.30.$((RANDOM % 200 + 20)).0/24"
prefix="${subnet%.0/24}"
gateway="${prefix}.10" source="${prefix}.11" outsider="${prefix}.12"

cleanup() {
	docker rm -f "$net-gateway" "$net-source" "$net-outsider" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

(cd "$root" && GOWORK=off GOOS=linux CGO_ENABLED=0 go test -c -o "$work/dataplane.test" ./internal/agent/dataplane/)

run() { # name, ip, env..., -- test args
	local name="$1" ip="$2"
	shift 2
	local envs=()
	while [[ "$1" != "--" ]]; do envs+=(-e "$1"); shift; done
	shift
	docker run --name "$name" --privileged --network "$net" ${ip:+--ip "$ip"} \
		-v "$work:/t" -e NATTERJACK_PRIVILEGED_TESTS=1 "${envs[@]}" "$image" \
		sh -c 'apk add -q --no-progress nftables iproute2 >/dev/null && exec /t/dataplane.test -test.v -test.count=1 "$@"' _ "$@"
}

docker network create --subnet "$subnet" "$net" >/dev/null

echo "--- one node"
run "$net-gateway" "" -- -test.run 'TestSingleNodeGateway|TestStaleFlowsAreFlushed|TestMarkUse|TestMarkUseJumps|TestOwnRulesStayInTheMask|TestMarkConflicts|TestRulesAhead'
docker rm "$net-gateway" >/dev/null

echo "--- eBPF fast path"
run "$net-gateway" "" -- -test.run 'TestSteerPrograms|TestEBPFFastPath|TestRemoveEBPFReadOnly'
docker rm "$net-gateway" >/dev/null

status=0
for tunnel in Geneve WireGuard; do
	echo "--- tunnel: $tunnel"
	mkdir "$work/signals-$tunnel"
	common=(NATTERJACK_TUNNEL_DIR="/t/signals-$tunnel" "NATTERJACK_TUNNEL_TYPE=$tunnel" "NATTERJACK_TUNNEL_GATEWAY=$gateway" "NATTERJACK_TUNNEL_SOURCE=$source")
	run "$net-gateway" "$gateway" "${common[@]}" NATTERJACK_TUNNEL_ROLE=gateway -- -test.run TestTunnel >"$work/gateway.log" 2>&1 &
	gw=$!
	run "$net-outsider" "$outsider" "${common[@]}" NATTERJACK_TUNNEL_ROLE=outsider -- -test.run TestTunnel >"$work/outsider.log" 2>&1 &
	out=$!
	run "$net-source" "$source" "${common[@]}" NATTERJACK_TUNNEL_ROLE=source -- -test.run TestTunnel || status=1
	wait "$out" || status=1
	wait "$gw" || status=1
	for role in gateway outsider; do
		echo "--- $tunnel: $role"
		cat "$work/$role.log"
	done
	docker rm -f "$net-gateway" "$net-source" "$net-outsider" >/dev/null
done
exit "$status"
