#!/usr/bin/env bash
# Runs Natterjack on a real EKS cluster built by test/eks, whose VPC has no
# NAT gateway, and proves:
#   1. nodes have no way out but Natterjack: they join, and pull images,
#      through VPC endpoints only;
#   2. a release pushed to the cluster's own ECR installs, every slot is
#      attached in its own zone and every gateway passes its self-test
#      through its slot;
#   3. node traffic leaves through the bootstrap route, and once a policy
#      selects it, through its zone's gateways; images pull from the
#      internet; a selected pod leaves from its zone's Elastic IPs;
#   4. restarting every agent moves no slot and ends no connection;
#   5. draining a gateway node moves its slot to another node in the zone
#      without a failed request;
#   6. a node at its interface limit is refused and avoided, and used again
#      once it has room;
#   7. terminating a gateway instance moves new flows to the zone's other
#      gateway within the probe window, then moves its slot (both timed);
#      rebooting one does the same, and the VPC CNI leaves every slot
#      interface unmanaged across the reboot;
#   8. a deleted slot drops out of the pool, and comes back when Terraform
#      recreates it;
#   9. a broken workload identity is reported as CloudAccess with the
#      failing call, without disturbing traffic, and clears once restored;
#  10. after all of that, `terraform plan` shows no changes;
#  11. attacks are dropped: an opened slot security group quarantines every
#      slot (Enforce), and with the slots kept in use (Warn), scans of every
#      Elastic IP find nothing open, and packets for private addresses or
#      with spoofed sources sent to a slot go nowhere;
#  12. throughput through a gateway, per instance type (written to $OUT);
#  13. uninstalling detaches every slot and leaves no kernel objects.
#
# The cluster must already exist: apply test/eks with TF_VAR_run_id and
# TF_VAR_api_allowed_cidrs set, and keep them set here (steps 8 to 10 apply
# and plan the same configuration). Destroy it afterwards.
#
# Usage: OUT=dir hack/eks-e2e.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tf="$root/test/eks"
: "${OUT:?OUT is required: where results and benchmarks are written}"
: "${TF_VAR_run_id:?TF_VAR_run_id is required, as when test/eks was applied}"
: "${TF_VAR_api_allowed_cidrs:?TF_VAR_api_allowed_cidrs is required, as when test/eks was applied}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ns=natterjack
release=natterjack
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
# Pinned: the test pods' image (curl, iperf3), copied into the run's ECR
# because nodes cannot reach Docker Hub before Natterjack runs.
netshoot=docker.io/nicolaka/netshoot:v0.16@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70
# Pulled from Docker Hub by a node once Natterjack runs.
pullable=docker.io/library/busybox:1.38.0@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4

# What a failed step leaves behind is undone on exit, so the cluster can
# run the suite again: filler interfaces and cordoned nodes.
fillers=()
cordoned=()
cleanup() {
	local eni att node
	for eni in "${fillers[@]}"; do
		att="$(aws ec2 describe-network-interfaces --network-interface-ids "$eni" --query 'NetworkInterfaces[0].Attachment.AttachmentId' --output text 2>/dev/null)" || continue
		[[ "$att" == None ]] || aws ec2 detach-network-interface --attachment-id "$att" --force >/dev/null 2>&1 || true
	done
	for eni in "${fillers[@]}"; do
		aws ec2 wait network-interface-available --network-interface-ids "$eni" 2>/dev/null &&
			aws ec2 delete-network-interface --network-interface-id "$eni" 2>/dev/null || true
	done
	for node in "${cordoned[@]}"; do
		kubectl uncordon "$node" >/dev/null 2>&1 || true
	done
	rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n== %s (%s)\n' "$*" "$(date -u +%H:%M:%S)"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	kubectl get egresspools -o yaml >&2 || true
	kubectl -n "$ns" get pods -o wide >&2 || true
	for p in $(kubectl -n "$ns" get pods -o name 2>/dev/null); do
		printf -- '--- %s\n' "$p" >&2
		kubectl -n "$ns" logs "$p" --tail=80 >&2 || true
	done
	exit 1
}
eventually() {
	local secs="$1" what="$2" end
	shift 2
	end=$(($(date +%s) + secs))
	while (($(date +%s) < end)); do
		if "$@" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	fail "$what (after ${secs}s)"
}
record() { printf '%s\n' "$*" | tee -a "$OUT/results.txt"; }

outputs="$(terraform -chdir="$tf" output -json)"
# out NAME[.FIELD]: an output, or a field of an object output; fails on null.
out() {
	local path=".${1%%.*}.value"
	[[ "$1" == *.* ]] && path+=".${1#*.}"
	jq -er "$path" <<<"$outputs" || fail "no output $1"
}
cluster="$(out cluster_name)"
region="$(out region)"
registry="$(out registry)"
registry_host="${registry%%/*}"
outside_ip="$(out outside.public_ip)"
outside_id="$(out outside.instance_id)"
attacker_id="$(out attacker.instance_id)"
slot_sg="$(out slot_security_group_id)"
read -r -a zones <<<"$(jq -r '.zones.value | join(" ")' <<<"$outputs")"
export AWS_REGION="$region"
# slot_ips ZONE: the zone's Elastic IPs. slot0_ip ZONE: its first slot's,
# where the zone's bootstrap route points.
slot_ips() { jq -r --arg z "$1" '.slots.value | to_entries[] | select(.value.availability_zone == $z) | .value.public_ip' <<<"$outputs"; }
slot0_ip() { jq -r --arg z "$1" '.slots.value[$z + "/0"].public_ip' <<<"$outputs"; }
all_ips="$(jq -r '.public_ips.value[]' <<<"$outputs")"
in_zone() { grep -qxF "$2" <<<"$(slot_ips "$1")"; }
refresh_outputs() { outputs="$(terraform -chdir="$tf" output -json)"; }
tf_apply() { terraform -chdir="$tf" apply -input=false -auto-approve >"$work/apply.log" 2>&1 || fail "terraform apply failed: $(tail -n 30 "$work/apply.log")"; }

# ssm INSTANCE SCRIPT: runs SCRIPT as root on an instance and prints its
# output; fails with the script.
ssm() {
	local id="$1" script="$2" cid status
	cid="$(aws ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript \
		--parameters "$(jq -n --arg c "$script" '{commands: [$c], executionTimeout: ["900"]}')" \
		--query Command.CommandId --output text)"
	for _ in $(seq 600); do
		status="$(aws ssm get-command-invocation --command-id "$cid" --instance-id "$id" --query Status --output text 2>/dev/null || echo Pending)"
		case "$status" in Pending | InProgress | Delayed) sleep 2 ;; *) break ;; esac
	done
	aws ssm get-command-invocation --command-id "$cid" --instance-id "$id" --query StandardOutputContent --output text
	[[ "$status" == Success ]] || {
		aws ssm get-command-invocation --command-id "$cid" --instance-id "$id" --query StandardErrorContent --output text >&2
		return 1
	}
}
ssm_start() {
	aws ssm send-command --instance-ids "$1" --document-name AWS-RunShellScript \
		--parameters "$(jq -n --arg c "$2" '{commands: [$c], executionTimeout: ["900"]}')" \
		--query Command.CommandId --output text
}
ssm_result() {
	local status
	for _ in $(seq 600); do
		status="$(aws ssm get-command-invocation --command-id "$1" --instance-id "$2" --query Status --output text 2>/dev/null || echo Pending)"
		case "$status" in Pending | InProgress | Delayed) sleep 2 ;; *) break ;; esac
	done
	aws ssm get-command-invocation --command-id "$1" --instance-id "$2" --query StandardOutputContent --output text
}

step "cluster $cluster in $region"
aws eks update-kubeconfig --name "$cluster" --kubeconfig "$KUBECONFIG" >/dev/null
kubectl get nodes -L topology.kubernetes.io/zone,kubernetes.io/arch,node.kubernetes.io/instance-type
nodes_ready() { (($(kubectl get nodes --no-headers | grep -cw Ready) >= 8)); }
eventually 900 "eight nodes ready" nodes_ready
node_zone() { kubectl get node "$1" -o jsonpath='{.metadata.labels.topology\.kubernetes\.io/zone}'; }
node_instance() { kubectl get node "$1" -o jsonpath='{.spec.providerID}' | sed 's|.*/||'; }
node_ip() { kubectl get node "$1" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'; }
nodes_in() { kubectl get nodes -l "topology.kubernetes.io/zone=$1" -o jsonpath='{.items[*].metadata.name}'; }
# Per zone, one amd64 node is the test pods' source and never a gateway;
# the others (at least three: two gateways and a spare) may be gateways.
role=natterjack-e2e/role
src=()
for z in "${zones[@]}"; do
	read -r -a in <<<"$(nodes_in "$z")"
	((${#in[@]} >= 4)) || fail "zone $z has ${#in[@]} nodes; the suite needs four (a source, two gateways and a spare)"
	s="$(kubectl get nodes -l "topology.kubernetes.io/zone=$z,kubernetes.io/arch=amd64" -o jsonpath='{.items[0].metadata.name}')"
	src+=("$s")
	kubectl label node "$s" "$role=source" --overwrite >/dev/null
done
label_gateways() {
	local n
	for n in $(kubectl get nodes -l "!$role" -o jsonpath='{.items[*].metadata.name}'); do
		kubectl label node "$n" "$role=gateway" --overwrite >/dev/null
	done
}
label_gateways
src_a="${src[0]}"
src_b="${src[1]}"

step "images"
pw="$(aws ecr get-login-password)"
crane auth login "$registry_host" -u AWS -p "$pw" >/dev/null
helm registry login "$registry_host" --username AWS --password-stdin <<<"$pw" >/dev/null 2>&1
crane copy "$netshoot" "$registry/netshoot:test" >/dev/null
test_image="$registry/netshoot@$(crane digest "$registry/netshoot:test")"
version="v0.0.0-e2e.$(date -u +%Y%m%d%H%M%S)"
VERSION="$version" REGISTRY="$registry" OUT="$work/dist" "$root/hack/release.sh" >"$work/release.log" 2>&1 ||
	fail "release failed: $(tail -n 30 "$work/release.log")"
jq . "$work/dist/release.json"

step "no way out but Natterjack"
# host_pod NAME NODE: a host-network pod, as node traffic.
host_pod() {
	kubectl -n e2e apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1}
spec:
  nodeName: $2
  hostNetwork: true
  terminationGracePeriodSeconds: 0
  containers: [{name: c, image: "$test_image", command: [sleep, infinity]}]
EOF
}
pod() {
	kubectl -n e2e apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, labels: {egress: "$3"}}
spec:
  nodeName: $2
  terminationGracePeriodSeconds: 0
  containers: [{name: c, image: "$test_image", command: [sleep, infinity]}]
EOF
}
http() { kubectl -n e2e exec "$1" -- curl -fsS --max-time "${3:-5}" "http://$outside_ip/$2"; }
kubectl create namespace e2e >/dev/null
host_pod probe-a "$src_a"
kubectl -n e2e wait pod/probe-a --for=condition=Ready --timeout=300s >/dev/null || fail "a pod could not start from the run's ECR"
# The target answers (checked on itself), so a failure from the node is the
# network's: curl must time out (28) or be refused (7), not fail otherwise.
[[ "$(ssm "$outside_id" "curl -fsS --max-time 5 http://127.0.0.1/")" == 127.0.0.1 ]] || fail "the outside server does not answer"
rc=0
http probe-a "" 5 >/dev/null 2>&1 || rc=$?
case "$rc" in
0) fail "a node reached the internet before Natterjack ran" ;;
7 | 28) ;;
*) fail "the pre-install check failed for another reason (curl exit $rc)" ;;
esac
record "before install: nodes joined and pulled from ECR through VPC endpoints; the internet was unreachable"

step "install"
chart_version="${version#v}"
helm install "$release" "oci://$registry/charts/natterjack" --version "$chart_version" -n "$ns" --create-namespace \
	--set clusterName="$cluster" --set controller.aws.region="$region" >/dev/null
ds=natterjack-agent
deploy=natterjack-controller
kubectl -n "$ns" rollout status "deploy/$deploy" --timeout=300s >/dev/null || fail "controllers did not roll out"
kubectl -n "$ns" rollout status "ds/$ds" --timeout=600s >/dev/null || fail "agents did not become ready"
kubectl apply -f - >/dev/null <<EOF
apiVersion: natterjack.io/v1alpha1
kind: EgressPool
metadata: {name: default}
spec:
  gatewayNodeSelector: {natterjack-e2e/role: gateway}
  probe: {intervalMilliseconds: 200, failureThreshold: 5}
  drainSeconds: 20
EOF
slot() { kubectl get egresspool default -o jsonpath="{.status.slots[?(@.id==\"$1\")].$2}"; }
slot_ids() { kubectl get egresspool default -o jsonpath='{.status.slots[*].id}'; }
active() { kubectl get egresspool default -o jsonpath='{range .status.slots[?(@.state=="Active")]}{.id}{"\n"}{end}' | grep -c .; }
all_active() { (($(active) == $(jq '.slots.value | length' <<<"$outputs"))); }
gw_ready() {
	[[ "$(kubectl -n "$ns" get pods -l app.kubernetes.io/component=agent --field-selector spec.nodeName="$1" \
		-o jsonpath='{.items[0].status.conditions[?(@.type=="natterjack.io/gateway-ready")].status}')" == True ]]
}
eventually 600 "every slot active" all_active
for id in $(slot_ids); do
	gwn="$(slot "$id" node)"
	[[ "$(node_zone "$gwn")" == "$(slot "$id" zone)" ]] || fail "$id is on $gwn, outside its zone $(slot "$id" zone)"
	eventually 120 "$gwn passes its self-test through $id" gw_ready "$gwn"
done
kubectl get egresspool default -o wide
record "install: every slot attached in its zone; every gateway passed its self-test"
gateways() { kubectl get egresspool default -o jsonpath='{range .status.slots[?(@.state=="Active")]}{.node}{"\n"}{end}'; }
# spare_in ZONE: an eligible node that is not a gateway. gw_in ZONE: a gateway.
eligible_in() { kubectl get nodes -l "topology.kubernetes.io/zone=$1,$role=gateway" -o jsonpath='{.items[*].metadata.name}'; }
spare_in() { local n; for n in $(eligible_in "$1"); do grep -qxF "$n" <<<"$(gateways)" || { echo "$n"; return; }; done; }
gw_in() { local n; for n in $(eligible_in "$1"); do grep -qxF "$n" <<<"$(gateways)" && { echo "$n"; return; }; done; }

step "node traffic and the bootstrap route"
# Before any policy, a node's traffic follows the private route table to
# its zone's first slot.
host_pod node-a "$src_a"
host_pod node-b "$src_b"
kubectl -n e2e wait pod/node-a pod/node-b --for=condition=Ready --timeout=300s >/dev/null || fail "host pods did not start"
from() { http "$1" "" "${2:-5}"; }
eventually 120 "node traffic in ${zones[0]} leaves from its bootstrap slot" test "$(from node-a)" = "$(slot0_ip "${zones[0]}")"
eventually 60 "node traffic in ${zones[1]} leaves from its bootstrap slot" test "$(from node-b)" = "$(slot0_ip "${zones[1]}")"
kubectl apply -f - >/dev/null <<EOF
apiVersion: natterjack.io/v1alpha1
kind: ClusterEgressPolicy
metadata: {name: nodes}
spec:
  poolName: default
  nodeTraffic: true
EOF
node_steered() { in_zone "$2" "$(from "$1")"; }
eventually 60 "node traffic in ${zones[0]} is steered" node_steered node-a "${zones[0]}"
eventually 60 "node traffic in ${zones[1]} is steered" node_steered node-b "${zones[1]}"
kubectl -n e2e run pull --image="$pullable" --restart=Never --overrides="{\"spec\":{\"nodeName\":\"$src_a\"}}" -- true >/dev/null
pulled() { [[ "$(kubectl -n e2e get pod pull -o jsonpath='{.status.phase}')" == Succeeded ]]; }
eventually 300 "a node pulls an image from Docker Hub" pulled
record "node traffic: bootstrap route to $(slot0_ip "${zones[0]}") and $(slot0_ip "${zones[1]}"), then steered within its zone; Docker Hub pull worked"

step "pod traffic"
pod steered-a "$src_a" yes
pod steered-b "$src_b" yes
kubectl -n e2e wait pod/steered-a pod/steered-b --for=condition=Ready --timeout=300s >/dev/null || fail "test pods did not start"
kubectl apply -f - >/dev/null <<EOF
apiVersion: natterjack.io/v1alpha1
kind: EgressPolicy
metadata: {name: egress, namespace: e2e}
spec:
  poolName: default
  podSelector: {matchLabels: {egress: "yes"}}
EOF
eventually 60 "steered-a leaves from a ${zones[0]} Elastic IP" node_steered steered-a "${zones[0]}"
eventually 60 "steered-b leaves from a ${zones[1]} Elastic IP" node_steered steered-b "${zones[1]}"
record "pod traffic: steered-a from $(from steered-a), steered-b from $(from steered-b)"

# watch_flows ZONE POD SECONDS: opens a new connection every 200ms and
# records "<epoch ms> <address or FAIL>" to $work/flows-POD.
watch_flows() {
	kubectl -n e2e exec "$2" -- bash -c "end=\$((SECONDS + $3)); while ((SECONDS < end)); do
		a=\$(curl -fsS --max-time 1 http://$outside_ip/ 2>/dev/null) || a=FAIL; echo \"\$((\${EPOCHREALTIME/./} / 1000)) \${a:-EMPTY}\"; sleep 0.2; done" \
		>"$work/flows-$2" 2>/dev/null
}
# flow_gap POD: the longest run of failed requests, in ms (0 if none).
flow_gap() {
	awk '$2 == "FAIL" { if (!s) s = $1; e = $1 } $2 != "FAIL" { if (s && e - s + 200 > m) m = e - s + 200; s = 0 }
		END { if (s && e - s + 200 > m) m = e - s + 200; print m + 0 }' "$work/flows-$1"
}
# flows_in_zone POD ZONE: whether every answered request left from a slot in
# ZONE. The record is kept in $OUT, and each answer from elsewhere is printed
# with its time.
flows_in_zone() {
	local ms addr bad
	cp "$work/flows-$1" "$OUT/flows-$1-$(date -u +%H%M%S)"
	bad="$(awk 'NR == FNR { ok[$1] = 1; next } $2 != "FAIL" && !($2 in ok)' <(slot_ips "$2") "$work/flows-$1")"
	[[ -z "$bad" ]] && return 0
	while read -r ms addr; do
		echo "  $(jq -rn --argjson ms "$ms" '$ms / 1000 | floor | todate') $addr"
	done <<<"$bad" | head -n 20
	return 1
}

step "agent restart"
stream() {
	kubectl -n e2e exec "$1" -- curl -fsSN --max-time 900 "http://$outside_ip/stream?seconds=900" \
		>"$work/stream-$1.out" 2>"$work/stream-$1.err"
}
lines() { wc -l <"$work/stream-$1.out" | tr -d ' '; }
stream steered-a &
stream_a=$!
stream steered-b &
stream_b=$!
eventually 30 "steered-a's stream started" test -s "$work/stream-steered-a.out"
eventually 30 "steered-b's stream started" test -s "$work/stream-steered-b.out"
placement() { kubectl get egresspool default -o jsonpath='{range .status.slots[*]}{.id}={.state}@{.node} {end}'; }
before="$(placement)"
old_agents="$(kubectl -n "$ns" get pods -l app.kubernetes.io/component=agent -o jsonpath='{.items[*].metadata.uid}')"
watch_flows "${zones[0]}" steered-a 600 &
watch=$!
kubectl -n "$ns" rollout restart "ds/$ds" >/dev/null
kubectl -n "$ns" rollout status "ds/$ds" --timeout=900s >/dev/null &
rollout=$!
checks=0
while kill -0 "$rollout" 2>/dev/null; do
	[[ "$(placement)" == "$before" ]] || fail "a slot moved during the restart: $(placement), was $before"
	checks=$((checks + 1))
	sleep 1
done
wait "$rollout" || fail "the agents did not roll out again"
kill "$watch" 2>/dev/null || true
wait "$watch" 2>/dev/null || true
for uid in $(kubectl -n "$ns" get pods -l app.kubernetes.io/component=agent -o jsonpath='{.items[*].metadata.uid}'); do
	[[ " $old_agents " != *" $uid "* ]] || fail "agent pod $uid was not restarted"
done
gap="$(flow_gap steered-a)"
((gap == 0)) || fail "new connections failed for ${gap}ms during the agent restart"
flows_in_zone steered-a "${zones[0]}" || fail "a new connection left outside ${zones[0]} during the restart"
for p in steered-a steered-b; do
	n0="$(lines "$p")"
	sleep 3
	pid=stream_${p#steered-}
	kill -0 "${!pid}" 2>/dev/null || fail "$p's connection ended in the restart: $(tail -n 2 "$work/stream-$p.out") $(cat "$work/stream-$p.err")"
	(($(lines "$p") > n0)) || fail "$p's connection stalled after the restart"
	[[ "$(awk '{print $1}' "$work/stream-$p.out" | sort -u | wc -l | tr -d ' ')" == 1 ]] || fail "$p's connection changed address"
done
kill "$stream_a" "$stream_b" 2>/dev/null || true
wait "$stream_a" "$stream_b" 2>/dev/null || true
record "agent restart: no slot moved in $checks checks, no new connection failed, both long connections lived on"

step "drain"
gw="$(gw_in "${zones[0]}")"
spare="$(spare_in "${zones[0]}")"
id="$(kubectl get egresspool default -o jsonpath="{.status.slots[?(@.node==\"$gw\")].id}")"
# The test pods are on the source nodes, so draining a gateway leaves them.
watch_flows "${zones[0]}" steered-a 300 &
watch=$!
start=$(date +%s)
cordoned+=("$gw")
kubectl drain "$gw" --ignore-daemonsets --delete-emptydir-data --timeout=300s >/dev/null || fail "drain of $gw failed"
seen_draining() { [[ "$(slot "$id" state)" == Draining ]]; }
eventually 30 "$id drains" seen_draining
moved() { [[ "$(slot "$id" state)" == Active && "$(slot "$id" node)" != "$gw" && -n "$(slot "$id" node)" ]]; }
eventually 300 "$id moves off the drained node" moved
moved_after=$(($(date +%s) - start))
[[ "$(node_zone "$(slot "$id" node)")" == "${zones[0]}" ]] || fail "$id moved out of its zone"
sleep 5
kill "$watch" 2>/dev/null || true
wait "$watch" 2>/dev/null || true
gap="$(flow_gap steered-a)"
((gap == 0)) || fail "new connections failed for ${gap}ms while $gw drained"
flows_in_zone steered-a "${zones[0]}" || fail "a connection left outside ${zones[0]} during the drain"
kubectl uncordon "$gw" >/dev/null
record "drain: $id moved from $gw to $(slot "$id" node) after ${moved_after}s (drainSeconds 20); no new connection failed"
if ((moved_after > 90)); then
  # EC2 waits for the guest to release the interface; keep what the guest
  # said about it while the node still exists.
  aws ec2 get-console-output --instance-id "$(node_instance "$gw")" --latest --output text \
    --query Output >"$OUT/drain-console-$gw.txt" 2>&1 || true
  kubectl get events -A --field-selector involvedObject.kind=EgressPool -o wide >"$OUT/drain-events.txt" 2>&1 || true
  record "drain: the detach took $((moved_after - 20))s past the drain window; console output in drain-console-$gw.txt"
fi

step "interface limit"
# The zone's spare node is filled to its interface limit with extra ENIs,
# then a gateway is drained: the controller must be refused, avoid the full
# node, report why, and use it once it has room again.
gw="$(gw_in "${zones[0]}")"
spare="$(spare_in "${zones[0]}")"
spare_instance="$(node_instance "$spare")"
id="$(kubectl get egresspool default -o jsonpath="{.status.slots[?(@.node==\"$gw\")].id}")"
max="$(aws ec2 describe-instance-types --instance-types "$(kubectl get node "$spare" -o jsonpath='{.metadata.labels.node\.kubernetes\.io/instance-type}')" \
	--query 'InstanceTypes[0].NetworkInfo.MaximumNetworkInterfaces' --output text)"
used="$(aws ec2 describe-instances --instance-ids "$spare_instance" --query 'length(Reservations[0].Instances[0].NetworkInterfaces)' --output text)"
subnet="$(aws ec2 describe-instances --instance-ids "$spare_instance" --query 'Reservations[0].Instances[0].SubnetId' --output text)"
for _ in $(seq $((used + 1)) "$max"); do
	eni="$(aws ec2 create-network-interface --subnet-id "$subnet" --description "natterjack e2e filler" \
		--tag-specifications "ResourceType=network-interface,Tags=[{Key=natterjack.io/e2e,Value=$TF_VAR_run_id},{Key=node.k8s.amazonaws.com/no_manage,Value=true}]" \
		--query NetworkInterface.NetworkInterfaceId --output text)"
	fillers+=("$eni")
	idx=1
	while ! aws ec2 attach-network-interface --network-interface-id "$eni" --instance-id "$spare_instance" --device-index "$idx" >/dev/null 2>&1; do
		idx=$((idx + 1))
		((idx < 16)) || fail "could not attach filler $eni to $spare"
	done
done
echo "$spare holds $max of $max interfaces"
cordoned+=("$gw")
kubectl drain "$gw" --ignore-daemonsets --delete-emptydir-data --timeout=300s >/dev/null || fail "drain of $gw failed"
refused() { [[ "$(slot "$id" state)" == Unschedulable ]] && grep -qi "$spare" <<<"$(slot "$id" reason)"; }
eventually 300 "$id is unschedulable, naming the full node $spare" refused
record "interface limit: $id unschedulable: $(slot "$id" reason)"
[[ "$(slot "$id" node)" != "$spare" ]] || fail "$id was placed on the full node"
for eni in "${fillers[@]}"; do
	att="$(aws ec2 describe-network-interfaces --network-interface-ids "$eni" --query 'NetworkInterfaces[0].Attachment.AttachmentId' --output text)"
	aws ec2 detach-network-interface --attachment-id "$att" --force >/dev/null
done
for eni in "${fillers[@]}"; do
	aws ec2 wait network-interface-available --network-interface-ids "$eni"
	aws ec2 delete-network-interface --network-interface-id "$eni"
done
fillers=()
# The controller avoids a node that refused an attach for ten minutes, then
# tries it again on a later sync.
on_spare() { [[ "$(slot "$id" state)" == Active && "$(slot "$id" node)" == "$spare" ]]; }
eventually 720 "$id moves to $spare once it has room" on_spare
kubectl uncordon "$gw" >/dev/null
record "interface limit: once freed, $id attached to $spare"

step "gateway instance terminated"
gw="$(gw_in "${zones[0]}")"
id="$(kubectl get egresspool default -o jsonpath="{.status.slots[?(@.node==\"$gw\")].id}")"
watch_flows "${zones[0]}" steered-a 420 &
watch=$!
sleep 5
start=$(date +%s)
aws ec2 terminate-instances --instance-ids "$(node_instance "$gw")" >/dev/null
eventually 600 "$id moves off the terminated node" moved
moved_after=$(($(date +%s) - start))
sleep 10
kill "$watch" 2>/dev/null || true
wait "$watch" 2>/dev/null || true
gap="$(flow_gap steered-a)"
# The probes notice in about a second; a request in flight then can wait
# out its own one-second timeout.
((gap <= 3000)) || fail "new connections failed for ${gap}ms after the gateway died"
flows_in_zone steered-a "${zones[0]}" || fail "a new connection left outside ${zones[0]} after the gateway died"
record "failover: longest run of failed new connections ${gap}ms; $id active on $(slot "$id" node) after ${moved_after}s"
eventually 900 "the node group replaces the terminated node" nodes_ready
label_gateways

step "gateway node rebooted"
# The VPC CNI manages every interface on a node that is not tagged no_manage.
# Across a reboot it must leave the slots alone: a slot it managed would get
# secondary addresses for pods, and its Elastic IP would leave from them.
slot_enis() { jq -r '.slots.value[].network_interface_id' <<<"$outputs"; }
unmanaged() {
	local eni
	for eni in $(slot_enis); do
		[[ "$(aws ec2 describe-network-interfaces --network-interface-ids "$eni" \
			--query 'length(NetworkInterfaces[0].PrivateIpAddresses)' --output text)" == 1 ]] || return 1
	done
}
gw="$(gw_in "${zones[0]}")"
id="$(kubectl get egresspool default -o jsonpath="{.status.slots[?(@.node==\"$gw\")].id}")"
watch_flows "${zones[0]}" steered-a 600 &
watch=$!
sleep 5
start=$(date +%s)
aws ec2 reboot-instances --instance-ids "$(node_instance "$gw")" >/dev/null
node_down() { [[ "$(kubectl get node "$gw" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" != True ]]; }
eventually 300 "$gw goes down" node_down
node_up() { ! node_down; }
eventually 600 "$gw comes back" node_up
up_after=$(($(date +%s) - start))
kubectl -n "$ns" rollout status "ds/$ds" --timeout=300s >/dev/null || fail "the agent on $gw did not come back"
eventually 300 "every slot active after the reboot" all_active
for n in $(gateways); do eventually 120 "$n passes its self-test" gw_ready "$n"; done
sleep 10
kill "$watch" 2>/dev/null || true
wait "$watch" 2>/dev/null || true
gap="$(flow_gap steered-a)"
((gap <= 3000)) || fail "new connections failed for ${gap}ms after $gw rebooted"
flows_in_zone steered-a "${zones[0]}" || fail "a new connection left outside ${zones[0]} after $gw rebooted"
unmanaged || fail "the VPC CNI added addresses to a slot interface after the reboot"
record "reboot: $gw back after ${up_after}s; $id on $(slot "$id" node); longest run of failed new connections ${gap}ms; no slot interface gained a secondary address"

step "slot deleted"
id="$(jq -r --arg z "${zones[1]}" '.slots.value[$z + "/1"].network_interface_id' <<<"$outputs")"
gone_from_cloud() { ! aws ec2 describe-network-interfaces --network-interface-ids "$id" >/dev/null 2>&1; }
for _ in $(seq 30); do
	att="$(aws ec2 describe-network-interfaces --network-interface-ids "$id" --query 'NetworkInterfaces[0].Attachment.AttachmentId' --output text 2>/dev/null || true)"
	[[ -n "$att" && "$att" != None ]] && aws ec2 detach-network-interface --attachment-id "$att" --force >/dev/null 2>&1 || true
	aws ec2 delete-network-interface --network-interface-id "$id" >/dev/null 2>&1 || true
	gone_from_cloud && break
	sleep 2
done
gone_from_cloud || fail "could not delete $id"
not_listed() { ! grep -qw "$id" <<<"$(slot_ids)"; }
eventually 120 "$id leaves the pool" not_listed
eventually 60 "steered-b still leaves from ${zones[1]}" node_steered steered-b "${zones[1]}"
record "slot deleted: $id left the pool; ${zones[1]} kept serving"
tf_apply
refresh_outputs
all_ips="$(jq -r '.public_ips.value[]' <<<"$outputs")"
eventually 300 "the recreated slot becomes active" all_active
record "slot deleted: Terraform recreated it and it became active"

step "workload identity broken"
assoc="$(aws eks list-pod-identity-associations --cluster-name "$cluster" --namespace "$ns" --query 'associations[0].associationId' --output text)"
aws eks delete-pod-identity-association --cluster-name "$cluster" --association-id "$assoc" >/dev/null
cloud_access() { kubectl get egresspool default -o jsonpath='{.status.conditions[?(@.type=="CloudAccess")].status}'; }
# New pods get no credentials and are not ready, so a rollout stops while
# the running replicas keep the credentials they already hold.
kubectl -n "$ns" rollout restart "deploy/$deploy" >/dev/null
sleep 90
kubectl -n "$ns" rollout status "deploy/$deploy" --timeout=1s >/dev/null 2>&1 &&
  fail "a rollout of controller pods without credentials completed"
[[ "$(cloud_access)" == True ]] || fail "running controller replicas lost cloud access to a stalled rollout"
record "identity broken: a rollout without identity stalled; the running replicas kept cloud access"
# Replacing the pods outright leaves none with credentials.
kubectl -n "$ns" delete pods -l app.kubernetes.io/component=controller --wait=false >/dev/null
denied() { [[ "$(cloud_access)" == False ]]; }
eventually 300 "CloudAccess false" denied
why="$(kubectl get egresspool default -o jsonpath='{.status.conditions[?(@.type=="CloudAccess")].message}')"
[[ "$why" == *"this pod has no workload identity"* ]] || fail "CloudAccess does not say the pod has no workload identity: $why"
record "identity broken: CloudAccess False: $why"
node_steered steered-a "${zones[0]}" || fail "traffic stopped while the controller had no cloud access"
tf_apply
# EKS injects credentials when a pod is admitted, and a new association
# takes a moment to reach the admission webhook: restart until every
# controller pod was given them, as the troubleshooting guide says.
injected() {
	local pods
	kubectl -n "$ns" rollout status "deploy/$deploy" --timeout=60s >/dev/null || return 1
	pods="$(kubectl -n "$ns" get pods -l app.kubernetes.io/component=controller --field-selector status.phase=Running \
		-o jsonpath='{range .items[*]}{.metadata.name} {.spec.containers[0].env[*].name}{"\n"}{end}')" || return 1
	[[ -n "$pods" ]] || return 1
	while read -r line; do
		[[ -z "$line" || "$line" == *AWS_CONTAINER_CREDENTIALS_FULL_URI* ]] || return 1
	done <<<"$pods"
}
restarts=0
until injected; do
	((++restarts <= 5)) || fail "controller pods never received Pod Identity credentials"
	kubectl -n "$ns" rollout restart "deploy/$deploy" >/dev/null
	sleep 10
done
allowed() { [[ "$(cloud_access)" == True ]]; }
eventually 300 "CloudAccess true once restored" allowed
eventually 300 "every slot active" all_active
replicas_ready() {
	[[ "$(kubectl -n "$ns" get "deploy/$deploy" -o jsonpath='{.status.readyReplicas}')" == \
		"$(kubectl -n "$ns" get "deploy/$deploy" -o jsonpath='{.spec.replicas}')" ]]
}
eventually 120 "every controller replica ready, credentials included" replicas_ready
record "identity restored: CloudAccess True after $restarts restart(s); every controller replica ready"

step "Terraform sees no drift"
set +e
terraform -chdir="$tf" plan -input=false -detailed-exitcode >"$work/plan.log" 2>&1
rc=$?
set -e
((rc == 0)) || fail "terraform plan after the controller moved slots exited $rc: $(grep -E '^\s+[~+-]|will be|must be' "$work/plan.log" | head -n 40)"
record "IaC: terraform plan shows no changes after the controller moved slots"

step "attack: opened security group, Enforce"
rule="$(aws ec2 authorize-security-group-ingress --group-id "$slot_sg" --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0,Description=natterjack e2e attack}]' \
	--query 'SecurityGroupRules[0].SecurityGroupRuleId' --output text)"
quarantined() { [[ "$(kubectl get egresspool default -o jsonpath='{range .status.slots[?(@.state=="Quarantined")]}{.id}{"\n"}{end}' | grep -c .)" == "$(jq '.slots.value | length' <<<"$outputs")" ]]; }
eventually 300 "every slot quarantined" quarantined
# shellcheck disable=SC2016 # a JMESPath literal, not a shell expansion
detached() {
	local enis
	mapfile -t enis < <(jq -r '.slots.value[].network_interface_id' <<<"$outputs")
	[[ "$(aws ec2 describe-network-interfaces --network-interface-ids "${enis[@]}" \
		--query 'length(NetworkInterfaces[?Attachment.Status==`attached`])' --output text)" == 0 ]]
}
eventually 120 "every quarantined slot detached" detached
record "attack, Enforce: an inbound rule quarantined and detached every slot: $(slot "$(slot_ids | awk '{print $1}')" reason)"

step "attack: opened security group, Warn"
kubectl patch egresspool default --type=merge -p '{"spec":{"safetyChecks":"Warn"}}' >/dev/null
eventually 300 "every slot active under Warn" all_active
eventually 60 "steered-a leaves through its zone" node_steered steered-a "${zones[0]}"
gw_a="$(gw_in "${zones[0]}")"
id_a="$(kubectl get egresspool default -o jsonpath="{.status.slots[?(@.node==\"$gw_a\")].id}")"
slot_private="$(aws ec2 describe-network-interfaces --network-interface-ids "$id_a" --query 'NetworkInterfaces[0].PrivateIpAddress' --output text)"
target_ip="$(node_ip "$src_a")"
target_pod_ip="$(kubectl -n e2e get pod steered-a -o jsonpath='{.status.podIP}')"
# Scans of every Elastic IP from the internet: every TCP port, and the UDP
# ports a node listens on.
scan="$(ssm "$outside_id" "dnf -y -q install nmap >/dev/null 2>&1; nmap -Pn -n -sS -p- --min-rate 3000 --max-retries 1 -oG - $(tr '\n' ' ' <<<"$all_ips") | grep -E 'Ports:' || true;
	nmap -Pn -n -sU -p 53,123,4789,6081,8472,10250,51820,51871 --max-retries 1 -oG - $(tr '\n' ' ' <<<"$all_ips") | grep -E 'Ports:' || true")"
open="$(grep -oE '[0-9]+/open/[a-z]+' <<<"$scan" || true)"
[[ -z "$open" ]] || fail "scans found open ports on the slots' Elastic IPs: $open"
record "attack, Warn: full TCP and node UDP scans of every Elastic IP found nothing open"
# From the slot's subnet, with source/destination check off: packets for a
# node, a pod and the kubelet sent to the slot's address, and packets with
# spoofed sources (a node, a pod, the slot itself) through it to the
# internet. "outside" captures what reaches it.
cap="$(ssm_start "$outside_id" "timeout 90 tcpdump -n -i any -c 50 'not port 22 and not net 169.254.0.0/16 and (src host $(tr '\n' ' ' <<<"$all_ips" | sed 's/ $//; s/ / or src host /g'))' 2>/dev/null; true")"
sleep 10
attack="$(ssm "$attacker_id" "set -x
ip route replace $target_ip/32 via $slot_private
ip route replace $target_pod_ip/32 via $slot_private
for port in 10250 22 80 443 9100; do timeout 3 bash -c \"echo > /dev/tcp/$target_ip/\$port\" && echo REACHED $target_ip:\$port; done
timeout 3 bash -c 'echo > /dev/tcp/$target_pod_ip/80' && echo REACHED pod
ip route del $target_ip/32; ip route del $target_pod_ip/32
python3 - <<'PY'
from scapy.all import IP, TCP, UDP, ICMP, Ether, sendp, conf, getmacbyip
import subprocess
slot = '$slot_private'
mac = getmacbyip(slot)
# Sources outside the cluster's, the VPC's and the pods' ranges.
for src in ['203.0.113.7', '192.168.77.7', '100.64.9.9', '8.8.8.8']:
    for pkt in [IP(src=src, dst='$outside_ip')/ICMP(), IP(src=src, dst='$outside_ip')/TCP(dport=80, flags='S'),
                IP(src=src, dst='$outside_ip')/UDP(dport=5201)]:
        sendp(Ether(dst=mac)/pkt, iface=conf.iface, count=5, verbose=False)
print('sent spoofed packets via', slot, mac)
PY")" || fail "the attack script failed: $attack"
grep -q REACHED <<<"$attack" && fail "an attack through the slot reached something: $(grep REACHED <<<"$attack")"
captured="$(ssm_result "$cap" "$outside_id")"
grep -qE ' IP ' <<<"$captured" && fail "spoofed packets left through a slot: $(grep ' IP ' <<<"$captured" | head -n 5)"
record "attack, Warn: kubelet, node and pod addresses through the slot unreachable; spoofed sources from outside the cluster's ranges did not leave"
aws ec2 revoke-security-group-ingress --group-id "$slot_sg" --security-group-rule-ids "$rule" >/dev/null
kubectl patch egresspool default --type=merge -p '{"spec":{"safetyChecks":"Enforce"}}' >/dev/null
no_warning() { ! kubectl get egresspool default -o jsonpath='{.status.slots[*].reason}' | grep -qi "inbound"; }
eventually 300 "the warnings clear once the rule is gone" no_warning

step "throughput"
# Through a gateway of each instance type in the cluster, from a pod on
# another node in the zone, to "outside".
: >"$OUT/bench.json.tmp"
for arch in amd64 arm64; do
	kubectl patch egresspool default --type=merge -p "{\"spec\":{\"gatewayNodeSelector\":{\"$role\":\"gateway\",\"kubernetes.io/arch\":\"$arch\"}}}" >/dev/null
	on_arch() {
		local n
		for n in $(gateways); do [[ "$(kubectl get node "$n" -o jsonpath='{.metadata.labels.kubernetes\.io/arch}')" == "$arch" ]] || return 1; done
		(($(active) >= 1))
	}
	eventually 600 "gateways move to $arch nodes" on_arch
	gwn="$(gateways | head -n 1)"
	zone="$(node_zone "$gwn")"
	type="$(kubectl get node "$gwn" -o jsonpath='{.metadata.labels.node\.kubernetes\.io/instance-type}')"
	srcn="$src_a"
	[[ "$zone" == "${zones[0]}" ]] || srcn="$src_b"
	kubectl -n e2e delete pod bench --ignore-not-found --wait=true >/dev/null
	pod bench "$srcn" yes
	kubectl -n e2e wait pod/bench --for=condition=Ready --timeout=300s >/dev/null || fail "bench pod did not start"
	eventually 60 "bench leaves through $zone" node_steered bench "$zone"
	up="$(kubectl -n e2e exec bench -- iperf3 -c "$outside_ip" -P 8 -t 20 -J | jq '.end.sum_received.bits_per_second')"
	down="$(kubectl -n e2e exec bench -- iperf3 -c "$outside_ip" -P 8 -t 20 -R -J | jq '.end.sum_received.bits_per_second')"
	jq -n --arg type "$type" --arg arch "$arch" --argjson up "$up" --argjson down "$down" \
		'{gateway: $type, arch: $arch, egress_gbps: ($up / 1e9 * 100 | round / 100), ingress_gbps: ($down / 1e9 * 100 | round / 100)}' >>"$OUT/bench.json.tmp"
	record "throughput through a $type gateway: $(tail -n 6 "$OUT/bench.json.tmp" | jq -c . 2>/dev/null || true)"
done
jq -s . "$OUT/bench.json.tmp" >"$OUT/bench.json"
rm "$OUT/bench.json.tmp"
kubectl patch egresspool default --type=merge -p "{\"spec\":{\"gatewayNodeSelector\":{\"kubernetes.io/arch\":null}}}" >/dev/null
eventually 600 "every slot active" all_active

step "uninstall"
kubectl delete clusteregresspolicy nodes >/dev/null
kubectl delete egresspolicy -n e2e egress >/dev/null
kubectl delete egresspool default --wait=true --timeout=300s >/dev/null || fail "the pool was not deleted"
eventually 300 "every slot detached once the pool is gone" detached
helm uninstall "$release" -n "$ns" --wait --timeout 300s --debug >"$work/uninstall.log" 2>&1 ||
	fail "uninstall failed: $(grep -iE 'error|fail' "$work/uninstall.log" | tail -n 20)"
for n in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
	left="$(ssm "$(node_instance "$n")" "nft list tables; ip -br link; ip rule" | grep -E 'natterjack|nj(gw|tun|wg|d0)' || true)"
	[[ -z "$left" ]] || fail "$n still holds Natterjack kernel objects: $left"
done
record "uninstall: every slot detached; no kernel objects left on any node"
echo PASS
