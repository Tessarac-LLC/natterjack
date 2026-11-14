#!/usr/bin/env bash
# Installs the chart on a throwaway kind cluster and proves, on a real API
# server and real nodes:
#   1. every agent is ready and both controllers run, with no RBAC denials;
#   2. RBAC grants nothing beyond what each component uses;
#   3. the admission policies hold: an agent changes only its own pod's
#      status, the controller only natterjack.io/ metadata on agent pods;
#   4. an agent recovers within one resync once a node problem is fixed;
#   5. uninstalling removes every kernel object and keeps the CRDs.
# The controller has no cloud credentials here, so its leader is not ready;
# slot assignment is covered by the envtest suite and the EKS end-to-end run.
#
# Usage: hack/chart-e2e.sh [kindest/node image]
set -euo pipefail

node_image="${1:-kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cluster="natterjack-e2e-$$"
ns=natterjack
release=e2e
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"

cleanup() {
	if [[ "${KEEP_CLUSTER:-}" != "1" ]]; then
		kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	kubectl -n "$ns" get pods -o wide >&2 || true
	for p in $(kubectl -n "$ns" get pods -o name 2>/dev/null); do
		printf -- '--- %s\n' "$p" >&2
		kubectl -n "$ns" logs "$p" --tail=40 >&2 || true
	done
	exit 1
}
nodes() { kind get nodes --name "$cluster"; }
sysctl_all() { for n in $(nodes); do docker exec "$n" sysctl -qw "net.ipv4.conf.all.rp_filter=$1"; done; }

step "cluster $cluster on $node_image"
cat >"$work/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
    labels:
      topology.kubernetes.io/zone: zone-a
  - role: worker
    labels:
      topology.kubernetes.io/zone: zone-b
EOF
kind create cluster --name "$cluster" --image "$node_image" --config "$work/kind.yaml" --wait 180s
# The agent refuses strict reverse-path filtering, which the Docker host
# hands down to kind nodes; EKS AMIs ship loose mode.
sysctl_all 2

step "images"
export KO_DOCKER_REPO=kind.local KIND_CLUSTER_NAME="$cluster" GOWORK=off
platform="linux/$(docker version --format '{{.Server.Arch}}')"
controller_image="$(cd "$root" && ko build --platform="$platform" --bare --tags e2e ./cmd/controller)"
agent_image="$(cd "$root" && ko build --platform="$platform" --bare --tags e2e ./cmd/agent)"
# Both land in one repository; tell them apart by digest.
controller_digest="${controller_image##*@}" agent_digest="${agent_image##*@}"
[[ "$controller_digest" == sha256:* && "$agent_digest" == sha256:* ]] || fail "ko printed no digests: $controller_image $agent_image"

step "install"
helm install "$release" "$root/charts/natterjack" -n "$ns" --create-namespace \
	--set clusterName=e2e --set controller.aws.region=us-east-1 \
	--set controller.image.repository=kind.local --set controller.image.digest="$controller_digest" \
	--set agent.image.repository=kind.local --set agent.image.digest="$agent_digest" \
	--set images.pullPolicy=Never
ds="natterjack-$release-agent"
kubectl -n "$ns" rollout status "ds/$ds" --timeout=180s || fail "agents did not become ready"
kubectl -n "$ns" wait pod -l app.kubernetes.io/component=controller --for=jsonpath='{.status.phase}'=Running --timeout=120s >/dev/null ||
	fail "controllers did not start"
holder=""
for _ in $(seq 60); do
	holder="$(kubectl -n "$ns" get lease natterjack-controller -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)"
	[[ -n "$holder" ]] && break
	sleep 2
done
[[ -n "$holder" ]] || fail "no controller holds the leader lease"
echo "leader: $holder"

step "no RBAC denials in any log"
sleep 20 # one agent resync and a controller pass
if kubectl -n "$ns" logs -l app.kubernetes.io/part-of=natterjack --tail=-1 --prefix | grep -iE 'forbidden|is not allowed|cannot (get|list|watch|patch|create|update)'; then
	fail "a component was denied an API call it makes"
fi

step "RBAC grants nothing extra"
agent_sa="system:serviceaccount:$ns:natterjack-$release-agent"
controller_sa="system:serviceaccount:$ns:natterjack-$release-controller"
deny() { # subject verb resource [namespace]
	if kubectl auth can-i --as="$1" "$2" "$3" ${4:+-n "$4"} >/dev/null 2>&1; then fail "$1 may $2 $3 ${4:-cluster-wide}"; fi
}
allow() {
	kubectl auth can-i --as="$1" "$2" "$3" ${4:+-n "$4"} >/dev/null 2>&1 || fail "$1 may not $2 $3 ${4:-cluster-wide}"
}
allow "$agent_sa" patch pods/status "$ns"
allow "$agent_sa" list pods
deny "$agent_sa" patch pods "$ns"
deny "$agent_sa" patch pods/status default
deny "$agent_sa" create pods "$ns"
deny "$agent_sa" get secrets "$ns"
deny "$agent_sa" get secrets
deny "$agent_sa" get configmaps "$ns"
deny "$agent_sa" create pods/exec "$ns"
deny "$agent_sa" patch nodes
deny "$agent_sa" patch egresspools.natterjack.io
deny "$agent_sa" update daemonsets.apps "$ns"
allow "$controller_sa" patch pods "$ns"
allow "$controller_sa" patch egresspools.natterjack.io/status
deny "$controller_sa" patch pods default
deny "$controller_sa" delete pods "$ns"
deny "$controller_sa" create pods "$ns"
deny "$controller_sa" patch pods/status "$ns"
deny "$controller_sa" get secrets "$ns"
deny "$controller_sa" get secrets
deny "$controller_sa" patch nodes
deny "$controller_sa" create pods/exec "$ns"
deny "$controller_sa" patch egresspools.natterjack.io
echo "ok"

step "admission policies"
mapfile -t agents < <(kubectl -n "$ns" get pods -l app.kubernetes.io/component=agent -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[[ ${#agents[@]} -ge 2 ]] || fail "expected an agent on every node, got ${#agents[@]}"
mapfile -t controllers < <(kubectl -n "$ns" get pods -l app.kubernetes.io/component=controller -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
# Tokens bound to a pod carry its name, exactly as the running pods' do.
agent_token="$(kubectl -n "$ns" create token "natterjack-$release-agent" --bound-object-kind Pod --bound-object-name "${agents[0]}" --duration 10m)"
controller_token="$(kubectl -n "$ns" create token "natterjack-$release-controller" --bound-object-kind Pod --bound-object-name "${controllers[0]}" --duration 10m)"
# A kubeconfig holding only the token: kind's admin client certificate must
# not ride along, or the API server would authenticate the request as admin.
server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d >"$work/ca.crt"
as() { # token, kubectl args...
	local token="$1"
	shift
	KUBECONFIG=/dev/null kubectl --server="$server" --certificate-authority="$work/ca.crt" --token="$token" "$@"
}
whoami="$(as "$agent_token" auth whoami -o jsonpath='{.status.userInfo.username}')"
[[ "$whoami" == "$agent_sa" ]] || fail "the agent token authenticates as $whoami"
condition='{"status":{"conditions":[{"type":"natterjack.io/e2e","status":"True","reason":"Test","message":"admission test"}]}}'
as "$agent_token" -n "$ns" patch pod "${agents[0]}" --subresource=status --type=strategic -p "$condition" >/dev/null ||
	fail "an agent may not change its own pod's status"
if out="$(as "$agent_token" -n "$ns" patch pod "${agents[1]}" --subresource=status --type=strategic -p "$condition" 2>&1)"; then
	fail "an agent changed another agent's status"
fi
grep -q "only change its own pod" <<<"$out" || fail "denied for the wrong reason: $out"

as "$controller_token" -n "$ns" label pod "${agents[0]}" natterjack.io/e2e=yes >/dev/null ||
	fail "the controller may not label an agent pod natterjack.io/"
as "$controller_token" -n "$ns" label pod "${agents[0]}" natterjack.io/e2e- >/dev/null
if out="$(as "$controller_token" -n "$ns" label pod "${agents[0]}" example.com/e2e=yes 2>&1)"; then
	fail "the controller set a label outside natterjack.io/"
fi
grep -q "natterjack.io/ labels and annotations" <<<"$out" || fail "denied for the wrong reason: $out"
if out="$(as "$controller_token" -n "$ns" label pod "${agents[0]}" app.kubernetes.io/component=other --overwrite 2>&1)"; then
	fail "the controller relabelled an agent pod"
fi
if out="$(as "$controller_token" -n "$ns" label pod "${controllers[0]}" natterjack.io/e2e=yes 2>&1)"; then
	fail "the controller labelled a pod that is not an agent"
fi
grep -q "only change agent pods" <<<"$out" || fail "denied for the wrong reason: $out"
echo "ok"

step "an agent recovers within one resync once its node is fixed"
victim="$(kubectl -n "$ns" get pod "${agents[0]}" -o jsonpath='{.spec.nodeName}')"
docker exec "$victim" sysctl -qw net.ipv4.conf.all.rp_filter=1
kubectl -n "$ns" delete pod "${agents[0]}" --wait=true >/dev/null
sleep 5
fresh="$(kubectl -n "$ns" get pods -l app.kubernetes.io/component=agent --field-selector "spec.nodeName=$victim" -o jsonpath='{.items[0].metadata.name}')"
# Long enough for an uncapped backoff to grow far past the resync.
sleep 150
[[ "$(kubectl -n "$ns" get pod "$fresh" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" == "False" ]] ||
	fail "the agent was ready with strict reverse-path filtering"
docker exec "$victim" sysctl -qw net.ipv4.conf.all.rp_filter=2
fixed="$(date +%s)"
kubectl -n "$ns" wait pod "$fresh" --for=condition=Ready --timeout=60s >/dev/null || fail "the agent did not recover within a minute"
echo "ready $(($(date +%s) - fixed))s after the fix"

step "uninstall removes the data path and keeps the CRDs"
for n in $(nodes); do
	docker exec "$n" ip link show nj0 >/dev/null 2>&1 || fail "no tunnel link on $n before uninstall"
done
helm uninstall "$release" -n "$ns" --wait --timeout 120s
for n in $(nodes); do
	for _ in $(seq 30); do
		docker exec "$n" ip link show nj0 >/dev/null 2>&1 || break
		sleep 2
	done
	if docker exec "$n" ip link show nj0 >/dev/null 2>&1; then fail "tunnel link left on $n"; fi
	if docker exec "$n" nft list table ip natterjack >/dev/null 2>&1; then fail "nftables table left on $n"; fi
done
for crd in egresspools egresspolicies clusteregresspolicies; do
	kubectl get crd "$crd.natterjack.io" >/dev/null || fail "CRD $crd was removed"
done
echo "ok"

printf '\nPASS\n'
