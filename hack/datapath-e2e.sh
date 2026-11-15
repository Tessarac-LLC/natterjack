#!/usr/bin/env bash
# Runs real egress traffic through Natterjack on a throwaway kind cluster.
# hack/fakecloud stands in for EC2 and the internet: the controller's AWS
# provider talks to it as it would to EC2, attaching a slot moves a real
# interface with the slot's MAC into the node, and the fake internet host
# answers with the address it sees, after the fake VPC has translated a
# slot's private address to its Elastic IP. It proves, per CNI:
#   1. a slot that fails a safety check is quarantined and never attached;
#   2. every zone's usable slot is attached to a node in its zone and its
#      gateway passes the self-test through the slot;
#   3. a selected pod leaves from its own zone's Elastic IP; an
#      unselected pod and the node leave from the node's address;
#   4. traffic to an excluded destination is not steered;
#   5. when a gateway node dies, new flows take another zone's gateway
#      within seconds, then its slot moves to another node in the zone and
#      the pod leaves from the same Elastic IP again;
#   6. uninstalling removes every kernel object and every attachment.
# With MESH set, the test pods run in that service mesh, whose proxies
# redirect their traffic and mark their own sockets: istio (sidecars),
# ambient (Istio's ztunnel) or linkerd.
#
# Usage: [MESH=istio|ambient|linkerd] hack/datapath-e2e.sh [kindnet|cilium|calico] [kindest/node image]
set -euo pipefail

cni="${1:-kindnet}"
node_image="${2:-kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}"
mesh="${MESH:-}"
case "$cni" in kindnet | cilium | calico) ;; *)
	echo "unknown CNI $cni; want kindnet, cilium or calico" >&2
	exit 2
	;;
esac
case "$mesh" in "" | istio | ambient | linkerd) ;; *)
	echo "unknown mesh $mesh; want istio, ambient or linkerd" >&2
	exit 2
	;;
esac
root="$(cd "$(dirname "$0")/.." && pwd)"
cluster="nj-dp-$cni${mesh:+-$mesh}-$$"
cloud="$cluster-cloud"
ns=natterjack
release=dp
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
# Pinned: the fake cloud's container and the test pods.
alpine=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

cleanup() {
	if [[ "${KEEP_CLUSTER:-}" != "1" ]]; then
		kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
		docker rm -f "$cloud" >/dev/null 2>&1 || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	kubectl get egresspools -o yaml >&2 || true
	kubectl -n "$ns" get pods -o wide >&2 || true
	for p in $(kubectl -n "$ns" get pods -o name 2>/dev/null); do
		printf -- '--- %s\n' "$p" >&2
		kubectl -n "$ns" logs "$p" --tail=60 >&2 || true
	done
	printf -- '--- fake cloud\n' >&2
	docker logs --tail=60 "$cloud" >&2 || true
	fake_state >&2 || true
	exit 1
}
# eventually SECONDS DESCRIPTION COMMAND...: retries COMMAND every second.
eventually() {
	local secs="$1" what="$2"
	shift 2
	for _ in $(seq "$secs"); do
		if "$@" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	fail "$what (after ${secs}s)"
}

# Topology: zone-a has three workers and one usable slot, plus one that
# fails the safety checks; zone-b has two workers and one usable slot. A
# test pod runs on a zone's non-gateway worker, and in zone-a a spare
# worker is left for the slot to move to.
workers=(worker worker2 worker3 worker4 worker5)
zones=(zone-a zone-a zone-a zone-b zone-b)
instance() { printf 'i-%016x' "$1"; }

step "cluster $cluster ($cni${mesh:+, $mesh}) on $node_image"
{
	cat <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
EOF
	if [[ "$cni" != kindnet ]]; then
		cat <<EOF
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
EOF
	fi
	cat <<EOF
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            - name: provider-id
              value: aws:///zone-c/$(instance 9)
EOF
	for i in "${!workers[@]}"; do
		cat <<EOF
  - role: worker
    labels:
      topology.kubernetes.io/zone: ${zones[$i]}
    kubeadmConfigPatches:
      - |
        kind: JoinConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            - name: provider-id
              value: aws:///${zones[$i]}/$(instance $((i + 1)))
EOF
	done
} >"$work/kind.yaml"
kind create cluster --name "$cluster" --image "$node_image" --config "$work/kind.yaml" --wait 0s
node() { printf '%s-%s' "$cluster" "$1"; }

step "CNI"
case "$cni" in
kindnet) ;;
cilium)
	api_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(node control-plane)")"
	helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
	helm repo update cilium >/dev/null
	# kube-proxy-free with eBPF host routing: pod traffic goes from the
	# pod's device to the uplink without the host's netfilter hooks.
	helm install cilium cilium/cilium --version "${CILIUM_VERSION:?set CILIUM_VERSION}" -n kube-system \
		--set kubeProxyReplacement=true --set k8sServiceHost="$api_ip" --set k8sServicePort=6443 \
		--set bpf.masquerade=true --set routingMode=native --set autoDirectNodeRoutes=true \
		--set ipv4NativeRoutingCIDR=10.244.0.0/16 --set ipam.mode=kubernetes \
		--set image.pullPolicy=IfNotPresent --set operator.replicas=1 --wait --timeout 10m
	;;
calico)
	api_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(node control-plane)")"
	v="${CALICO_VERSION:?set CALICO_VERSION}"
	kubectl create -f "https://raw.githubusercontent.com/projectcalico/calico/$v/manifests/operator-crds.yaml"
	kubectl create -f "https://raw.githubusercontent.com/projectcalico/calico/$v/manifests/tigera-operator.yaml"
	# The eBPF data plane needs the API server's address without kube-proxy.
	kubectl create -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata: {name: kubernetes-services-endpoint, namespace: tigera-operator}
data: {KUBERNETES_SERVICE_HOST: "$api_ip", KUBERNETES_SERVICE_PORT: "6443"}
EOF
	eventually 120 "Installation CRD" kubectl get crd installations.operator.tigera.io
	kubectl create -f - <<EOF
apiVersion: operator.tigera.io/v1
kind: Installation
metadata: {name: default}
spec:
  calicoNetwork:
    linuxDataplane: BPF
    bgp: Disabled
    ipPools:
      - {cidr: 10.244.0.0/16, encapsulation: VXLAN, natOutgoing: Enabled, nodeSelector: all()}
---
apiVersion: operator.tigera.io/v1
kind: APIServer
metadata: {name: default}
spec: {}
EOF
	eventually 600 "calico ready" kubectl wait --for=condition=Available tigerastatus/calico --timeout=1s
	;;
esac
kubectl wait --for=condition=Ready nodes --all --timeout=600s >/dev/null || fail "nodes not ready"
# The agent refuses strict reverse-path filtering, which the Docker host
# hands down to kind nodes; EKS AMIs ship loose mode.
for n in $(kind get nodes --name "$cluster"); do docker exec "$n" sysctl -qw net.ipv4.conf.all.rp_filter=2; done

if [[ -n "$mesh" ]]; then
	step "mesh"
	helm repo add istio https://istio-release.storage.googleapis.com/charts >/dev/null 2>&1 || true
	helm repo add linkerd-edge https://helm.linkerd.io/edge >/dev/null 2>&1 || true
	helm repo update istio linkerd-edge >/dev/null
	case "$mesh" in
	istio)
		iv="${ISTIO_VERSION:?set ISTIO_VERSION}"
		helm install istio-base istio/base -n istio-system --create-namespace --version "$iv" --wait >/dev/null
		helm install istiod istio/istiod -n istio-system --version "$iv" --wait --timeout 10m >/dev/null
		;;
	ambient)
		iv="${ISTIO_VERSION:?set ISTIO_VERSION}"
		helm install istio-base istio/base -n istio-system --create-namespace --version "$iv" --wait >/dev/null
		helm install istiod istio/istiod -n istio-system --version "$iv" --set profile=ambient --wait --timeout 10m >/dev/null
		helm install istio-cni istio/cni -n istio-system --version "$iv" --set profile=ambient --wait --timeout 10m >/dev/null
		helm install ztunnel istio/ztunnel -n istio-system --version "$iv" --wait --timeout 10m >/dev/null
		;;
	linkerd)
		kubectl apply --server-side -f \
			"https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION:?set GATEWAY_API_VERSION}/experimental-install.yaml" >/dev/null
		# Linkerd's identity needs a trust anchor and an issuer under it.
		pki="$work/linkerd"
		mkdir -p "$pki"
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=root.linkerd.cluster.local \
			-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
			-keyout "$pki/ca.key" -out "$pki/ca.crt" 2>/dev/null
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=identity.linkerd.cluster.local \
			-keyout "$pki/issuer.key" -out "$pki/issuer.csr" 2>/dev/null
		printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$pki/issuer.ext"
		openssl x509 -req -in "$pki/issuer.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" -CAcreateserial -days 2 \
			-extfile "$pki/issuer.ext" -out "$pki/issuer.crt" 2>/dev/null
		lv="${LINKERD_VERSION:?set LINKERD_VERSION}"
		helm install linkerd-crds linkerd-edge/linkerd-crds -n linkerd --create-namespace --version "$lv" --wait >/dev/null
		helm install linkerd-control-plane linkerd-edge/linkerd-control-plane -n linkerd --version "$lv" \
			--set-file identityTrustAnchorsPEM="$pki/ca.crt" \
			--set-file identity.issuer.tls.crtPEM="$pki/issuer.crt" \
			--set-file identity.issuer.tls.keyPEM="$pki/issuer.key" --wait --timeout 10m >/dev/null
		;;
	esac
fi

step "fake cloud"
cat >"$work/config.json" <<EOF
{
  "cluster": "e2e", "vpc": "vpc-fake", "nodePublicIP": "198.51.100.200",
  "subnets": [
    {"id": "subnet-a", "zone": "zone-a", "cidr": "10.250.1.0/24"},
    {"id": "subnet-b", "zone": "zone-b", "cidr": "10.250.2.0/24"}
  ],
  "securityGroups": [{"id": "sg-closed"}],
  "slots": [
    {"id": "eni-a1", "subnet": "subnet-a", "privateIP": "10.250.1.10", "publicIP": "198.51.100.11",
     "mac": "02:4e:4a:01:00:0a", "groups": ["sg-closed"],
     "tags": {"natterjack.io/egress": "true", "natterjack.io/cluster": "e2e", "node.k8s.amazonaws.com/no_manage": "true"}},
    {"id": "eni-a9", "subnet": "subnet-a", "privateIP": "10.250.1.99",
     "mac": "02:4e:4a:01:00:63", "groups": ["sg-closed"], "sourceDestCheck": true,
     "tags": {"natterjack.io/egress": "true", "natterjack.io/cluster": "e2e", "node.k8s.amazonaws.com/no_manage": "true"}},
    {"id": "eni-b1", "subnet": "subnet-b", "privateIP": "10.250.2.10", "publicIP": "198.51.100.21",
     "mac": "02:4e:4a:02:00:0a", "groups": ["sg-closed"],
     "tags": {"natterjack.io/egress": "true", "natterjack.io/cluster": "e2e", "node.k8s.amazonaws.com/no_manage": "true"}}
  ],
  "instances": [
$(for i in "${!workers[@]}"; do
	printf '    {"id": "%s", "zone": "%s", "node": "%s", "tags": {"kubernetes.io/cluster/e2e": "owned"}},\n' \
		"$(instance $((i + 1)))" "${zones[$i]}" "$(node "${workers[$i]}")"
done)
    {"id": "$(instance 9)", "zone": "zone-c", "node": "$(node control-plane)", "tags": {"kubernetes.io/cluster/e2e": "owned"}}
  ]
}
EOF
arch="$(docker version --format '{{.Server.Arch}}')"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOWORK=off go build -o "$work/fakecloud" ./hack/fakecloud)
mkdir -p "$work/out"
# Privileged in the host's process namespace: it moves interfaces into the
# kind nodes' network namespaces, as EC2 moves an ENI to an instance.
docker run -d --name "$cloud" --privileged --pid=host --network kind \
	-v "$work:/fakecloud" "$alpine" \
	sh -c 'apk add -q --no-progress nftables iproute2 >/dev/null && exec /fakecloud/fakecloud' >/dev/null
cloud_ip="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$cloud")"
eventually 120 "fake cloud ready" test -f "$work/out/ready"
for n in $(kind get nodes --name "$cluster"); do
	docker exec "$n" ip route replace 203.0.113.0/24 via "$cloud_ip"
done
whoami_from() { docker exec "$1" curl -fsS --max-time 5 http://203.0.113.1/; }
# The fake's admin API is asked from a node: the kind network is not
# routable from the host on every platform (Docker Desktop on macOS).
fake_state() { docker exec "$cluster-control-plane" curl -fsS --max-time 5 "http://$cloud_ip:4566/_fake/state"; }
[[ "$(whoami_from "$(node worker)")" == 198.51.100.200 ]] || fail "a node does not reach the fake internet through the fake NAT"

step "images"
export KO_DOCKER_REPO=ko.local GOWORK=off VERSION=v0.0.0-e2e
platform="linux/$arch"
for c in controller agent natterjack; do
	(cd "$root" && ko build --local --platform="$platform" --base-import-paths --tags e2e "./cmd/$c" >/dev/null)
	kind load docker-image --name "$cluster" "ko.local/$c:e2e"
done
# Built for this platform alone: kind cannot load a multi-platform image
# whose other platforms the Docker host never pulled.
printf 'FROM %s\n' "$alpine" | docker build -q --provenance=false --platform="$platform" -t natterjack-e2e/alpine:test - >/dev/null
kind load docker-image --name "$cluster" natterjack-e2e/alpine:test

step "install"
helm install "$release" "$root/charts/natterjack" -n "$ns" --create-namespace \
	--set clusterName=e2e --set controller.aws.region=us-east-1 \
	--set controller.image.repository=ko.local/controller --set controller.image.tag=e2e \
	--set agent.image.repository=ko.local/agent --set agent.image.tag=e2e \
	--set doctor.image.repository=ko.local/natterjack --set doctor.image.tag=e2e \
	--set images.pullPolicy=Never --set agent.selfTest.url=https://203.0.113.1/ \
	--set agent.selfTest.interval=5s
ds="natterjack-$release-agent"
deploy="natterjack-$release-controller"
# Test only: the controller talks to the fake, and the agents trust its CA.
kubectl -n "$ns" set env "deploy/$deploy" AWS_ENDPOINT_URL_EC2="http://$cloud_ip:4566" \
	AWS_ACCESS_KEY_ID=fake AWS_SECRET_ACCESS_KEY=fake AWS_EC2_METADATA_DISABLED=true >/dev/null
kubectl -n "$ns" create configmap fakecloud-ca --from-file=ca.crt="$work/out/ca.crt" >/dev/null
kubectl -n "$ns" patch ds "$ds" --type=json -p '[
  {"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "fakecloud-ca", "configMap": {"name": "fakecloud-ca"}}},
  {"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-", "value": {"name": "fakecloud-ca", "mountPath": "/etc/fakecloud", "readOnly": true}},
  {"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": "SSL_CERT_FILE", "value": "/etc/fakecloud/ca.crt"}}
]' >/dev/null
if [[ "$cni" == calico ]]; then
	# Calico keeps its marks in 0xffff0000, over the agent's default bits.
	# The agents must say so, and steer once given bits of their own.
	mark_clash() {
		grep -q "table ip calico.*agent.markMask" <<<"$(kubectl -n "$ns" get pods -l app.kubernetes.io/component=agent \
			-o jsonpath='{.items[*].status.conditions[?(@.type=="natterjack.io/dataplane-ready")].message}')"
	}
	eventually 180 "the agents report Calico's use of their mark bits" mark_clash
	helm upgrade "$release" "$root/charts/natterjack" -n "$ns" --reuse-values --set agent.markMask=0x00003f00 >/dev/null
fi
kubectl -n "$ns" rollout status "deploy/$deploy" --timeout=180s >/dev/null || fail "controllers did not roll out"
kubectl -n "$ns" rollout status "ds/$ds" --timeout=300s >/dev/null || fail "agents did not become ready"

step "slots"
kubectl apply -f - <<EOF >/dev/null
apiVersion: natterjack.io/v1alpha1
kind: EgressPool
metadata: {name: default}
spec:
  probe: {intervalMilliseconds: 200, failureThreshold: 5}
EOF
slot() { kubectl get egresspool default -o jsonpath="{.status.slots[?(@.id==\"$1\")].$2}"; }
slot_is() { [[ "$(slot "$1" state)" == "$2" ]]; }
eventually 180 "eni-a1 active" slot_is eni-a1 Active
eventually 60 "eni-b1 active" slot_is eni-b1 Active
eventually 60 "eni-a9 quarantined" slot_is eni-a9 Quarantined
grep -q "source/destination check" <<<"$(slot eni-a9 reason)" || fail "eni-a9's reason does not name the failed check: $(slot eni-a9 reason)"
attached="$(fake_state)"
grep -q '"eni-a9"' <<<"$attached" && fail "the quarantined slot was attached: $attached"
gw_a="$(slot eni-a1 node)"
gw_b="$(slot eni-b1 node)"
echo "gateways: zone-a $gw_a, zone-b $gw_b"
[[ " $(node worker) $(node worker2) $(node worker3) " == *" $gw_a "* ]] || fail "eni-a1 is on $gw_a, outside zone-a"
[[ " $(node worker4) $(node worker5) " == *" $gw_b "* ]] || fail "eni-b1 is on $gw_b, outside zone-b"
gw_ready() {
	[[ "$(kubectl -n "$ns" get pods -l app.kubernetes.io/component=agent --field-selector spec.nodeName="$1" \
		-o jsonpath='{.items[0].status.conditions[?(@.type=="natterjack.io/gateway-ready")].status}')" == True ]]
}
eventually 120 "the zone-a gateway passes its self-test" gw_ready "$gw_a"
eventually 60 "the zone-b gateway passes its self-test" gw_ready "$gw_b"

step "traffic"
# A selected and an unselected pod on a non-gateway worker in each zone.
pick() {
	local zone="$1" skip="$2" i
	for i in "${!workers[@]}"; do
		[[ "${zones[$i]}" == "$zone" && "$(node "${workers[$i]}")" != "$skip" ]] && {
			node "${workers[$i]}"
			return
		}
	done
}
pod_a="$(pick zone-a "$gw_a")"
pod_b="$(pick zone-b "$gw_b")"
kubectl create namespace app >/dev/null
case "$mesh" in
istio) kubectl label namespace app istio-injection=enabled >/dev/null ;;
ambient) kubectl label namespace app istio.io/dataplane-mode=ambient >/dev/null ;;
linkerd) kubectl annotate namespace app linkerd.io/inject=enabled >/dev/null ;;
esac
kubectl -n app create configmap fakecloud-ca --from-file=ca.crt="$work/out/ca.crt" >/dev/null
run_pod() {
	kubectl -n app apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, labels: {egress: "$3"}}
spec:
  nodeName: $2
  terminationGracePeriodSeconds: 0
  containers:
    - name: c
      image: natterjack-e2e/alpine:test
      imagePullPolicy: Never
      command: [sleep, infinity]
      volumeMounts: [{name: ca, mountPath: /etc/fakecloud}]
  volumes: [{name: ca, configMap: {name: fakecloud-ca}}]
EOF
}
run_pod steered-a "$pod_a" "yes"
run_pod steered-b "$pod_b" "yes"
run_pod plain-a "$pod_a" "no"
kubectl -n app wait pod --all --for=condition=Ready --timeout=300s >/dev/null || fail "test pods did not start"
# The mesh must really have taken the pods' traffic, or the test proves
# nothing about it.
containers() { kubectl -n app get pod "$1" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}'; }
meshed() {
	case "$mesh" in
	istio) grep -qw istio-proxy <<<"$(containers "$1")" ;;
	ambient) [[ "$(kubectl -n app get pod "$1" -o jsonpath='{.metadata.annotations.ambient\.istio\.io/redirection}')" == enabled ]] ;;
	linkerd) grep -qw linkerd-proxy <<<"$(containers "$1")" ;;
	esac
}
if [[ -n "$mesh" ]]; then
	for p in steered-a steered-b plain-a; do meshed "$p" || fail "$p is not in the $mesh mesh"; done
fi
kubectl apply -f - >/dev/null <<EOF
apiVersion: natterjack.io/v1alpha1
kind: EgressPolicy
metadata: {name: egress, namespace: app}
spec:
  poolName: default
  podSelector: {matchLabels: {egress: "yes"}}
  excludedCIDRs: [203.0.113.0/30]
EOF
# 203.0.113.0/30 holds the internet host, so it is excluded; the HTTPS
# check goes through the same host's 203.0.113.1 and must therefore leave
# unsteered. A second address on the host is not excluded.
docker exec "$cloud" ip netns exec internet ip addr add 203.0.113.9/24 dev eth0
http() { kubectl -n app exec "$1" -c c -- wget -qO- -T 5 "http://$2/"; }
from_is() { [[ "$(http "$1" "$2")" == "$3" ]]; }
eventually 60 "steered-a leaves from zone-a's Elastic IP" from_is steered-a 203.0.113.9 198.51.100.11
eventually 30 "steered-b leaves from zone-b's Elastic IP" from_is steered-b 203.0.113.9 198.51.100.21
from_is plain-a 203.0.113.9 198.51.100.200 || fail "an unselected pod was steered: $(http plain-a 203.0.113.9)"
from_is steered-a 203.0.113.1 198.51.100.200 || fail "an excluded destination was steered: $(http steered-a 203.0.113.1)"
[[ "$(whoami_from "$pod_a")" == 198.51.100.200 ]] || fail "node traffic was steered without nodeTraffic"
echo "steered-a: $(http steered-a 203.0.113.9), steered-b: $(http steered-b 203.0.113.9), plain-a: $(http plain-a 203.0.113.9)"

step "failover"
# The zone-a gateway node dies without warning. Within the probes' window
# (200ms x 5) new flows from zone-a take zone-b's gateway; the slot then
# moves to another zone-a node once Kubernetes marks the dead node not
# ready, and flows come back to zone-a's Elastic IP.
start=$(date +%s)
docker kill "$gw_a" >/dev/null
eventually 30 "steered-a falls back to zone-b's gateway" from_is steered-a 203.0.113.9 198.51.100.21
fallback=$(($(date +%s) - start))
# The probes need about a second; the rest of the bound is the exec and
# the client's own timeout.
((fallback <= 10)) || fail "new flows took ${fallback}s to leave the dead gateway"
moved() { [[ "$(slot eni-a1 state)" == Active && "$(slot eni-a1 node)" != "$gw_a" ]]; }
eventually 240 "eni-a1 moves off the dead node" moved
eventually 120 "steered-a leaves from the same Elastic IP" from_is steered-a 203.0.113.9 198.51.100.11
echo "new flows left through zone-b after ${fallback}s; eni-a1 moved from $gw_a to $(slot eni-a1 node), zone-a's Elastic IP back after $(($(date +%s) - start))s"
docker start "$gw_a" >/dev/null

step "uninstall"
kubectl delete egresspolicy -n app egress >/dev/null
kubectl delete egresspool default --wait=true --timeout=120s >/dev/null || fail "the pool was not deleted"
none_attached() { ! grep -q '"eni-' <<<"$(fake_state)"; }
eventually 120 "every slot is detached once the pool is gone" none_attached
helm uninstall "$release" -n "$ns" --wait --timeout 180s >/dev/null || fail "uninstall failed"
for n in $(kind get nodes --name "$cluster"); do
	if docker exec "$n" sh -c 'nft list tables; ip link; ip rule' | grep -E 'natterjack|nj(gw|tun|wg|d0)'; then
		fail "$n still holds Natterjack kernel objects"
	fi
done
echo "PASS ($cni${mesh:+, $mesh})"
