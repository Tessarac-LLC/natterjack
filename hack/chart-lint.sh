#!/usr/bin/env bash
# Static checks on the chart: helm lint, every rendering valid against the
# Kubernetes schemas, and every bad input refused with a clear message.
set -euo pipefail

chart="$(cd "$(dirname "$0")/.." && pwd)/charts/natterjack"
kube_version="${KUBE_VERSION:-1.34.0}"
required=(--set clusterName=lint --set controller.aws.region=us-east-1)

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

echo "== helm lint"
helm lint --strict "$chart" "${required[@]}"

echo "== renderings validate against Kubernetes $kube_version"
renders=(
	""
	"--set agent.enabled=false"
	"--set controller.enabled=false"
	"--set crds.install=false"
	"--set crds.keep=false"
	"--set namespace.create=true"
	"--set controller.replicas=1"
	"--set agent.excludedCIDRs={203.0.113.0/24,198.51.100.0/24}"
	"--set controller.image.digest=sha256:$(printf '0%.0s' {1..64})"
	"--set images.pullSecrets={regcred}"
	"--set controller.serviceAccount.annotations.eks\.amazonaws\.com/role-arn=arn:aws:iam::111122223333:role/natterjack"
)
for extra in "${renders[@]}"; do
	# shellcheck disable=SC2086 # each entry is a list of flags
	helm template lint "$chart" -n natterjack "${required[@]}" $extra |
		kubeconform -strict -summary -kubernetes-version "$kube_version" -skip CustomResourceDefinition ||
		fail "rendering with '$extra' is not valid"
done

echo "== bad input is refused"
refuse() { # message, flags...
	local want="$1" out
	shift
	if out="$(helm template lint "$chart" "$@" 2>&1)"; then
		fail "rendered with: $*"
	fi
	grep -qF "$want" <<<"$out" || fail "refused '$*' without saying '$want': $out"
}
refuse "clusterName is required" --set controller.aws.region=us-east-1
refuse "controller.aws.region is required" --set clusterName=lint
refuse "enable the controller, the agent or both" "${required[@]}" --set controller.enabled=false --set agent.enabled=false
refuse "/agent/markMask" "${required[@]}" --set agent.markMask=ff
refuse "/agent/gatewayLink" "${required[@]}" --set agent.gatewayLink=10.0.0.0/30
refuse "/agent/excludedCIDRs/0" "${required[@]}" --set "agent.excludedCIDRs={2001:db8::/32}"
refuse "/agent/rulePriority" "${required[@]}" --set agent.rulePriority=40000
refuse "/agent/selfTest/url" "${required[@]}" --set agent.selfTest.url=http://checkip.example
refuse "/agent/resync" "${required[@]}" --set agent.resync=30
refuse "/controller/image/digest" "${required[@]}" --set controller.image.digest=latest
refuse "/controller/aws/region" --set clusterName=lint --set controller.aws.region=USEAST1
refuse "additional properties 'typo' not allowed" "${required[@]}" --set agent.typo=1

echo "== the agent selector the binaries use matches the agent pods"
rendered="$(helm template lint "$chart" -n natterjack "${required[@]}")"
selector="$(grep -m1 -oE -- '--agent-selector=[^"]+' <<<"$rendered" | cut -d= -f2-)"
for pair in ${selector//,/ }; do
	grep -qE "^\s+${pair%%=*}: ${pair#*=}$" <<<"$rendered" || fail "selector term $pair matches no label"
done
[[ "$(grep -c -- "--agent-selector=$selector" <<<"$rendered")" == 2 ]] || fail "controller and agent use different selectors"

echo "== the values reference is current"
(cd "$chart/../.." && helm-docs --chart-search-root charts --template-files README.md.gotmpl >/dev/null)
git -C "$chart" diff --exit-code -- README.md || fail "charts/natterjack/README.md is stale: run 'make chart-docs' and commit"

echo "PASS"
