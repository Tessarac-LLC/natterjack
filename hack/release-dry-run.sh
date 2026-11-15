#!/usr/bin/env bash
# Runs hack/release.sh against a throwaway local registry and checks what a
# user would pull: multi-arch images with SBOMs and stamped versions, and a
# chart that installs exactly those images.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
port="${PORT:-5055}"
registry="localhost:$port/tessarac-llc"
crane registry serve --address "127.0.0.1:$port" >"$work/registry.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true; rm -rf "$work"' EXIT
for _ in $(seq 50); do
	curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break
	sleep 0.2
done

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

VERSION=v0.0.0-dryrun.1 REGISTRY="$registry" OUT="$work/out" PLAIN_HTTP=1 "$root/hack/release.sh"
release="$work/out/release.json"
get() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$release" "$1"; }

for c in controller agent; do
	ref="$(get "$c")"
	echo "== $c $ref"
	platforms="$(crane manifest "$ref" | python3 -I -c 'import json,sys; print(" ".join(sorted(m["platform"]["architecture"] for m in json.load(sys.stdin)["manifests"] if m["platform"]["os"] == "linux")))')"
	[[ "$platforms" == "amd64 arm64" ]] || fail "$c is built for '$platforms', not amd64 and arm64"
	sbom="${ref%@*}:sha256-${ref##*sha256:}.sbom"
	crane manifest "$sbom" >/dev/null || fail "$c has no SBOM at $sbom"
	# The release string exists nowhere in the image but the stamped binary.
	crane export --platform linux/amd64 "$ref" "$work/$c.tar"
	grep -aq v0.0.0-dryrun.1 "$work/$c.tar" ||
		fail "$c is not stamped with its release"
	crane config --platform linux/arm64 "$ref" | grep -q '"architecture":"arm64"' || fail "$c arm64 image is not arm64"
done

echo "== chart"
mkdir -p "$work/pull"
helm pull "oci://$registry/charts/natterjack" --version 0.0.0-dryrun.1 --plain-http -d "$work/pull" >/dev/null
rendered="$(helm template e2e "$work/pull/natterjack-0.0.0-dryrun.1.tgz" --set clusterName=x --set controller.aws.region=us-east-1)"
grep -qF "image: $(get controller)" <<<"$rendered" || fail "the chart does not install the released controller"
grep -qF "image: $(get agent)" <<<"$rendered" || fail "the chart does not install the released agent"
helm show chart "$work/pull/natterjack-0.0.0-dryrun.1.tgz" | grep -qx "appVersion: v0.0.0-dryrun.1" || fail "chart appVersion is not the release"

echo "PASS"
