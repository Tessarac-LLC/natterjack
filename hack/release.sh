#!/usr/bin/env bash
# Builds and pushes one release: both images for amd64 and arm64 on a base
# pinned by digest, each with an SPDX SBOM attached, then the chart with its
# image references pinned to those digests. Writes what it pushed to
# $OUT/release.json for the signing and attestation steps.
#
# Usage: VERSION=v1.2.3 REGISTRY=ghcr.io/tessarac-llc OUT=dist hack/release.sh
# PLAIN_HTTP=1 pushes the chart over HTTP (a local test registry).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
: "${VERSION:?VERSION is required, for example v1.2.3}"
: "${REGISTRY:?REGISTRY is required, for example ghcr.io/tessarac-llc}"
: "${OUT:?OUT is required}"
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
[[ "$VERSION" =~ $semver ]] || {
	echo "VERSION $VERSION is not vMAJOR.MINOR.PATCH[-PRERELEASE]" >&2
	exit 1
}
chart_version="${VERSION#v}"
mkdir -p "$OUT"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

base_repo="$(sed -n 's/^defaultBaseImage: *//p' "$root/.ko.yaml")"
base_repo="${base_repo%:*}"
base_digest="$(crane digest "$base_repo:latest")"
export KO_DEFAULTBASEIMAGE="$base_repo@$base_digest" VERSION GOWORK=off
echo "base image $KO_DEFAULTBASEIMAGE"

declare -A ref
for c in controller agent; do
	out="$(cd "$root" && KO_DOCKER_REPO="$REGISTRY/natterjack-$c" ko build --bare --sbom=spdx --tags "$VERSION" "./cmd/$c")"
	# ko prints repo:tag@digest; keep the digest only.
	ref[$c]="$REGISTRY/natterjack-$c@${out##*@}"
	[[ "${ref[$c]}" == "$REGISTRY/natterjack-$c@sha256:"* ]] || {
		echo "ko printed an unexpected reference for $c: ${ref[$c]}" >&2
		exit 1
	}
	echo "$c ${ref[$c]}"
done

cp -R "$root/charts/natterjack" "$work/natterjack"
python3 -I - "$work/natterjack/values.yaml" "${ref[controller]}" "${ref[agent]}" <<'PY'
import sys
# Pin each component's image to the repository and digest just pushed.
path = sys.argv[1]
want = {}
for section, ref in (("controller", sys.argv[2]), ("agent", sys.argv[3])):
    repo, digest = ref.split("@")
    want[section] = {"repository": repo, "digest": digest}
out, section = [], None
for line in open(path):
    if line[:1].isalpha():
        section = line.split(":")[0]
    key = line.strip().split(":")[0]
    if section in want and line.startswith("    ") and not line.startswith("     ") and key in want[section]:
        line = "    %s: %s\n" % (key, want[section].pop(key))
    out.append(line)
missing = {s: sorted(k) for s, k in want.items() if k}
if missing:
    sys.exit(f"values.yaml has no image field for {missing}")
open(path, "w").writelines(out)
PY
helm package "$work/natterjack" --version "$chart_version" --app-version "$VERSION" -d "$work" >/dev/null
helm template check "$work/natterjack-$chart_version.tgz" --set clusterName=x --set controller.aws.region=us-east-1 |
	grep -c "@sha256:" | grep -qx 2 || {
	echo "the packaged chart does not pin both images by digest" >&2
	exit 1
}
push="$(helm push "$work/natterjack-$chart_version.tgz" "oci://$REGISTRY/charts" ${PLAIN_HTTP:+--plain-http} 2>&1)"
chart_digest="$(sed -n 's/^Digest: *//p' <<<"$push")"
[[ "$chart_digest" == sha256:* ]] || {
	echo "helm push printed no digest: $push" >&2
	exit 1
}
cp "$work/natterjack-$chart_version.tgz" "$OUT/"
echo "chart $REGISTRY/charts/natterjack:$chart_version@$chart_digest"

cat >"$OUT/release.json" <<JSON
{
  "version": "$VERSION",
  "base": "$KO_DEFAULTBASEIMAGE",
  "controller": "${ref[controller]}",
  "agent": "${ref[agent]}",
  "chart": "$REGISTRY/charts/natterjack@$chart_digest",
  "chartVersion": "$chart_version"
}
JSON
