#!/usr/bin/env bash
# Lists the chart on Artifact Hub, idempotently.
#
# It makes sure the Artifact Hub organization and its Helm repository for
# the chart's OCI location exist, then pushes the repository metadata
# (artifacthub-repo.yml, carrying the repository ID) to the chart
# repository's "artifacthub.io" tag, which is what earns the Verified
# Publisher mark. Artifact Hub then indexes every chart version on its own.
#
# Needs an Artifact Hub API key (ARTIFACTHUB_API_KEY_ID and
# ARTIFACTHUB_API_KEY_SECRET) and oras logged in to the registry with
# permission to push to the chart repository.
set -euo pipefail

: "${ARTIFACTHUB_API_KEY_ID:?an Artifact Hub API key ID is required}"
: "${ARTIFACTHUB_API_KEY_SECRET:?an Artifact Hub API key secret is required}"
API="${ARTIFACTHUB_API:-https://artifacthub.io/api/v1}"
ORG="${ARTIFACTHUB_ORG:-natterjack}"
NAME="${ARTIFACTHUB_REPO:-natterjack}"
CHART="${CHART:-ghcr.io/tessarac-llc/charts/natterjack}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The key goes to curl through a file, never on its command line.
(
  umask 077
  printf 'X-API-KEY-ID: %s\nX-API-KEY-SECRET: %s\n' \
    "$ARTIFACTHUB_API_KEY_ID" "$ARTIFACTHUB_API_KEY_SECRET" >"$work/auth"
)

# ah METHOD PATH [JSON]: prints the HTTP status; the body is in $work/body.
ah() {
  local args=(-sS -o "$work/body" -w '%{http_code}' -X "$1" -H @"$work/auth")
  if [[ $# -gt 2 ]]; then
    args+=(-H 'Content-Type: application/json' --data-binary "$3")
  fi
  curl "${args[@]}" "$API$2"
}

fail() {
  echo "artifacthub: $1 (HTTP $2): $(head -c 500 "$work/body")" >&2
  exit 1
}

org="$(jq -nc --arg name "$ORG" '{
  name: $name,
  display_name: "Natterjack",
  description: "Highly available, zone-aware egress gateways for Kubernetes that replace cloud NAT gateways.",
  home_url: "https://natterjack.io"
}')"
code="$(ah GET "/orgs/$ORG")"
case "$code" in
  200) code="$(ah PUT "/orgs/$ORG" "$org")"; [[ "$code" == 204 ]] || fail "updating organization $ORG" "$code" ;;
  404) code="$(ah POST /orgs "$org")"; [[ "$code" == 201 ]] || fail "creating organization $ORG" "$code"
       echo "artifacthub: created organization $ORG" ;;
  *) fail "reading organization $ORG" "$code" ;;
esac

repo="$(jq -nc --arg name "$NAME" --arg url "oci://$CHART" \
  '{kind: 0, name: $name, display_name: "Natterjack", url: $url}')"
# Search is the only way to read a repository's ID, and its responses are
# cached for an hour at the CDN: a lookup just after creating the repository
# would get the empty answer cached a moment before. A unique query
# parameter keeps every lookup off the cache.
lookup() {
  local code
  code="$(ah GET "/repositories/search?kind=0&org=$ORG&name=$NAME&limit=60&nocache=$(date +%s)$RANDOM")"
  [[ "$code" == 200 ]] || fail "searching for repository $NAME" "$code"
  jq -r --arg name "$NAME" --arg org "$ORG" \
    '[.[] | select(.name == $name and .organization_name == $org)][0].repository_id // empty' "$work/body"
}
id="$(lookup)"
if [[ -z "$id" ]]; then
  code="$(ah POST "/repositories/org/$ORG" "$repo")"
  [[ "$code" == 201 ]] || fail "creating repository $NAME" "$code"
  echo "artifacthub: created repository $ORG/$NAME for oci://$CHART"
  for _ in 1 2 3 4 5 6; do
    id="$(lookup)"
    [[ -z "$id" ]] || break
    sleep 5
  done
  [[ -n "$id" ]] || { echo "artifacthub: repository $NAME not found after creating it" >&2; exit 1; }
else
  code="$(ah PUT "/repositories/org/$ORG/$NAME" "$repo")"
  [[ "$code" == 204 ]] || fail "updating repository $NAME" "$code"
fi
echo "artifacthub: repository $ORG/$NAME is $id"

printf 'repositoryID: %s\n' "$id" >"$work/artifacthub-repo.yml"
(
  cd "$work"
  oras push "$CHART:artifacthub.io" \
    --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
    artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml
)
echo "artifacthub: published repository metadata to $CHART:artifacthub.io"
