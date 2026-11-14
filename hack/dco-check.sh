#!/usr/bin/env bash
# Fails if any commit in BASE..HEAD lacks a Signed-off-by trailer matching its
# author (Developer Certificate of Origin, see CONTRIBUTING.md).
#
#   hack/dco-check.sh <base-sha> <head-sha>
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <base-sha> <head-sha>" >&2
  exit 2
fi
base=$1
head=$2

missing=0
checked=0
while IFS= read -r sha; do
  checked=$((checked + 1))
  author="$(git show -s --format='%an <%ae>' "$sha")"
  trailers="$(git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha")"
  if ! grep -qxF "$author" <<<"$trailers"; then
    echo "::error::commit $sha by $author has no matching 'Signed-off-by: $author' (commit with: git commit -s)"
    missing=$((missing + 1))
  fi
done < <(git rev-list --no-merges "${base}..${head}")

if [ "$checked" -eq 0 ]; then
  echo "::error::no commits found between $base and $head"
  exit 1
fi
if [ "$missing" -ne 0 ]; then
  echo "$missing of $checked commit(s) are not signed off."
  exit 1
fi
echo "All $checked commit(s) are signed off."
