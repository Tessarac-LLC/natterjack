#!/usr/bin/env bash
# Prints, as a Markdown table, how fast one gateway can send to the internet
# on each size of the given EC2 instance families, from the EC2 API's own
# figures and AWS's internet gateway limits:
#   - fewer than 32 vCPUs: at most 5 Gbps through an internet gateway;
#   - more than 32 vCPUs: at most half the instance's bandwidth.
# AWS states no rule for exactly 32 vCPUs; this script applies the 5 Gbps one.
# Sizes up to 4xlarge burst above their baseline on network credits for
# minutes at a time; the table shows the sustained baseline and, in
# brackets, the burst.
#
# Usage: [REGION=us-east-1] hack/aws-bandwidth.sh m7i m7g c7i …
set -euo pipefail

region="${REGION:-us-east-1}"
[ $# -gt 0 ] || { echo "usage: $0 FAMILY…" >&2; exit 2; }

sizes=(large xlarge 2xlarge 4xlarge 8xlarge 12xlarge 16xlarge 24xlarge)
filters=$(printf '%s.*,' "$@")

aws ec2 describe-instance-types --region "$region" \
	--filters "Name=instance-type,Values=${filters%,}" \
	--query 'InstanceTypes[].{t:InstanceType,v:VCpuInfo.DefaultVCpus,b:NetworkInfo.NetworkCards[0].BaselineBandwidthInGbps,p:NetworkInfo.NetworkCards[0].PeakBandwidthInGbps}' \
	--output json |
	jq -r --argjson sizes "$(printf '%s\n' "${sizes[@]}" | jq -R . | jq -s .)" --args '
	def gbps: . * 100 | round / 100 | tostring;
	def igw: if .v > 32 then {s: (.b / 2), p: (.b / 2)}
		else {s: ([.b, 5] | min), p: ([.p, 5] | min)} end;
	def cell: igw | if .s == .p then (.s | gbps) else "\(.s | gbps) (\(.p | gbps))" end;
	map(. + {f: (.t | split(".")[0]), z: (.t | split(".")[1])}) as $all
	| "| Family | " + ($sizes | join(" | ")) + " | 5 Gbps sustained from |",
	  "| --- |" + ($sizes | map(" ---: |") | join("")) + " --- |",
	  ($ARGS.positional[] as $f
	   | [$all[] | select(.f == $f)] as $types
	   | ($types | map(select(.z | IN($sizes[]))) | INDEX(.z)) as $by
	   | ([$sizes[] | select($by[.] and ($by[.] | igw | .s) >= 5)] | first // "—") as $from
	   | "| `\($f)` | "
	     + ([$sizes[] | if $by[.] then ($by[.] | cell) else "—" end] | join(" | "))
	     + " | \(if $from == "—" then $from else "`\($from)`" end) |")
	' --args "$@"
