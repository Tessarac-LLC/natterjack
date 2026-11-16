#!/usr/bin/env bash
# Readies a test/eks run for `terraform destroy` after a run that stopped
# part-way: deletes the filler interfaces hack/eks-e2e.sh creates outside
# Terraform, and detaches every slot the controller left attached (Terraform
# cannot delete an interface in use).
#
# Usage: TF_VAR_run_id=… [REGION=us-east-2] hack/eks-e2e-sweep.sh
set -euo pipefail

: "${TF_VAR_run_id:?TF_VAR_run_id is required}"
region="${REGION:-us-east-2}"
cluster="natterjack-e2e-$TF_VAR_run_id"
ec2() { aws ec2 --region "$region" "$@"; }

enis() { # filter → "id attachment-id" per line
	ec2 describe-network-interfaces --filters "$1" \
		--query 'NetworkInterfaces[].[NetworkInterfaceId,Attachment.AttachmentId]' --output text
}

detach() {
	local id="$1" att="$2"
	[[ "$att" == None || -z "$att" ]] && return 0
	echo "detaching $id"
	ec2 detach-network-interface --attachment-id "$att" --force >/dev/null || true
	for _ in $(seq 60); do
		[[ "$(ec2 describe-network-interfaces --network-interface-ids "$id" \
			--query 'NetworkInterfaces[0].Status' --output text)" == available ]] && return 0
		sleep 2
	done
	echo "warning: $id is still attached" >&2
}

while read -r id att; do
	[[ -n "$id" ]] || continue
	detach "$id" "$att"
	echo "deleting filler $id"
	ec2 delete-network-interface --network-interface-id "$id" || true
done < <(enis "Name=tag:natterjack.io/e2e,Values=$TF_VAR_run_id")

while read -r id att; do
	[[ -n "$id" ]] || continue
	detach "$id" "$att"
done < <(enis "Name=tag:natterjack.io/cluster,Values=$cluster")
