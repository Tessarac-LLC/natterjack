output "controller_role_arn" {
  description = "IAM role for the controller. With identity \"irsa\", set it as the chart's controller.serviceAccount.annotations.\"eks.amazonaws.com/role-arn\"."
  value       = aws_iam_role.controller.arn
}

output "slots" {
  description = "Every slot: ENI ID, zone and public IP."
  value = {
    for k, eni in aws_network_interface.slot : k => {
      network_interface_id = eni.id
      availability_zone    = data.aws_subnet.slot[split("/", k)[0]].availability_zone
      public_ip            = local.slot_eips[k].public_ip
    }
  }
}

output "public_ips" {
  description = "The addresses the cluster's selected traffic leaves from. Give these to anyone who allow-lists your egress."
  value       = sort([for e in local.slot_eips : e.public_ip])
}

output "slot_security_group_id" {
  description = "Security group on every slot. It admits only the bootstrap sources, if any; a rule from outside the VPC makes the controller quarantine the slots."
  value       = aws_security_group.slot.id
}
