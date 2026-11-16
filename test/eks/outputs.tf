output "cluster_name" {
  description = "EKS cluster name, also the chart's clusterName."
  value       = aws_eks_cluster.this.name
}

output "region" {
  description = "Region of every resource."
  value       = var.region
}

output "kubernetes_version" {
  description = "EKS version the cluster runs."
  value       = aws_eks_cluster.this.version
}

output "registry" {
  description = "ECR registry and repository prefix for this run's images and chart."
  value       = "${local.registry}/${local.name}"
}

output "slots" {
  description = "Every slot: ENI ID, zone and public IP."
  value       = module.natterjack.slots
}

output "public_ips" {
  description = "The slots' public IPs."
  value       = module.natterjack.public_ips
}

output "slot_security_group_id" {
  description = "Security group on every slot."
  value       = module.natterjack.slot_security_group_id
}

output "controller_role_arn" {
  description = "The controller's IAM role."
  value       = module.natterjack.controller_role_arn
}

output "zones" {
  description = "The two zones in use."
  value       = local.zones
}

output "outside" {
  description = "The internet-side server."
  value = {
    instance_id = aws_instance.outside.id
    public_ip   = aws_instance.outside.public_ip
  }
}

output "attacker" {
  description = "The instance that probes the slots from their subnet."
  value = {
    instance_id = aws_instance.attacker.id
    public_ip   = aws_instance.attacker.public_ip
    private_ip  = aws_instance.attacker.private_ip
  }
}

output "node_groups" {
  description = "Managed node group names."
  value       = [for g in aws_eks_node_group.this : g.node_group_name]
}
