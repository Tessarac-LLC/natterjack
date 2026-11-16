mock_provider "aws" {
  mock_data "aws_subnet" {
    defaults = {
      vpc_id            = "vpc-0000000000000000a"
      availability_zone = "us-east-1a"
    }
  }
  mock_data "aws_vpc" {
    defaults = { cidr_block = "10.40.0.0/16" }
  }
  mock_resource "aws_network_interface" {
    defaults = { id = "eni-00000000000000000" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/natterjack-test" }
  }
}

variables {
  cluster_name = "prod-east"
  slot_subnets = { "us-east-1a" = "subnet-0000000000000000a" }
}

run "slots_pass_the_controllers_safety_checks" {
  command = plan

  assert {
    condition     = length(aws_network_interface.slot) == 2 && length(aws_eip.slot) == 2 && length(aws_eip_association.slot) == 2
    error_message = "Each subnet gets slots_per_subnet ENIs, each with its own Elastic IP."
  }

  assert {
    condition = alltrue([for e in aws_network_interface.slot : (
      e.source_dest_check == false
      && e.tags["natterjack.io/egress"] == "true"
      && e.tags["natterjack.io/cluster"] == "prod-east"
      && e.tags["node.k8s.amazonaws.com/no_manage"] == "true"
    )])
    error_message = "A slot needs source/destination check off and the egress, cluster and no_manage tags."
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.slot_ipv4.cidr_ipv4 == "0.0.0.0/0" && length(aws_vpc_security_group_ingress_rule.tunnel) == 0
    error_message = "The slot security group has egress only; no tunnel rule without a node security group."
  }
}

run "caller_tags_cannot_override_slot_tags" {
  command = plan

  variables {
    tags = {
      "natterjack.io/cluster"            = "someone-else"
      "node.k8s.amazonaws.com/no_manage" = "false"
      team                               = "platform"
    }
  }

  assert {
    condition = alltrue([for e in aws_network_interface.slot : (
      e.tags["natterjack.io/cluster"] == "prod-east"
      && e.tags["node.k8s.amazonaws.com/no_manage"] == "true"
      && e.tags["team"] == "platform"
    )])
    error_message = "Slot tags win over caller tags; other caller tags are kept."
  }
}

run "pod_identity_by_default" {
  command = plan

  assert {
    condition     = length(aws_eks_pod_identity_association.controller) == 1 && aws_eks_pod_identity_association.controller[0].service_account == "natterjack-controller" && aws_eks_pod_identity_association.controller[0].namespace == "natterjack"
    error_message = "The default identity is an EKS Pod Identity association for natterjack/natterjack-controller."
  }

  assert {
    condition     = jsondecode(aws_iam_role.controller.assume_role_policy).Statement[0].Principal.Service == "pods.eks.amazonaws.com"
    error_message = "Only the EKS Pod Identity service may assume the role."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.controller.policy, "\"aws:ResourceTag/natterjack.io/cluster\": \"prod-east\"") && !strcontains(aws_iam_role_policy.controller.policy, "$${cluster_name}")
    error_message = "The policy is scoped to this cluster's slots."
  }
}

run "irsa_trusts_only_the_controller_service_account" {
  command = plan

  variables {
    identity          = "irsa"
    oidc_provider_arn = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
    namespace         = "egress"
    service_account   = "nj-controller"
  }

  assert {
    condition     = length(aws_eks_pod_identity_association.controller) == 0
    error_message = "No Pod Identity association with IRSA."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.controller.assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub"] == "system:serviceaccount:egress:nj-controller"
      && jsondecode(aws_iam_role.controller.assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud"] == "sts.amazonaws.com"
    )
    error_message = "IRSA trust must be limited to the controller's ServiceAccount."
  }
}

run "irsa_without_provider_is_refused" {
  command = plan

  variables {
    identity = "irsa"
  }

  expect_failures = [aws_iam_role.controller]
}

run "bootstrap_route_and_tunnel_rule" {
  command = plan

  variables {
    bootstrap_route_table_ids = { "us-east-1a" = "rtb-0000000000000000a" }
    node_security_group_ids   = ["sg-0000000000000000a"]
  }

  assert {
    condition     = aws_route.bootstrap["us-east-1a"].destination_cidr_block == "0.0.0.0/0" && aws_route.bootstrap["us-east-1a"].route_table_id == "rtb-0000000000000000a"
    error_message = "The bootstrap route sends the private route table's default route to the zone's first slot."
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.tunnel["0/0"].ip_protocol == "udp" && aws_vpc_security_group_ingress_rule.tunnel["0/0"].from_port == 6081 && aws_vpc_security_group_ingress_rule.tunnel["0/0"].referenced_security_group_id == "sg-0000000000000000a"
    error_message = "The tunnel rule allows UDP 6081 between nodes only."
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.wireguard["0/0"].ip_protocol == "udp" && aws_vpc_security_group_ingress_rule.wireguard["0/0"].from_port == 51871 && aws_vpc_security_group_ingress_rule.wireguard["0/0"].to_port == 51871 && aws_vpc_security_group_ingress_rule.wireguard["0/0"].referenced_security_group_id == "sg-0000000000000000a"
    error_message = "The WireGuard rule allows UDP 51871 between nodes only."
  }
}

run "tunnel_rules_between_every_node_group" {
  command = plan

  variables {
    node_security_group_ids = ["sg-0000000000000000a", "sg-0000000000000000b"]
  }

  assert {
    condition = (
      length(aws_vpc_security_group_ingress_rule.tunnel) == 4 && length(aws_vpc_security_group_ingress_rule.wireguard) == 4
      && aws_vpc_security_group_ingress_rule.tunnel["0/1"].referenced_security_group_id == "sg-0000000000000000a"
      && aws_vpc_security_group_ingress_rule.tunnel["0/1"].security_group_id == "sg-0000000000000000b"
    )
    error_message = "Each node group accepts both tunnels from every node group, itself included."
  }
}

run "bad_inputs_are_refused" {
  command = plan

  variables {
    cluster_name     = "bad name"
    slots_per_subnet = 0
  }

  expect_failures = [var.cluster_name, var.slots_per_subnet]
}

run "ports_must_differ" {
  command = plan

  variables {
    tunnel_port    = 51871
    wireguard_port = 51871
  }

  expect_failures = [var.wireguard_port]
}

run "bootstrap_routes_only_for_slot_zones" {
  command = plan

  variables {
    bootstrap_route_table_ids = { "us-east-1b" = "rtb-0000000000000000b" }
  }

  expect_failures = [var.bootstrap_route_table_ids]
}

run "slot_subnet_keyed_by_another_zone_is_refused" {
  command = plan

  variables {
    slot_subnets = { "us-east-1b" = "subnet-0000000000000000a" }
  }

  expect_failures = [aws_network_interface.slot]
}

# Subnets, route tables and security groups created in the same apply have no
# IDs at plan time.
run "slots_take_no_inbound_traffic_without_bootstrap_routes" {
  command = plan

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.slot_routed) == 0
    error_message = "Without bootstrap routes nothing may enter a slot."
  }
}

run "bootstrap_routes_admit_the_vpc_to_the_slots" {
  command = plan

  variables {
    bootstrap_route_table_ids = { "us-east-1a" = "rtb-0000000000000000a" }
  }

  # The VPC applies the slot's security group to traffic a route table sends
  # through it, as it does for any NAT instance.
  assert {
    condition = (
      length(aws_vpc_security_group_ingress_rule.slot_routed) == 1 &&
      aws_vpc_security_group_ingress_rule.slot_routed[0].cidr_ipv4 == "10.40.0.0/16" &&
      aws_vpc_security_group_ingress_rule.slot_routed[0].ip_protocol == "-1"
    )
    error_message = "With bootstrap routes the slots admit the VPC's CIDR, every protocol."
  }
}

run "bootstrap_source_cidrs_replace_the_vpc_cidr" {
  command = plan

  variables {
    bootstrap_route_table_ids = { "us-east-1a" = "rtb-0000000000000000a" }
    bootstrap_source_cidrs    = ["10.40.16.0/20", "100.64.0.0/16"]
  }

  assert {
    condition     = [for r in aws_vpc_security_group_ingress_rule.slot_routed : r.cidr_ipv4] == ["10.40.16.0/20", "100.64.0.0/16"]
    error_message = "bootstrap_source_cidrs are the only sources admitted."
  }
}

run "bad_bootstrap_source_cidrs_are_refused" {
  command = plan

  variables {
    bootstrap_route_table_ids = { "us-east-1a" = "rtb-0000000000000000a" }
    bootstrap_source_cidrs    = ["0.0.0.0/0"]
  }

  expect_failures = [var.bootstrap_source_cidrs]
}

run "plans_with_subnets_created_in_the_same_apply" {
  command = plan

  module {
    source = "./tests/new-vpc"
  }

  assert {
    condition     = length(module.natterjack.slots) == 4
    error_message = "Two zones with two slots each."
  }
}

run "permissions_boundary_on_the_controller_role" {
  command = plan

  variables {
    permissions_boundary = "arn:aws:iam::111122223333:policy/boundary"
  }

  assert {
    condition     = aws_iam_role.controller.permissions_boundary == "arn:aws:iam::111122223333:policy/boundary"
    error_message = "The controller role carries the given permissions boundary."
  }
}
