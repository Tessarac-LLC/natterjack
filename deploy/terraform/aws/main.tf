data "aws_subnet" "slot" {
  for_each = var.slot_subnets
  id       = each.value
}

locals {
  vpc_ids = distinct([for s in data.aws_subnet.slot : s.vpc_id])

  slots = {
    for pair in setproduct(keys(var.slot_subnets), range(var.slots_per_subnet)) :
    "${pair[0]}/${pair[1]}" => { zone = pair[0], subnet_id = var.slot_subnets[pair[0]], index = pair[1] }
  }

  # Tags the controller and the VPC CNI read. Applied last so callers cannot
  # override them.
  slot_tags = {
    "natterjack.io/egress"             = "true"
    "natterjack.io/cluster"            = var.cluster_name
    "node.k8s.amazonaws.com/no_manage" = "true"
  }

  # Every node group can reach every other. Keyed by position: the IDs of
  # groups created in the same apply are unknown at plan time.
  node_security_group_pairs = {
    for p in setproduct(range(length(var.node_security_group_ids)), range(length(var.node_security_group_ids))) :
    "${p[0]}/${p[1]}" => { from = var.node_security_group_ids[p[0]], to = var.node_security_group_ids[p[1]] }
  }

  oidc_issuer = var.oidc_provider_arn == null ? "" : replace(var.oidc_provider_arn, "/^.*oidc-provider\\//", "")
}

# --- Slots -------------------------------------------------------------------

data "aws_vpc" "slot" {
  count = length(var.bootstrap_route_table_ids) > 0 && var.bootstrap_source_cidrs == null ? 1 : 0
  id    = one(local.vpc_ids)
}

resource "aws_security_group" "slot" {
  name_prefix = "natterjack-${var.cluster_name}-slot-"
  description = "Natterjack egress slots: only replies from the internet return."
  vpc_id      = one(local.vpc_ids)
  tags        = merge(var.tags, { Name = "natterjack-${var.cluster_name}-slot" })

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = length(local.vpc_ids) == 1
      error_message = "All slot subnets must be in the cluster's VPC."
    }
  }
}

resource "aws_vpc_security_group_egress_rule" "slot_ipv4" {
  security_group_id = aws_security_group.slot.id
  description       = "Egress to the internet."
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  tags              = var.tags
}

resource "aws_network_interface" "slot" {
  for_each = local.slots

  subnet_id         = each.value.subnet_id
  security_groups   = [aws_security_group.slot.id]
  source_dest_check = false
  description       = "Natterjack egress slot for ${var.cluster_name}"
  tags              = merge(var.tags, { Name = "natterjack-${var.cluster_name}-${each.key}" }, local.slot_tags)

  # The controller attaches and detaches slots. An attachment block here would
  # fight it.
  lifecycle {
    ignore_changes = [attachment]

    # Keying by zone keeps it to one subnet per zone, as long as the key is
    # the subnet's own zone.
    precondition {
      condition     = contains([data.aws_subnet.slot[each.value.zone].availability_zone, data.aws_subnet.slot[each.value.zone].availability_zone_id], each.value.zone)
      error_message = "slot_subnets key ${each.value.zone} is not the zone of subnet ${each.value.subnet_id}."
    }
  }
}

resource "aws_eip" "slot" {
  for_each = { for k, v in local.slots : k => v if !contains(keys(var.slot_eip_allocation_ids), k) }

  domain = "vpc"
  tags   = merge(var.tags, { Name = "natterjack-${var.cluster_name}-${each.key}" })
}

data "aws_eip" "adopted" {
  for_each = var.slot_eip_allocation_ids
  id       = each.value
}

locals {
  slot_eips = merge(
    { for k, e in aws_eip.slot : k => { allocation_id = e.id, public_ip = e.public_ip } },
    { for k, e in data.aws_eip.adopted : k => { allocation_id = e.id, public_ip = e.public_ip } },
  )
}

resource "aws_eip_association" "slot" {
  for_each = local.slots

  allocation_id        = local.slot_eips[each.key].allocation_id
  network_interface_id = aws_network_interface.slot[each.key].id
}

# The bootstrap route targets the zone's first slot. It stays valid when the
# controller moves that ENI between nodes.
resource "aws_route" "bootstrap" {
  for_each = var.bootstrap_route_table_ids

  route_table_id         = each.value
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_network_interface.slot["${each.key}/0"].id
}

# The VPC applies the slot's security group to traffic a bootstrap route sends
# through it, as for any NAT instance. Only private sources reach it that way;
# the gateway forwards them to the internet and nowhere else. Counted, not
# keyed by CIDR, so it plans before a new VPC exists.
resource "aws_vpc_security_group_ingress_rule" "slot_routed" {
  count = length(var.bootstrap_route_table_ids) > 0 ? (var.bootstrap_source_cidrs == null ? 1 : length(var.bootstrap_source_cidrs)) : 0

  security_group_id = aws_security_group.slot.id
  description       = "Traffic routed to the slot by a bootstrap route."
  ip_protocol       = "-1"
  cidr_ipv4         = var.bootstrap_source_cidrs == null ? data.aws_vpc.slot[0].cidr_block : var.bootstrap_source_cidrs[count.index]
  tags              = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "tunnel" {
  for_each = local.node_security_group_pairs

  security_group_id            = each.value.to
  referenced_security_group_id = each.value.from
  description                  = "Natterjack agent tunnel between nodes."
  ip_protocol                  = "udp"
  from_port                    = var.tunnel_port
  to_port                      = var.tunnel_port
  tags                         = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "wireguard" {
  for_each = local.node_security_group_pairs

  security_group_id            = each.value.to
  referenced_security_group_id = each.value.from
  description                  = "Natterjack agent WireGuard tunnel between nodes."
  ip_protocol                  = "udp"
  from_port                    = var.wireguard_port
  to_port                      = var.wireguard_port
  tags                         = var.tags
}

# --- Controller identity -----------------------------------------------------

locals {
  trust = {
    "pod-identity" = {
      Effect    = "Allow"
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Principal = { Service = "pods.eks.amazonaws.com" }
    }
    irsa = {
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = var.oidc_provider_arn }
      Condition = {
        StringEquals = {
          "${local.oidc_issuer}:sub" = "system:serviceaccount:${var.namespace}:${var.service_account}"
          "${local.oidc_issuer}:aud" = "sts.amazonaws.com"
        }
      }
    }
  }
}

resource "aws_iam_role" "controller" {
  name_prefix          = "natterjack-${substr(var.cluster_name, 0, 20)}-"
  description          = "Natterjack controller for ${var.cluster_name}: moves this cluster's egress ENIs between its nodes."
  assume_role_policy   = jsonencode({ Version = "2012-10-17", Statement = [local.trust[var.identity]] })
  max_session_duration = 3600
  permissions_boundary = var.permissions_boundary
  tags                 = var.tags

  lifecycle {
    precondition {
      condition     = var.identity != "irsa" || var.oidc_provider_arn != null
      error_message = "oidc_provider_arn is required when identity is \"irsa\"."
    }
  }
}

resource "aws_iam_role_policy" "controller" {
  name   = "natterjack-controller"
  role   = aws_iam_role.controller.id
  policy = templatefile("${path.module}/controller-policy.json.tftpl", { cluster_name = var.cluster_name })
}

resource "aws_eks_pod_identity_association" "controller" {
  count = var.identity == "pod-identity" ? 1 : 0

  cluster_name    = var.cluster_name
  namespace       = var.namespace
  service_account = var.service_account
  role_arn        = aws_iam_role.controller.arn
  tags            = var.tags
}
