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

  oidc_issuer = var.oidc_provider_arn == null ? "" : replace(var.oidc_provider_arn, "/^.*oidc-provider\\//", "")
}

# --- Slots -------------------------------------------------------------------

resource "aws_security_group" "slot" {
  name_prefix = "natterjack-${var.cluster_name}-slot-"
  description = "Natterjack egress slots: no inbound rules, so only replies to outbound flows return."
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
  for_each = local.slots

  domain = "vpc"
  tags   = merge(var.tags, { Name = "natterjack-${var.cluster_name}-${each.key}" })
}

resource "aws_eip_association" "slot" {
  for_each = local.slots

  allocation_id        = aws_eip.slot[each.key].id
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

resource "aws_vpc_security_group_ingress_rule" "tunnel" {
  count = var.node_security_group_id == null ? 0 : 1

  security_group_id            = var.node_security_group_id
  referenced_security_group_id = var.node_security_group_id
  description                  = "Natterjack agent tunnel between nodes."
  ip_protocol                  = "udp"
  from_port                    = var.tunnel_port
  to_port                      = var.tunnel_port
  tags                         = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "wireguard" {
  count = var.node_security_group_id == null ? 0 : 1

  security_group_id            = var.node_security_group_id
  referenced_security_group_id = var.node_security_group_id
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
