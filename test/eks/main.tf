# An EKS cluster with no NAT gateway, where Natterjack is the only way out.
# Nodes join, pull images and reach AWS through VPC endpoints; everything
# else leaves through the slots once the agents run. Two more instances sit
# on the internet side: "outside" answers HTTP and iperf3 from the slots'
# public IPs only, and "attacker" probes the slots from the public subnet.

data "aws_availability_zones" "this" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}

data "aws_eks_cluster_versions" "standard" {
  version_status = "STANDARD_SUPPORT"
}

locals {
  name  = "natterjack-e2e-${var.run_id}"
  zones = slice(sort(data.aws_availability_zones.this.names), 0, 2)
  cidr  = "10.40.0.0/16"

  # Versions are "1.N"; the newest is the largest N.
  minors             = [for v in data.aws_eks_cluster_versions.standard.cluster_versions : tonumber(split(".", v.cluster_version)[1])]
  kubernetes_version = coalesce(var.kubernetes_version, "1.${max(local.minors...)}")

  registry = "${data.aws_caller_identity.this.account_id}.dkr.ecr.${var.region}.amazonaws.com"
}

# --- Network -------------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = local.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = local.name }
}

resource "aws_subnet" "public" {
  for_each = { for i, z in local.zones : z => i }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = cidrsubnet(local.cidr, 8, each.value)
  tags              = { Name = "${local.name}-public-${each.key}" }
}

resource "aws_subnet" "private" {
  for_each = { for i, z in local.zones : z => i }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = cidrsubnet(local.cidr, 4, each.value + 1)
  tags              = { Name = "${local.name}-private-${each.key}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${local.name}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# One per zone. Their default route is the module's bootstrap route to the
# zone's first slot; there is no NAT gateway.
resource "aws_route_table" "private" {
  for_each = aws_subnet.private

  vpc_id = aws_vpc.this.id
  tags   = { Name = "${local.name}-private-${each.key}" }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for r in aws_route_table.private : r.id]
  tags              = { Name = "${local.name}-s3" }
}

resource "aws_security_group" "endpoints" {
  name_prefix = "${local.name}-endpoints-"
  description = "VPC interface endpoints: HTTPS from the VPC"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${local.name}-endpoints" }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints" {
  security_group_id = aws_security_group.endpoints.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = local.cidr
}

# What a node needs before any internet access: to join (eks, sts), pull
# images (ecr, s3), run the VPC CNI (ec2), get pod credentials (eks-auth) and
# be reached for debugging (ssm).
resource "aws_vpc_endpoint" "interface" {
  for_each = toset(["ec2", "ecr.api", "ecr.dkr", "sts", "eks", "eks-auth", "ssm", "ssmmessages", "ec2messages"])

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [for s in aws_subnet.private : s.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  tags                = { Name = "${local.name}-${each.key}" }
}

# --- Cluster -------------------------------------------------------------------

data "aws_iam_policy_document" "cluster_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name_prefix          = "nj-e2e-${var.run_id}-cluster-"
  permissions_boundary = var.permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.cluster_trust.json
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = local.name
  version  = local.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }

  vpc_config {
    subnet_ids              = [for s in aws_subnet.private : s.id]
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.api_allowed_cidrs
  }

  depends_on = [aws_iam_role_policy_attachment.cluster]
}

data "aws_iam_policy_document" "node_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name_prefix          = "nj-e2e-${var.run_id}-node-"
  permissions_boundary = var.permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.node_trust.json
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset(["AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly", "AmazonSSMManagedInstanceCore"])

  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/${each.key}"
}

# IMDSv2 only, one hop: pods cannot borrow the node's role.
resource "aws_launch_template" "node" {
  name_prefix = "${local.name}-node-"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${local.name}-node", "natterjack.io/e2e" = var.run_id }
  }
}

resource "aws_eks_node_group" "this" {
  for_each = {
    amd64 = { ami_type = "AL2023_x86_64_STANDARD", instance_type = var.amd64_instance_type, size = 6 }
    arm64 = { ami_type = "AL2023_ARM_64_STANDARD", instance_type = var.arm64_instance_type, size = 2 }
  }

  cluster_name    = aws_eks_cluster.this.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = [for s in aws_subnet.private : s.id]
  ami_type        = each.value.ami_type
  instance_types  = [each.value.instance_type]

  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }

  scaling_config {
    desired_size = each.value.size
    min_size     = each.value.size
    max_size     = each.value.size + 1
  }

  update_config {
    max_unavailable = 1
  }

  # Nodes join through the endpoints, before any slot has a gateway.
  depends_on = [
    aws_iam_role_policy_attachment.node,
    aws_vpc_endpoint.interface,
    aws_vpc_endpoint.s3,
    aws_route_table_association.private,
  ]
}

resource "aws_eks_addon" "this" {
  for_each = toset(["vpc-cni", "kube-proxy", "coredns", "eks-pod-identity-agent"])

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  # CoreDNS needs nodes to schedule on; the rest are DaemonSets.
  depends_on = [aws_eks_node_group.this]
}

# --- Natterjack ----------------------------------------------------------------

module "natterjack" {
  source = "../../deploy/terraform/aws"

  cluster_name              = aws_eks_cluster.this.name
  slot_subnets              = { for z, s in aws_subnet.public : z => s.id }
  bootstrap_route_table_ids = { for z, r in aws_route_table.private : z => r.id }
  node_security_group_ids   = [aws_eks_cluster.this.vpc_config[0].cluster_security_group_id]
  permissions_boundary      = var.permissions_boundary
}

resource "aws_ecr_repository" "this" {
  for_each = toset(["natterjack-controller", "natterjack-agent", "natterjack", "charts/natterjack", "netshoot"])

  name                 = "${local.name}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true
}

# --- Internet side -------------------------------------------------------------

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_iam_role" "instance" {
  name_prefix          = "nj-e2e-${var.run_id}-host-"
  permissions_boundary = var.permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.node_trust.json
}

resource "aws_iam_role_policy_attachment" "instance" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name_prefix = "nj-e2e-${var.run_id}-"
  role        = aws_iam_role.instance.name
}

# "outside" lives in its own VPC, as any server on the internet would.
resource "aws_vpc" "outside" {
  cidr_block = "10.50.0.0/24"
  tags       = { Name = "${local.name}-outside" }
}

resource "aws_internet_gateway" "outside" {
  vpc_id = aws_vpc.outside.id
  tags   = { Name = "${local.name}-outside" }
}

resource "aws_subnet" "outside" {
  vpc_id            = aws_vpc.outside.id
  availability_zone = local.zones[0]
  cidr_block        = aws_vpc.outside.cidr_block
  tags              = { Name = "${local.name}-outside" }
}

resource "aws_route_table" "outside" {
  vpc_id = aws_vpc.outside.id
  tags   = { Name = "${local.name}-outside" }
}

resource "aws_route" "outside_internet" {
  route_table_id         = aws_route_table.outside.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.outside.id
}

resource "aws_route_table_association" "outside" {
  subnet_id      = aws_subnet.outside.id
  route_table_id = aws_route_table.outside.id
}

resource "aws_security_group" "outside" {
  name_prefix = "${local.name}-outside-"
  description = "HTTP and iperf3 from the slot public IPs only"
  vpc_id      = aws_vpc.outside.id
  tags        = { Name = "${local.name}-outside" }
}

resource "aws_vpc_security_group_ingress_rule" "outside" {
  # Keyed by slot: the addresses are unknown until the EIPs exist.
  for_each = { for p in setproduct(keys(module.natterjack.slots), [["tcp", 80], ["tcp", 5201], ["udp", 5201]]) : "${p[0]}/${p[1][0]}/${p[1][1]}" => p }

  security_group_id = aws_security_group.outside.id
  cidr_ipv4         = "${module.natterjack.slots[each.value[0]].public_ip}/32"
  ip_protocol       = each.value[1][0]
  from_port         = each.value[1][1]
  to_port           = each.value[1][1]
}

resource "aws_vpc_security_group_egress_rule" "outside" {
  security_group_id = aws_security_group.outside.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_instance" "outside" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.amd64_instance_type
  subnet_id                   = aws_subnet.outside.id
  vpc_security_group_ids      = [aws_security_group.outside.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  user_data_replace_on_change = true
  user_data                   = file("${path.module}/outside.sh")

  metadata_options {
    http_tokens = "required"
  }

  tags = { Name = "${local.name}-outside" }

  depends_on = [aws_route.outside_internet]
}

# "attacker" sits in a slot subnet with source/destination check off, so it
# can send packets with any source address.
resource "aws_security_group" "attacker" {
  name_prefix = "${local.name}-attacker-"
  description = "No inbound; anything outbound"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${local.name}-attacker" }
}

resource "aws_vpc_security_group_egress_rule" "attacker" {
  security_group_id = aws_security_group.attacker.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_instance" "attacker" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.amd64_instance_type
  subnet_id                   = aws_subnet.public[local.zones[0]].id
  vpc_security_group_ids      = [aws_security_group.attacker.id]
  associate_public_ip_address = true
  source_dest_check           = false
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  user_data_replace_on_change = true
  user_data                   = file("${path.module}/attacker.sh")

  metadata_options {
    http_tokens = "required"
  }

  tags = { Name = "${local.name}-attacker" }

  depends_on = [aws_route.public_internet]
}
