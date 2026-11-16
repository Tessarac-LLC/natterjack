variable "cluster_name" {
  description = "Kubernetes cluster name. The same value as the chart's clusterName; slots are tagged with it and IAM is scoped to it."
  type        = string

  validation {
    condition     = can(regex("^[0-9A-Za-z][0-9A-Za-z_-]{0,99}$", var.cluster_name))
    error_message = "cluster_name must be a valid EKS cluster name."
  }
}

variable "slot_subnets" {
  description = "Public subnets to create slots in, keyed by zone name, at most one per zone. Each must route 0.0.0.0/0 to an internet gateway. Slot ENIs can only attach to nodes in the same zone. The keys must be known when Terraform plans, so use zone names rather than subnet IDs: subnets created in the same apply have no ID yet."
  type        = map(string)

  validation {
    condition     = length(var.slot_subnets) > 0
    error_message = "Give at least one public subnet."
  }
}

variable "slots_per_subnet" {
  description = "Slots (ENI with an Elastic IP) per subnet. Two give a zone a warm replacement: the controller fails over by moving an attached slot or using a spare."
  type        = number
  default     = 2

  validation {
    condition     = var.slots_per_subnet >= 1 && var.slots_per_subnet == floor(var.slots_per_subnet)
    error_message = "slots_per_subnet must be a whole number of at least 1."
  }
}

variable "slot_eip_allocation_ids" {
  description = "Existing Elastic IP allocations to give slots instead of new ones, keyed by slot as zone/index (\"us-east-1a/0\" is the zone's first slot). Use it to keep addresses others allow-list, such as a NAT gateway's after deleting the gateway. Terraform never releases an adopted address."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([for k in keys(var.slot_eip_allocation_ids) : (
      length(split("/", k)) == 2
      && contains(keys(var.slot_subnets), split("/", k)[0])
      && can(tonumber(split("/", k)[1]))
      && try(tonumber(split("/", k)[1]) >= 0 && tonumber(split("/", k)[1]) < var.slots_per_subnet && floor(tonumber(split("/", k)[1])) == tonumber(split("/", k)[1]), false)
    )])
    error_message = "Every slot_eip_allocation_ids key must name a slot: a slot_subnets key, a slash, and an index below slots_per_subnet."
  }

  validation {
    condition     = length(distinct(values(var.slot_eip_allocation_ids))) == length(var.slot_eip_allocation_ids)
    error_message = "An Elastic IP allocation can belong to only one slot."
  }
}

variable "bootstrap_route_table_ids" {
  description = "Private route tables, keyed by zone name as in slot_subnets, whose 0.0.0.0/0 route should point at that zone's first slot. Nodes then reach the internet before their agent runs. Leave empty if the cluster keeps another default route."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for z in keys(var.bootstrap_route_table_ids) : contains(keys(var.slot_subnets), z)])
    error_message = "Every bootstrap_route_table_ids key must also be a slot_subnets key."
  }
}

variable "bootstrap_source_cidrs" {
  description = "Sources the slots admit when bootstrap_route_table_ids is set: the addresses of the nodes and pods behind those route tables. Null admits the VPC's primary CIDR; list a secondary CIDR here if nodes or pods use one."
  type        = list(string)
  default     = null

  validation {
    condition = var.bootstrap_source_cidrs == null || alltrue([
      for c in coalesce(var.bootstrap_source_cidrs, []) : can(cidrhost(c, 0)) && can(regex("^[0-9.]+/[0-9]+$", c)) && tonumber(split("/", c)[1]) >= 8
    ])
    error_message = "bootstrap_source_cidrs must be IPv4 CIDRs no wider than /8."
  }
}

variable "node_security_group_ids" {
  description = "Security groups of the cluster's nodes. The module allows the agent tunnels (UDP) from each of these groups to each. Empty to manage the rules yourself."
  type        = list(string)
  default     = []
}

variable "tunnel_port" {
  description = "UDP port of the agent tunnel. Must match the chart's agent.tunnelPort."
  type        = number
  default     = 6081

  validation {
    condition     = var.tunnel_port >= 1 && var.tunnel_port <= 65535 && floor(var.tunnel_port) == var.tunnel_port
    error_message = "tunnel_port must be a port number."
  }
}

variable "wireguard_port" {
  description = "UDP port of the agent WireGuard tunnel, used by pools with tunnel WireGuard. Must match the chart's agent.wireguardPort and differ from tunnel_port."
  type        = number
  default     = 51871

  validation {
    condition     = var.wireguard_port >= 1 && var.wireguard_port <= 65535 && floor(var.wireguard_port) == var.wireguard_port && var.wireguard_port != var.tunnel_port
    error_message = "wireguard_port must be a port number different from tunnel_port."
  }
}

variable "identity" {
  description = "How the controller gets AWS credentials: \"pod-identity\" (EKS Pod Identity; the eks-pod-identity-agent add-on must be installed) or \"irsa\" (IAM roles for service accounts)."
  type        = string
  default     = "pod-identity"

  validation {
    condition     = contains(["pod-identity", "irsa"], var.identity)
    error_message = "identity must be \"pod-identity\" or \"irsa\"."
  }
}

variable "oidc_provider_arn" {
  description = "ARN of the cluster's IAM OIDC provider. Required when identity is \"irsa\"."
  type        = string
  default     = null
}

variable "namespace" {
  description = "Namespace the chart is installed in."
  type        = string
  default     = "natterjack"
}

variable "service_account" {
  description = "The controller's ServiceAccount name. The chart default is `<release>-controller`, so `natterjack-controller` for a release named natterjack."
  type        = string
  default     = "natterjack-controller"
}

variable "tags" {
  description = "Tags added to every resource the module creates. Cannot override the natterjack.io and no_manage tags."
  type        = map(string)
  default     = {}
}

variable "permissions_boundary" {
  description = "ARN of a permissions boundary for the controller's IAM role, for accounts that require one on every role. Null for none."
  type        = string
  default     = null
}
