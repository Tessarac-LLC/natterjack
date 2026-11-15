variable "cluster_name" {
  description = "Kubernetes cluster name. The same value as the chart's clusterName; slots are tagged with it and IAM is scoped to it."
  type        = string

  validation {
    condition     = can(regex("^[0-9A-Za-z][0-9A-Za-z_-]{0,99}$", var.cluster_name))
    error_message = "cluster_name must be a valid EKS cluster name."
  }
}

variable "slot_subnet_ids" {
  description = "Public subnets to create slots in, at most one per zone. Each must route 0.0.0.0/0 to an internet gateway. Slot ENIs can only attach to nodes in the same zone."
  type        = list(string)

  validation {
    condition     = length(var.slot_subnet_ids) > 0
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

variable "bootstrap_route_table_ids" {
  description = "Private route tables, keyed by the slot subnet ID in the same zone, whose 0.0.0.0/0 route should point at that zone's first slot. Nodes then reach the internet before their agent runs. Leave empty if the cluster keeps another default route."
  type        = map(string)
  default     = {}
}

variable "node_security_group_id" {
  description = "Security group shared by the cluster's nodes. The module allows the agent tunnel (UDP) between members of this group. Null to manage the rule yourself."
  type        = string
  default     = null
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
