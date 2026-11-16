variable "run_id" {
  description = "Names this run's resources and tags every one of them, so a failed run can be found and destroyed."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.run_id))
    error_message = "run_id is 1 to 20 lowercase letters, digits and hyphens."
  }
}

variable "region" {
  description = "Region to test in. It needs four free Elastic IPs."
  type        = string
  default     = "us-east-2"
}

variable "api_allowed_cidrs" {
  description = "Addresses allowed to reach the cluster's public API endpoint: the machine running the test."
  type        = list(string)
}

variable "kubernetes_version" {
  description = "EKS version. Null picks the newest one in standard support."
  type        = string
  default     = null
}

variable "amd64_instance_type" {
  description = "Instance type of the amd64 nodes."
  type        = string
  default     = "m7i.large"
}

variable "arm64_instance_type" {
  description = "Instance type of the arm64 nodes."
  type        = string
  default     = "m7g.large"
}

variable "permissions_boundary" {
  description = "ARN of the permissions boundary every IAM role this environment creates must carry. CI's role may create roles only with it; null for a person's run."
  type        = string
  default     = null
}
