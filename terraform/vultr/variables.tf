variable "vultr_api_key" {
  description = "Vultr API key"
  type        = string
  sensitive   = true
}

variable "vke_cluster_name" {
  description = "VKE cluster name (label)"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "release_name" {
  description = "Helm release name"
  type        = string
  default     = "package-repo"
}

variable "namespace" {
  description = "Kubernetes namespace"
  type        = string
  default     = "package-repo"
}

variable "image_repository" {
  description = "Docker image repository"
  type        = string
  default     = "package-repo"
}

variable "image_tag" {
  description = "Docker image tag"
  type        = string
  default     = "latest"
}

variable "domain" {
  description = "Domain name for package repository"
  type        = string
}

variable "tls_enabled" {
  description = "Enable TLS"
  type        = bool
  default     = true
}

variable "storage_size" {
  description = "Storage size"
  type        = string
  default     = "50Gi"
}

variable "use_object_storage" {
  description = "Use Vultr Object Storage for packages"
  type        = bool
  default     = false
}

variable "object_storage_cluster_id" {
  description = "Vultr Object Storage cluster ID"
  type        = number
  default     = 2  # ewr1 (New Jersey)
}

variable "object_storage_tier_id" {
  description = "Vultr Object Storage tier ID"
  type        = string
  default     = "storage_tier_5gb_0_00500"
}

variable "api_keys" {
  description = "API keys for authentication"
  type        = list(string)
  sensitive   = true
}

variable "cpu_request" {
  description = "CPU request"
  type        = string
  default     = "100m"
}

variable "memory_request" {
  description = "Memory request"
  type        = string
  default     = "256Mi"
}

variable "cpu_limit" {
  description = "CPU limit"
  type        = string
  default     = "1000m"
}

variable "memory_limit" {
  description = "Memory limit"
  type        = string
  default     = "1Gi"
}
