# Vultr Deployment for Package Repository
# Deploys to VKE (Vultr Kubernetes Engine)

terraform {
  required_version = ">= 1.0"
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
}

provider "vultr" {
  api_key = var.vultr_api_key
}

# Get VKE cluster data
data "vultr_kubernetes" "cluster" {
  filter {
    name   = "label"
    values = [var.vke_cluster_name]
  }
}

# Decode kubeconfig
locals {
  kubeconfig = yamldecode(base64decode(data.vultr_kubernetes.cluster.kube_config))
}

provider "kubernetes" {
  host                   = local.kubeconfig.clusters[0].cluster.server
  cluster_ca_certificate = base64decode(local.kubeconfig.clusters[0].cluster["certificate-authority-data"])
  client_certificate     = base64decode(local.kubeconfig.users[0].user["client-certificate-data"])
  client_key             = base64decode(local.kubeconfig.users[0].user["client-key-data"])
}

provider "helm" {
  kubernetes {
    host                   = local.kubeconfig.clusters[0].cluster.server
    cluster_ca_certificate = base64decode(local.kubeconfig.clusters[0].cluster["certificate-authority-data"])
    client_certificate     = base64decode(local.kubeconfig.users[0].user["client-certificate-data"])
    client_key             = base64decode(local.kubeconfig.users[0].user["client-key-data"])
  }
}

# Optional: Object storage for packages (Vultr Object Storage is S3-compatible)
resource "vultr_object_storage" "packages" {
  count            = var.use_object_storage ? 1 : 0
  cluster_id       = var.object_storage_cluster_id
  tier_id          = var.object_storage_tier_id
  label            = "package-repo-${var.environment}"
}

# Deploy package repository
module "package_repo" {
  source = "../modules/package-repo"

  release_name     = var.release_name
  namespace        = var.namespace
  create_namespace = true

  image_repository = var.image_repository
  image_tag        = var.image_tag

  domain          = var.domain
  ingress_enabled = true
  ingress_class_name = "nginx"
  ingress_annotations = {
    "nginx.ingress.kubernetes.io/proxy-body-size" = "500m"
    "cert-manager.io/cluster-issuer"              = "letsencrypt-prod"
  }
  tls_enabled = var.tls_enabled

  storage_size  = var.storage_size
  storage_class = "vultr-block-storage"

  api_keys = var.api_keys

  # Vultr Object Storage is S3-compatible
  s3_enabled    = var.use_object_storage
  s3_endpoint   = var.use_object_storage ? vultr_object_storage.packages[0].s3_hostname : ""
  s3_bucket     = "packages"
  s3_region     = "us-east-1"  # Vultr uses standard region naming
  s3_access_key = var.use_object_storage ? vultr_object_storage.packages[0].s3_access_key : ""
  s3_secret_key = var.use_object_storage ? vultr_object_storage.packages[0].s3_secret_key : ""

  cpu_request    = var.cpu_request
  memory_request = var.memory_request
  cpu_limit      = var.cpu_limit
  memory_limit   = var.memory_limit
}
