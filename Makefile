# Package Repository Server Makefile

.PHONY: all build build-server build-docker push run stop clean test lint help
.DEFAULT_GOAL := help

# Configuration
IMAGE_NAME ?= package-repo
IMAGE_TAG ?= latest
REGISTRY ?= docker.io
PLATFORM ?= linux/amd64,linux/arm64

# Docker Compose
COMPOSE_FILE := docker/docker-compose.yml

# Helm
HELM_RELEASE ?= package-repo
HELM_NAMESPACE ?= package-repo
HELM_VALUES ?= helm/package-repo/values.yaml

##@ Build

all: build ## Build everything

build: build-server build-docker ## Build server and Docker image

build-server: ## Build the Rust server
	@echo "Building Rust server..."
	cd server && cargo build --release

build-docker: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) -f docker/Dockerfile .

build-multiarch: ## Build multi-architecture Docker image
	@echo "Building multi-arch Docker image..."
	docker buildx build --platform $(PLATFORM) \
		-t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) \
		-f docker/Dockerfile \
		--push .

##@ Development

run: ## Run with Docker Compose
	@echo "Starting package repository..."
	docker-compose -f $(COMPOSE_FILE) up -d

run-foreground: ## Run with Docker Compose in foreground
	docker-compose -f $(COMPOSE_FILE) up

stop: ## Stop Docker Compose
	docker-compose -f $(COMPOSE_FILE) down

logs: ## Show logs
	docker-compose -f $(COMPOSE_FILE) logs -f

restart: stop run ## Restart services

dev: ## Run in development mode
	@echo "Starting development environment..."
	cd server && RUST_LOG=debug cargo run

##@ Testing

test: ## Run all tests (unit + integration)
	@echo "Running all tests..."
	cd server && cargo test --all-features

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	cd server && cargo test --lib

test-integration: ## Run integration tests only
	@echo "Running integration tests..."
	cd server && cargo test --test '*'

test-e2e: ## Run E2E tests with Docker Compose
	@echo "Running E2E tests..."
	docker-compose -f tests/e2e/docker-compose.test.yml up \
		--build \
		--abort-on-container-exit \
		--exit-code-from test-runner
	docker-compose -f tests/e2e/docker-compose.test.yml down -v

test-e2e-clean: ## Clean up E2E test containers
	docker-compose -f tests/e2e/docker-compose.test.yml down -v --rmi local

test-all: test test-e2e ## Run all tests including E2E

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	cd server && cargo tarpaulin --out Html --output-dir ../coverage

lint: ## Run linters
	@echo "Running linters..."
	cd server && cargo clippy --all-features -- -D warnings
	cd server && cargo fmt -- --check
	@echo "Linting shell scripts..."
	shellcheck docker/scripts/*.sh || true

fmt: ## Format code
	cd server && cargo fmt

audit: ## Run security audit
	@echo "Running security audit..."
	cd server && cargo audit

##@ Kubernetes

k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f kubernetes/namespace.yaml
	kubectl apply -f kubernetes/

k8s-delete: ## Delete from Kubernetes
	kubectl delete -f kubernetes/ --ignore-not-found

##@ Helm

helm-install: ## Install Helm chart
	helm upgrade --install $(HELM_RELEASE) ./helm/package-repo \
		--namespace $(HELM_NAMESPACE) \
		--create-namespace \
		-f $(HELM_VALUES)

helm-uninstall: ## Uninstall Helm chart
	helm uninstall $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)

helm-template: ## Template Helm chart
	helm template $(HELM_RELEASE) ./helm/package-repo \
		--namespace $(HELM_NAMESPACE) \
		-f $(HELM_VALUES)

helm-lint: ## Lint Helm chart
	helm lint ./helm/package-repo

helm-package: ## Package Helm chart
	helm package ./helm/package-repo

##@ Terraform

tf-init-aws: ## Initialize Terraform for AWS
	cd terraform/aws && terraform init

tf-plan-aws: ## Plan Terraform for AWS
	cd terraform/aws && terraform plan

tf-apply-aws: ## Apply Terraform for AWS
	cd terraform/aws && terraform apply

tf-init-gcp: ## Initialize Terraform for GCP
	cd terraform/gcp && terraform init

tf-plan-gcp: ## Plan Terraform for GCP
	cd terraform/gcp && terraform plan

tf-apply-gcp: ## Apply Terraform for GCP
	cd terraform/gcp && terraform apply

tf-init-azure: ## Initialize Terraform for Azure
	cd terraform/azure && terraform init

tf-plan-azure: ## Plan Terraform for Azure
	cd terraform/azure && terraform plan

tf-apply-azure: ## Apply Terraform for Azure
	cd terraform/azure && terraform apply

tf-init-do: ## Initialize Terraform for DigitalOcean
	cd terraform/digitalocean && terraform init

tf-plan-do: ## Plan Terraform for DigitalOcean
	cd terraform/digitalocean && terraform plan

tf-apply-do: ## Apply Terraform for DigitalOcean
	cd terraform/digitalocean && terraform apply

tf-init-vultr: ## Initialize Terraform for Vultr
	cd terraform/vultr && terraform init

tf-plan-vultr: ## Plan Terraform for Vultr
	cd terraform/vultr && terraform plan

tf-apply-vultr: ## Apply Terraform for Vultr
	cd terraform/vultr && terraform apply

##@ Utilities

clean: ## Clean build artifacts
	@echo "Cleaning..."
	cd server && cargo clean
	docker-compose -f $(COMPOSE_FILE) down -v --rmi local
	rm -rf target/

push: ## Push Docker image
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

shell: ## Open shell in running container
	docker-compose -f $(COMPOSE_FILE) exec package-repo /bin/bash

generate-key: ## Generate a secure API key
	@openssl rand -hex 32

##@ Help

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
