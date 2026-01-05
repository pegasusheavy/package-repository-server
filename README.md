# Package Repository Server

A self-hosted, multi-format package repository server supporting **DEB** (Debian/Ubuntu), **RPM** (RHEL/Fedora/Rocky), **Arch Linux**, and **Alpine Linux** packages with automatic indexing, GPG signing, and multi-architecture support (x86_64/ARM64).

Built entirely in Rust - uses **Actix** for the API server and **Ferron** for static file serving.

## Features

- **Multi-Format Support**: APT, YUM/DNF, Pacman, and APK repositories in one server
- **Multi-Architecture**: Full support for x86_64 (amd64) and ARM64 (aarch64)
- **Automatic Indexing**: Packages are automatically indexed and signed on upload
- **GPG Signing**: All repository metadata is GPG-signed for security
- **SSO Authentication**: OAuth 2.0 / OpenID Connect support (Google, GitHub, GitLab, Microsoft, Okta, Auth0, Keycloak)
- **Stateless Backend**: No session storage required - horizontally scalable out of the box
- **REST API**: Full API for CI/CD integration
- **S3 Compatible Storage**: Optional S3-compatible backend (AWS S3, MinIO, DigitalOcean Spaces, etc.)
- **Pure Rust**: Actix API server + Ferron static file server
- **Cloud Ready**: Terraform modules for AWS, GCP, Azure, DigitalOcean, and Vultr

## Quick Start

### Docker Compose (HTTP)

```bash
# Clone the repository
git clone https://github.com/your-org/package-repo.git
cd package-repo

# Generate an API key
API_KEY=$(openssl rand -hex 32)
echo "Your API key: $API_KEY"

# Start the server
API_KEYS=$API_KEY docker-compose -f docker/docker-compose.yml up -d

# Repositories at http://localhost/deb, /rpm, /arch, /alpine
```

### Docker Compose with HTTPS (Let's Encrypt)

```bash
# Set your domain and email
export DOMAIN=packages.example.com
export ADMIN_EMAIL=admin@example.com
export API_KEYS=$(openssl rand -hex 32)

# Start with TLS
docker-compose -f docker/docker-compose.yml -f docker/docker-compose.tls.yml up -d

# Obtain Let's Encrypt certificate
docker exec package-repo setup-ssl letsencrypt

# Restart to apply
docker-compose restart
```

### Self-Signed Certificate (Testing)

```bash
# Generate self-signed cert
docker exec package-repo setup-ssl selfsigned

# Restart to apply
docker-compose restart
```

### Build from Source

```bash
# Build everything
make build

# Run
make run

# View logs
make logs
```

## Client Configuration

### One-Liner Setup (Recommended)

The easiest way to add the repository to your system:

```bash
# Ubuntu/Debian (APT)
curl -fsSL https://packages.example.com/setup/apt | sudo bash

# RHEL/Fedora/Rocky (YUM/DNF)
curl -fsSL https://packages.example.com/setup/rpm | sudo bash

# Arch Linux (Pacman)
curl -fsSL https://packages.example.com/setup/arch | sudo bash

# Alpine Linux (APK)
curl -fsSL https://packages.example.com/setup/alpine | sudo sh
```

That's it! After running the one-liner, you can install packages normally:
- APT: `sudo apt install <package>`
- DNF: `sudo dnf install <package>`
- Pacman: `sudo pacman -S <package>`
- APK: `apk add <package>`

### Manual Configuration

<details>
<summary>Click to expand manual setup instructions</summary>

#### Debian/Ubuntu (APT)

```bash
# Add GPG key
curl -fsSL https://packages.example.com/repo.gpg | sudo gpg --dearmor -o /usr/share/keyrings/custom-repo.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/custom-repo.gpg] https://packages.example.com/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/custom.list

# Update and install
sudo apt update
```

#### RHEL/Fedora/Rocky (YUM/DNF)

```bash
# Create repo file
sudo tee /etc/yum.repos.d/custom.repo << EOF
[custom-repo]
name=Custom Repository
baseurl=https://packages.example.com/rpm/\$basearch/
enabled=1
gpgcheck=1
gpgkey=https://packages.example.com/repo.gpg
EOF
```

#### Arch Linux (Pacman)

```bash
# Add to /etc/pacman.conf
[custom]
SigLevel = Optional TrustAll
Server = https://packages.example.com/arch/$arch

# Sync databases
sudo pacman -Sy
```

#### Alpine Linux (APK)

```bash
# Add repository
echo "https://packages.example.com/alpine/v3.19/main" >> /etc/apk/repositories

# Import key
wget -qO /etc/apk/keys/repo.rsa.pub https://packages.example.com/repo.gpg
```

</details>

## API Usage

### Upload a Package

```bash
# Upload DEB package
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -F "file=@mypackage_1.0.0_amd64.deb" \
  https://packages.example.com/api/v1/upload/deb

# Upload RPM package
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -F "file=@mypackage-1.0.0-1.x86_64.rpm" \
  https://packages.example.com/api/v1/upload/rpm

# Upload Arch package
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -F "file=@mypackage-1.0.0-1-x86_64.pkg.tar.zst" \
  https://packages.example.com/api/v1/upload/arch

# Upload Alpine package
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -F "file=@mypackage-1.0.0-r0.apk" \
  https://packages.example.com/api/v1/upload/alpine
```

### List Packages

```bash
# List all packages
curl https://packages.example.com/api/v1/packages

# List by type
curl https://packages.example.com/api/v1/packages/deb
curl https://packages.example.com/api/v1/packages/rpm
```

### Delete a Package

```bash
curl -X DELETE \
  -H "X-API-Key: your-api-key" \
  https://packages.example.com/api/v1/packages/deb/mypackage
```

### Rebuild Repository

```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  https://packages.example.com/api/v1/repos/deb/rebuild
```

## CI/CD Integration

Repository indexes **automatically update** when packages are uploaded - no manual rebuild required. This makes it easy to integrate with any CI/CD system.

### Quick Example (Any CI System)

```bash
# Upload triggers automatic re-indexing
curl -X POST \
  -H "X-API-Key: $PACKAGE_REPO_API_KEY" \
  -F "file=@mypackage_1.0.0_amd64.deb" \
  https://packages.example.com/api/v1/upload/deb
```

### Ready-to-Use CI Configurations

Example configurations are provided in `ci-examples/`:

| Platform | File | Trigger |
|----------|------|---------|
| GitHub Actions | `github-actions.yml` | Release published, manual |
| GitLab CI | `gitlab-ci.yml` | Tags (v*) |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` | Tags (v*), manual |
| Jenkins | `jenkins-pipeline.groovy` | Parameterized |
| Azure DevOps | `azure-devops.yml` | Tags (v*) |
| Drone CI | `drone-ci.yml` | Tags |

### Required Secrets/Variables

Configure these in your CI system:

| Variable | Description |
|----------|-------------|
| `PACKAGE_REPO_URL` | Your repository URL (e.g., `https://packages.example.com`) |
| `PACKAGE_REPO_API_KEY` | API key for authentication |

### GitHub Actions Example

```yaml
# .github/workflows/publish.yml
name: Publish Package
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build package
        run: dpkg-deb --build ./package mypackage_${{ github.ref_name }}_amd64.deb

      - name: Upload to repository
        run: |
          curl -X POST \
            -H "X-API-Key: ${{ secrets.PACKAGE_REPO_API_KEY }}" \
            -F "file=@mypackage_${{ github.ref_name }}_amd64.deb" \
            "${{ vars.PACKAGE_REPO_URL }}/api/v1/upload/deb"
```

### GitLab CI Example

```yaml
# .gitlab-ci.yml
publish:
  stage: deploy
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST \
        -H "X-API-Key: ${PACKAGE_REPO_API_KEY}" \
        -F "file=@mypackage_${CI_COMMIT_TAG}_amd64.deb" \
        "${PACKAGE_REPO_URL}/api/v1/upload/deb"
  rules:
    - if: $CI_COMMIT_TAG
```

## Deployment

### Kubernetes

```bash
# Apply manifests directly
kubectl apply -f kubernetes/

# Or use Helm
helm install package-repo ./helm/package-repo \
  --namespace package-repo \
  --create-namespace \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=packages.example.com \
  --set config.apiKeys[0]="your-secure-api-key"
```

### Terraform

#### AWS (EKS)

```bash
cd terraform/aws

cat > terraform.tfvars << EOF
eks_cluster_name = "my-cluster"
domain           = "packages.example.com"
api_keys         = ["your-secure-api-key"]
use_s3_storage   = true
s3_bucket_name   = "my-packages"
EOF

terraform init
terraform apply
```

#### GCP (GKE)

```bash
cd terraform/gcp

cat > terraform.tfvars << EOF
gcp_project          = "my-project"
gke_cluster_name     = "my-cluster"
gke_cluster_location = "us-central1"
domain               = "packages.example.com"
api_keys             = ["your-secure-api-key"]
EOF

terraform init
terraform apply
```

#### Azure (AKS)

```bash
cd terraform/azure

cat > terraform.tfvars << EOF
resource_group_name = "my-rg"
aks_cluster_name    = "my-cluster"
domain              = "packages.example.com"
api_keys            = ["your-secure-api-key"]
EOF

terraform init
terraform apply
```

#### DigitalOcean (DOKS)

```bash
cd terraform/digitalocean

cat > terraform.tfvars << EOF
do_token          = "your-do-token"
doks_cluster_name = "my-cluster"
domain            = "packages.example.com"
api_keys          = ["your-secure-api-key"]
EOF

terraform init
terraform apply
```

#### Vultr (VKE)

```bash
cd terraform/vultr

cat > terraform.tfvars << EOF
vultr_api_key    = "your-vultr-key"
vke_cluster_name = "my-cluster"
domain           = "packages.example.com"
api_keys         = ["your-secure-api-key"]
EOF

terraform init
terraform apply
```

## Authentication

### API Key Authentication

For service accounts, CI/CD, and automation:

```bash
# Generate a secure API key
API_KEY=$(openssl rand -hex 32)

# Use in requests
curl -H "X-API-Key: $API_KEY" \
  -F "file=@package.deb" \
  https://packages.example.com/api/v1/upload/deb
```

### SSO Authentication

Enable OAuth 2.0 / OpenID Connect for user login:

```bash
# Enable SSO
export SSO_ENABLED=true
export SSO_JWT_SECRET=$(openssl rand -hex 32)
export SSO_BASE_URL=https://packages.example.com

# Configure Google SSO
export SSO_GOOGLE_ENABLED=true
export SSO_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
export SSO_GOOGLE_CLIENT_SECRET=your-secret
export SSO_GOOGLE_ALLOWED_DOMAINS=example.com

# Start server
docker-compose up -d
```

**Supported SSO Providers:**
- Google (Google Workspace)
- GitHub
- GitLab (SaaS and self-hosted)
- Microsoft / Azure AD
- Okta
- Auth0
- Keycloak
- Generic OIDC (any compliant provider)

See [docs/SSO_CONFIGURATION.md](docs/SSO_CONFIGURATION.md) for complete SSO setup guide.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_KEYS` | Comma-separated list of valid API keys | `default-change-me` |
| `REPO_DATA_DIR` | Package storage directory | `/data/packages` |
| `REPO_GPG_DIR` | GPG keys directory | `/data/gpg` |
| `RUST_LOG` | Log level (trace, debug, info, warn, error) | `info` |
| `S3_ENABLED` | Enable S3 storage backend | `false` |
| `S3_ENDPOINT` | S3 endpoint URL | `` |
| `S3_BUCKET` | S3 bucket name | `packages` |
| `S3_REGION` | S3 region | `us-east-1` |
| `S3_ACCESS_KEY` | S3 access key | `` |
| `S3_SECRET_KEY` | S3 secret key | `` |
| `SSO_ENABLED` | Enable SSO authentication | `false` |
| `SSO_JWT_SECRET` | JWT secret for session tokens | `` |
| `SSO_BASE_URL` | Base URL for OAuth redirects | `` |

### Helm Values

See `helm/package-repo/values.yaml` for all available options.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Package Repository Server                 │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────┐  ┌───────────────────────────┐ │
│  │     Actix REST API      │  │    Package Processor      │ │
│  │     (Port 8080)         │  │    (Sign & Index)         │ │
│  └─────────────────────────┘  └───────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Ferron (Static File Serving)               ││
│  │  /deb/* → APT repo    /rpm/* → YUM repo                ││
│  │  /arch/* → Pacman     /alpine/* → APK repo             ││
│  └─────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Storage (Local / S3-compatible)            ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Development

```bash
# Run development server
make dev

# Run tests
make test

# Lint code
make lint

# Format code
make fmt
```

## Security

- Always use strong, randomly generated API keys
- Enable TLS in production (use cert-manager for automatic certificates)
- GPG keys are auto-generated on first run; backup `/data/gpg` for persistence
- Consider network policies to restrict access

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for details.

Copyright 2026 Pegasus Heavy Industries LLC
