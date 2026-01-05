use actix_web::{HttpRequest, HttpResponse, Responder};

/// Returns a shell script for easy APT repository setup
pub async fn apt_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let script = format!(
        r#"#!/bin/bash
# Package Repository - APT Setup Script
# Usage: curl -fsSL {scheme}://{host}/setup/apt | sudo bash

set -e

REPO_URL="{scheme}://{host}"
KEYRING_PATH="/usr/share/keyrings/package-repo.gpg"
LIST_PATH="/etc/apt/sources.list.d/package-repo.list"

echo "Setting up APT repository from $REPO_URL..."

# Download and install GPG key
echo "Downloading GPG key..."
curl -fsSL "$REPO_URL/repo.gpg" | gpg --dearmor -o "$KEYRING_PATH"

# Add repository
echo "Adding repository..."
cat > "$LIST_PATH" << EOF
deb [signed-by=$KEYRING_PATH] $REPO_URL/deb stable main
EOF

# Update package lists
echo "Updating package lists..."
apt-get update

echo ""
echo "Done! Repository configured successfully."
echo "You can now install packages with: apt install <package-name>"
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/x-shellscript")
        .body(script)
}

/// Returns a shell script for easy YUM/DNF repository setup
pub async fn rpm_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let script = format!(
        r#"#!/bin/bash
# Package Repository - YUM/DNF Setup Script
# Usage: curl -fsSL {scheme}://{host}/setup/rpm | sudo bash

set -e

REPO_URL="{scheme}://{host}"

echo "Setting up YUM/DNF repository from $REPO_URL..."

# Create repo file
cat > /etc/yum.repos.d/package-repo.repo << EOF
[package-repo]
name=Package Repository
baseurl=$REPO_URL/rpm/\$basearch/
enabled=1
gpgcheck=1
gpgkey=$REPO_URL/repo.gpg
EOF

# Import GPG key
echo "Importing GPG key..."
rpm --import "$REPO_URL/repo.gpg"

# Update cache
echo "Updating package cache..."
if command -v dnf &> /dev/null; then
    dnf makecache
else
    yum makecache
fi

echo ""
echo "Done! Repository configured successfully."
echo "You can now install packages with: dnf install <package-name>"
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/x-shellscript")
        .body(script)
}

/// Returns a shell script for easy Pacman repository setup
pub async fn arch_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let script = format!(
        r#"#!/bin/bash
# Package Repository - Pacman Setup Script
# Usage: curl -fsSL {scheme}://{host}/setup/arch | sudo bash

set -e

REPO_URL="{scheme}://{host}"

echo "Setting up Pacman repository from $REPO_URL..."

# Check if already configured
if grep -q "package-repo" /etc/pacman.conf 2>/dev/null; then
    echo "Repository already configured in /etc/pacman.conf"
else
    # Add repository to pacman.conf
    echo "Adding repository to /etc/pacman.conf..."
    cat >> /etc/pacman.conf << EOF

[package-repo]
SigLevel = Optional TrustAll
Server = $REPO_URL/arch/\$arch
EOF
fi

# Sync databases
echo "Syncing package databases..."
pacman -Sy

echo ""
echo "Done! Repository configured successfully."
echo "You can now install packages with: pacman -S <package-name>"
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/x-shellscript")
        .body(script)
}

/// Returns a shell script for easy APK repository setup
pub async fn alpine_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let script = format!(
        r#"#!/bin/sh
# Package Repository - APK Setup Script
# Usage: curl -fsSL {scheme}://{host}/setup/alpine | sh
# Note: Uses /bin/sh for Alpine compatibility (no bash required)

set -e

REPO_URL="{scheme}://{host}"

echo "Setting up APK repository from $REPO_URL..."

# Download GPG key
echo "Downloading repository key..."
wget -qO /etc/apk/keys/package-repo.rsa.pub "$REPO_URL/repo.gpg"

# Add repository if not already present
if ! grep -q "$REPO_URL/alpine" /etc/apk/repositories 2>/dev/null; then
    echo "Adding repository..."
    echo "$REPO_URL/alpine/v3.19/main" >> /etc/apk/repositories
fi

# Update package index
echo "Updating package index..."
apk update

echo ""
echo "Done! Repository configured successfully."
echo "You can now install packages with: apk add <package-name>"
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/x-shellscript")
        .body(script)
}

/// Returns Cargo configuration for private registry setup
pub async fn cargo_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let config = format!(
        r#"# Cargo Private Registry Configuration
# Add this to ~/.cargo/config.toml

[registries.private]
index = "sparse+{scheme}://{host}/cargo/index/"

# Set as default registry (optional)
[registry]
default = "private"

# Authentication - set your token
[registries.private]
token = "Bearer YOUR_API_KEY_HERE"

# Alternative: use credential process
# [registries.private]
# credential-provider = ["cargo:token"]

# ---
# Usage:
#   cargo publish --registry private
#   cargo add my-crate --registry private
#
# Or with default registry set:
#   cargo publish
#   cargo add my-crate
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(config)
}

/// Returns npm configuration for private registry setup
pub async fn npm_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let npmrc = format!(
        r#"# npm Private Registry Configuration
# Add this to ~/.npmrc or project .npmrc

# Set registry for all packages
registry={scheme}://{host}/npm/

# Authentication (replace with your API key)
//{host}/npm/:_authToken=YOUR_API_KEY_HERE

# ---
# For scoped packages only (@myorg/*), use:
#
# @myorg:registry={scheme}://{host}/npm/
# //{host}/npm/:_authToken=YOUR_API_KEY_HERE
#
# This allows mixing public npm packages with private scoped packages
#
# ---
# Usage:
#   npm publish
#   npm install my-package
#   npm install @myorg/my-package
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(npmrc)
}

/// Returns pip configuration for private PyPI registry
pub async fn pypi_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let config = format!(
        r#"# pip Private Registry Configuration
# Add this to ~/.pip/pip.conf (Linux/Mac) or %APPDATA%\pip\pip.ini (Windows)

[global]
index-url = {scheme}://__token__:YOUR_API_KEY_HERE@{host}/pypi/simple/
trusted-host = {host}

# Or use environment variables:
# export PIP_INDEX_URL="{scheme}://__token__:YOUR_API_KEY_HERE@{host}/pypi/simple/"
# export PIP_TRUSTED_HOST="{host}"

# ---
# For twine uploads, create ~/.pypirc:
#
# [distutils]
# index-servers = private
#
# [private]
# repository = {scheme}://{host}/pypi/
# username = __token__
# password = YOUR_API_KEY_HERE
#
# Then upload with: twine upload --repository private dist/*
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(config)
}

/// Returns Maven configuration for private repository
pub async fn maven_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let config = format!(
        r#"<!-- Maven Private Repository Configuration -->
<!-- Add to ~/.m2/settings.xml -->

<settings>
  <servers>
    <server>
      <id>private-repo</id>
      <username>token</username>
      <password>YOUR_API_KEY_HERE</password>
    </server>
  </servers>
</settings>

<!-- Add to your pom.xml -->
<repositories>
  <repository>
    <id>private-repo</id>
    <url>{scheme}://{host}/maven/</url>
  </repository>
</repositories>

<distributionManagement>
  <repository>
    <id>private-repo</id>
    <url>{scheme}://{host}/maven/</url>
  </repository>
</distributionManagement>

<!-- For Gradle, add to build.gradle: -->
<!--
repositories {{
    maven {{
        url "{scheme}://{host}/maven/"
        credentials {{
            username = "token"
            password = "YOUR_API_KEY_HERE"
        }}
    }}
}}

publishing {{
    repositories {{
        maven {{
            url "{scheme}://{host}/maven/"
            credentials {{
                username = "token"
                password = "YOUR_API_KEY_HERE"
            }}
        }}
    }}
}}
-->
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(config)
}

/// Returns Docker configuration for private registry
pub async fn docker_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let config = format!(
        r#"# Docker Private Registry Configuration

# 1. Login to the registry:
echo "YOUR_API_KEY_HERE" | docker login {host} -u token --password-stdin

# 2. Tag and push images:
docker tag myimage:latest {host}/myimage:latest
docker push {host}/myimage:latest

# 3. Pull images:
docker pull {host}/myimage:latest

# ---
# For Docker daemon configuration (if using HTTP):
# Add to /etc/docker/daemon.json:
#
# {{
#   "insecure-registries": ["{host}"]
# }}
#
# Then restart Docker: sudo systemctl restart docker

# ---
# For Kubernetes, create a secret:
# kubectl create secret docker-registry regcred \
#   --docker-server={host} \
#   --docker-username=token \
#   --docker-password=YOUR_API_KEY_HERE

# ---
# For containerd (nerdctl), add to /etc/containerd/config.toml:
# [plugins."io.containerd.grpc.v1.cri".registry.configs."{host}".auth]
#   username = "token"
#   password = "YOUR_API_KEY_HERE"
"#,
        host = host
    );
    let _ = scheme; // May be used in future for protocol-aware config

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(config)
}

/// Returns NuGet configuration for private registry
pub async fn nuget_setup(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let config = format!(
        r#"# NuGet Private Registry Configuration

# Option 1: Add source via CLI
dotnet nuget add source {scheme}://{host}/nuget/v3/index.json \
  --name private \
  --username token \
  --password YOUR_API_KEY_HERE \
  --store-password-in-clear-text

# Option 2: Add to NuGet.Config (user-level: ~/.nuget/NuGet/NuGet.Config)
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="private" value="{scheme}://{host}/nuget/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <private>
      <add key="Username" value="token" />
      <add key="ClearTextPassword" value="YOUR_API_KEY_HERE" />
    </private>
  </packageSourceCredentials>
</configuration>

# ---
# Usage:

# Push a package:
dotnet nuget push MyPackage.1.0.0.nupkg \
  --source private \
  --api-key YOUR_API_KEY_HERE

# Install a package:
dotnet add package MyPackage --source private

# Or set as default source in your project's nuget.config:
# Then just use: dotnet add package MyPackage

# ---
# For CI/CD, set environment variables:
# export NUGET_SOURCE="{scheme}://{host}/nuget/v3/index.json"
# export NUGET_API_KEY="YOUR_API_KEY_HERE"
#
# Then use:
# dotnet nuget push *.nupkg --source $NUGET_SOURCE --api-key $NUGET_API_KEY
"#,
        scheme = scheme,
        host = host
    );

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(config)
}
