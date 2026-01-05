# Contributing to Package Repository Server

First off, thank you for considering contributing to Package Repository Server! It's people like you that make this project better for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to creating a welcoming and inclusive environment. Please be respectful and constructive in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/package-repo.git
   cd package-repo
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/pegasusheavy/package-repo.git
   ```

## Development Setup

### Prerequisites

- **Rust** (1.75 or later): https://rustup.rs/
- **Docker** and **Docker Compose**: For testing the full stack
- **make**: For running common tasks

### Building Locally

```bash
# Build the Rust API server
cd server
cargo build

# Run tests
cargo test

# Check formatting and lints
cargo fmt --check
cargo clippy

# Build Docker image
cd ..
docker build -f docker/Dockerfile.standalone -t package-repo:dev .
```

### Running Locally

```bash
# Using Docker Compose (recommended)
API_KEYS=dev-key docker-compose -f docker/docker-compose.yml up

# Or run the server directly (requires external dependencies)
cd server
RUST_LOG=debug API_KEYS=dev-key cargo run
```

## Making Changes

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes**, following our [coding standards](#coding-standards)

3. **Test your changes** thoroughly

4. **Commit your changes** with a clear commit message:
   ```bash
   git commit -m "feat: add support for XYZ"
   # or
   git commit -m "fix: resolve issue with ABC"
   ```

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

## Coding Standards

### Rust Code

- Run `cargo fmt` before committing
- Ensure `cargo clippy` passes without warnings
- Write documentation comments for public APIs
- Use meaningful variable and function names
- Handle errors appropriately (avoid `.unwrap()` in production code)

### Shell Scripts

- Use `#!/bin/bash` shebang
- Include `set -e` for error handling
- Quote variables to prevent word splitting
- Pass ShellCheck without warnings

### Terraform

- Use consistent naming conventions
- Include descriptions for variables
- Run `terraform fmt` before committing
- Validate with `terraform validate`

### Helm Charts

- Follow Helm best practices
- Include chart documentation
- Test with `helm lint`

## Testing

### Unit Tests

```bash
cd server
cargo test
```

### Integration Testing

```bash
# Start the server
docker-compose -f docker/docker-compose.yml up -d

# Test package upload
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -F "file=@test-package.deb" \
  http://localhost/api/v1/upload/deb

# Check health
curl http://localhost:8080/health
```

### Testing Different Package Types

When making changes to package processing, test all affected package types:

- **DEB**: Test with `.deb` packages on Debian/Ubuntu
- **RPM**: Test with `.rpm` packages on Fedora/RHEL
- **Arch**: Test with `.pkg.tar.zst` packages on Arch Linux
- **Alpine**: Test with `.apk` packages on Alpine Linux

## Submitting Changes

1. **Push your branch** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** against the `main` branch

3. **Fill out the PR template** completely

4. **Wait for review** - maintainers will review your PR and may request changes

5. **Address feedback** by pushing additional commits to your branch

### PR Requirements

- All CI checks must pass
- Code must be reviewed by at least one maintainer
- Documentation must be updated if applicable
- Tests must be added for new functionality

## Reporting Bugs

Use the [Bug Report template](https://github.com/pegasusheavy/package-repo/issues/new?template=bug_report.yml) and include:

- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Docker version, etc.)
- Relevant logs

## Suggesting Features

Use the [Feature Request template](https://github.com/pegasusheavy/package-repo/issues/new?template=feature_request.yml) and include:

- Problem statement
- Proposed solution
- Alternative approaches considered
- Your willingness to contribute

## Questions?

- Open a [Discussion](https://github.com/pegasusheavy/package-repo/discussions) for general questions
- Check existing issues and PRs before creating new ones

Thank you for contributing! 🎉
