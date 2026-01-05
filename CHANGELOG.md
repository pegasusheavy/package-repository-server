# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-05

### Added

#### SSO Authentication System
- OAuth 2.0 / OpenID Connect authentication support
- Support for 9 SSO providers:
  - Google (Google Workspace / Gmail)
  - GitHub
  - GitLab (SaaS and self-hosted)
  - Microsoft / Azure AD
  - Okta
  - Auth0
  - Keycloak
  - Generic OIDC (any compliant provider)
- JWT-based session management with configurable expiration
- Stateless backend architecture (no session storage required)
- AES-256-GCM encryption for OAuth state management
- PKCE support for enhanced OAuth 2.0 security
- CSRF protection with encrypted state parameters
- Domain and email-based access restrictions
- Auto-registration configuration per provider

#### Backend (Rust)
- Complete SSO implementation in Rust:
  - `sso_config.rs` - Provider configuration and environment loading
  - `sso_session.rs` - JWT token management and user profiles
  - `sso_handlers.rs` - OAuth2/OIDC flow implementation
  - `sso_state.rs` - Stateless state management with encryption
- Comprehensive security module (`security.rs`):
  - Input validation and sanitization
  - Malware pattern detection
  - Path traversal prevention
  - API key validation
  - Entropy analysis
  - Archive scanning
- Multi-format package registry handlers:
  - Cargo (Rust packages)
  - npm (JavaScript/TypeScript packages)
  - PyPI (Python packages)
  - Maven (Java packages)
  - NuGet (.NET packages)
  - Docker/OCI (container images)
- Enhanced middleware:
  - Security headers on all responses
  - Request ID tracking for audit logs
  - Client fingerprinting
- API key authentication alongside SSO
- Dual authentication mode support

#### Frontend (Angular 21)
- Modern authentication UI with Angular 21:
  - `auth.service.ts` - Authentication state management with signals
  - `auth.guard.ts` - Route protection
  - `auth.interceptor.ts` - Automatic JWT token injection
- Login component with SSO provider selection:
  - Beautiful, modern UI with Tailwind CSS
  - Provider-specific branding and colors
  - Dark mode support
  - Loading and error states
- OAuth callback handler component
- Dashboard with package statistics
- Package management interface
- Upload component for packages
- Settings page
- Responsive design with mobile support

#### Documentation
- `docs/SSO_CONFIGURATION.md` - Complete SSO setup guide
- `docs/SSO_IMPLEMENTATION_SUMMARY.md` - Implementation overview
- `docs/STATELESS_DESIGN.md` - Stateless architecture documentation
- Comprehensive Cursor rules for development:
  - `general.mdc` - Core project guidelines
  - `rust.mdc` - Rust backend development
  - `angular.mdc` - Angular frontend development
  - `infrastructure.mdc` - Docker, Kubernetes, Terraform
  - `security.mdc` - Security best practices
  - `package-processing.mdc` - Package handling guidelines
  - `authentication.mdc` - SSO development guidelines
- Configuration examples:
  - `.env.example` - Environment variable template
  - `config/sso.env.example` - SSO configuration template
- Updated README with SSO features

#### Infrastructure
- Docker Compose configurations
- Kubernetes manifests
- Helm charts for Kubernetes deployment
- Terraform modules for cloud providers:
  - AWS (EKS)
  - GCP (GKE)
  - Azure (AKS)
  - DigitalOcean (DOKS)
  - Vultr (VKE)
- CI/CD integration examples:
  - GitHub Actions
  - GitLab CI
  - Bitbucket Pipelines
  - Jenkins
  - Azure DevOps
  - Drone CI
- End-to-end testing framework
- Benchmarking suite

#### Package Management
- Multi-format package support:
  - DEB (Debian/Ubuntu) - APT repositories
  - RPM (RHEL/Fedora/Rocky) - YUM/DNF repositories
  - Arch Linux - Pacman repositories
  - Alpine Linux - APK repositories
- Multi-architecture support (x86_64/ARM64)
- Automatic package indexing on upload
- GPG signing for all repository metadata
- Package validation and security scanning
- S3-compatible storage backend support

### Security
- Constant-time cryptographic operations
- Authenticated encryption (AES-256-GCM)
- Comprehensive input validation
- Path traversal prevention
- Malware pattern detection
- API key hashing and secure storage
- HTTPS enforcement in production
- Secure cookie handling
- Token expiration and validation
- Audit logging for security events

### Performance
- Stateless design enables horizontal scaling
- Sub-millisecond authentication checks
- No database lookups for token validation
- Efficient package processing
- Streaming support for large files
- LTO and optimization in release builds

### Developer Experience
- Comprehensive documentation
- Example configurations for all scenarios
- Clear error messages
- Extensive code comments
- Type-safe implementations
- Automated testing
- Development guidelines

### Infrastructure
- No external dependencies for authentication
- No session storage required (Redis, Memcached, etc.)
- Cloud-native design
- Serverless-compatible
- Container-ready
- Kubernetes-native

## [Unreleased]

### Planned Features
- User management UI
- Token refresh mechanism
- Redis-based session storage (optional)
- TOTP-based 2FA
- Rate limiting
- Enhanced audit logging
- Package vulnerability scanning
- Repository mirroring
- Package promotion workflows

---

## Release Notes

### v0.1.0 - Initial Release

This is the first official release of the Package Repository Server. The project provides a complete, self-hosted package repository solution with enterprise-grade SSO authentication.

**Key Highlights:**
- **Stateless Architecture**: No session storage required, scales horizontally
- **9 SSO Providers**: Google, GitHub, GitLab, Microsoft, Okta, Auth0, Keycloak, Generic OIDC
- **Security First**: AES-256-GCM encryption, PKCE, CSRF protection
- **Cloud Native**: Perfect for Kubernetes, serverless, and containers
- **Production Ready**: Comprehensive documentation and deployment examples

**Getting Started:**
1. See [README.md](README.md) for quick start
2. Configure SSO providers using [docs/SSO_CONFIGURATION.md](docs/SSO_CONFIGURATION.md)
3. Review architecture in [docs/STATELESS_DESIGN.md](docs/STATELESS_DESIGN.md)
4. Deploy using Docker Compose, Kubernetes, or Terraform

**Upgrading:**
This is the initial release, no upgrade path needed.

**Breaking Changes:**
None - this is the first release.

---

**Full Changelog**: https://github.com/pegasusheavy/package-repository-server/commits/v0.1.0

[0.1.0]: https://github.com/pegasusheavy/package-repository-server/releases/tag/v0.1.0
