# SSO Authentication Configuration Guide

This document describes how to configure Single Sign-On (SSO) authentication for the Package Repository Server.

## Table of Contents

- [Overview](#overview)
- [Supported Providers](#supported-providers)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Provider-Specific Setup](#provider-specific-setup)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

The Package Repository Server supports OAuth 2.0 / OpenID Connect (OIDC) authentication with multiple identity providers. This allows your organization to:

- Use existing identity management systems
- Enable single sign-on across services
- Enforce multi-factor authentication (if supported by your provider)
- Control access through domain/email restrictions
- Maintain API key authentication for service accounts

## Supported Providers

The following SSO providers are supported out of the box:

- **Google** - Google Workspace / Gmail accounts
- **GitHub** - GitHub user accounts
- **GitLab** - GitLab.com or self-hosted GitLab
- **Microsoft** / **Azure AD** - Microsoft 365 / Azure Active Directory
- **Okta** - Okta identity platform
- **Auth0** - Auth0 identity platform
- **Keycloak** - Self-hosted Keycloak
- **Generic OIDC** - Any OpenID Connect compliant provider

## Configuration

### Global SSO Settings

Set these environment variables to enable SSO:

```bash
# Enable SSO globally
SSO_ENABLED=true

# JWT secret for session token signing (generate a secure random string)
SSO_JWT_SECRET=$(openssl rand -hex 32)

# Base URL of your application
SSO_BASE_URL=https://packages.example.com

# JWT token expiration in seconds (default: 86400 = 24 hours)
SSO_JWT_EXPIRATION_SECONDS=86400

# Allow API key authentication alongside SSO (default: true)
SSO_ALLOW_API_KEY_AUTH=true

# Require SSO (disables API key auth except for configured keys)
SSO_REQUIRE=false

# Cookie settings
SSO_COOKIE_SECURE=true        # Use secure cookies (HTTPS only)
SSO_COOKIE_DOMAIN=example.com # Cookie domain (optional)
```

### Provider-Specific Setup

Each provider requires its own configuration. Enable a provider by setting `SSO_<PROVIDER>_ENABLED=true` and providing client credentials.

#### Google

1. Create OAuth credentials in [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Add authorized redirect URI: `https://your-domain.com/auth/callback/google`
3. Configure environment variables:

```bash
SSO_GOOGLE_ENABLED=true
SSO_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
SSO_GOOGLE_CLIENT_SECRET=your-google-client-secret
SSO_GOOGLE_ALLOWED_DOMAINS=example.com,company.com  # Optional: restrict to specific domains
```

#### GitHub

1. Create OAuth App in [GitHub Developer Settings](https://github.com/settings/developers)
2. Set Authorization callback URL: `https://your-domain.com/auth/callback/github`
3. Configure environment variables:

```bash
SSO_GITHUB_ENABLED=true
SSO_GITHUB_CLIENT_ID=your-github-client-id
SSO_GITHUB_CLIENT_SECRET=your-github-client-secret
SSO_GITHUB_ALLOWED_EMAILS=user@example.com,*@company.com  # Optional: restrict access
```

#### GitLab

1. Create application in [GitLab Applications](https://gitlab.com/-/profile/applications)
2. Set Redirect URI: `https://your-domain.com/auth/callback/gitlab`
3. Enable scopes: `read_user`, `email`
4. Configure environment variables:

```bash
SSO_GITLAB_ENABLED=true
SSO_GITLAB_CLIENT_ID=your-gitlab-client-id
SSO_GITLAB_CLIENT_SECRET=your-gitlab-client-secret
# For self-hosted GitLab:
SSO_GITLAB_AUTH_URL=https://gitlab.your-company.com/oauth/authorize
SSO_GITLAB_TOKEN_URL=https://gitlab.your-company.com/oauth/token
SSO_GITLAB_USERINFO_URL=https://gitlab.your-company.com/api/v4/user
```

#### Microsoft / Azure AD

1. Register application in [Azure Portal](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Add redirect URI: `https://your-domain.com/auth/callback/microsoft`
3. Create client secret
4. Configure environment variables:

```bash
SSO_MICROSOFT_ENABLED=true
SSO_MICROSOFT_CLIENT_ID=your-azure-client-id
SSO_MICROSOFT_CLIENT_SECRET=your-azure-client-secret
SSO_MICROSOFT_ALLOWED_DOMAINS=company.com  # Optional
```

#### Okta

1. Create application in Okta Admin Console
2. Set Sign-in redirect URI: `https://your-domain.com/auth/callback/okta`
3. Configure environment variables:

```bash
SSO_OKTA_ENABLED=true
SSO_OKTA_CLIENT_ID=your-okta-client-id
SSO_OKTA_CLIENT_SECRET=your-okta-client-secret
SSO_OKTA_AUTH_URL=https://your-domain.okta.com/oauth2/v1/authorize
SSO_OKTA_TOKEN_URL=https://your-domain.okta.com/oauth2/v1/token
SSO_OKTA_USERINFO_URL=https://your-domain.okta.com/oauth2/v1/userinfo
SSO_OKTA_DISCOVERY_URL=https://your-domain.okta.com/.well-known/openid-configuration
```

#### Auth0

1. Create application in [Auth0 Dashboard](https://manage.auth0.com/)
2. Add callback URL: `https://your-domain.com/auth/callback/auth0`
3. Configure environment variables:

```bash
SSO_AUTH0_ENABLED=true
SSO_AUTH0_CLIENT_ID=your-auth0-client-id
SSO_AUTH0_CLIENT_SECRET=your-auth0-client-secret
SSO_AUTH0_AUTH_URL=https://your-domain.auth0.com/authorize
SSO_AUTH0_TOKEN_URL=https://your-domain.auth0.com/oauth/token
SSO_AUTH0_USERINFO_URL=https://your-domain.auth0.com/userinfo
```

#### Keycloak

1. Create client in Keycloak Admin Console
2. Set valid redirect URI: `https://your-domain.com/auth/callback/keycloak`
3. Configure environment variables:

```bash
SSO_KEYCLOAK_ENABLED=true
SSO_KEYCLOAK_CLIENT_ID=package-repo
SSO_KEYCLOAK_CLIENT_SECRET=your-keycloak-client-secret
SSO_KEYCLOAK_AUTH_URL=https://keycloak.example.com/realms/master/protocol/openid-connect/auth
SSO_KEYCLOAK_TOKEN_URL=https://keycloak.example.com/realms/master/protocol/openid-connect/token
SSO_KEYCLOAK_USERINFO_URL=https://keycloak.example.com/realms/master/protocol/openid-connect/userinfo
SSO_KEYCLOAK_DISCOVERY_URL=https://keycloak.example.com/realms/master/.well-known/openid-configuration
```

#### Generic OIDC

For any OpenID Connect compliant provider:

```bash
SSO_OIDC_ENABLED=true
SSO_OIDC_NAME="My Custom Provider"
SSO_OIDC_CLIENT_ID=your-client-id
SSO_OIDC_CLIENT_SECRET=your-client-secret
SSO_OIDC_DISCOVERY_URL=https://provider.example.com/.well-known/openid-configuration
# Or specify endpoints manually:
SSO_OIDC_AUTH_URL=https://provider.example.com/oauth2/authorize
SSO_OIDC_TOKEN_URL=https://provider.example.com/oauth2/token
SSO_OIDC_USERINFO_URL=https://provider.example.com/oauth2/userinfo
SSO_OIDC_SCOPES=openid,profile,email
```

### Access Control

Restrict access to specific domains or email addresses:

```bash
# Allow only users from specific domains
SSO_GOOGLE_ALLOWED_DOMAINS=company.com,subsidiary.com

# Allow specific emails or patterns
SSO_GITHUB_ALLOWED_EMAILS=admin@company.com,*@company.com

# Auto-register new users (default: true)
SSO_GOOGLE_AUTO_REGISTER=true
```

## Docker Compose Example

```yaml
version: '3.8'
services:
  package-repo:
    image: package-repo-server:latest
    environment:
      # SSO Configuration
      - SSO_ENABLED=true
      - SSO_JWT_SECRET=${SSO_JWT_SECRET}
      - SSO_BASE_URL=https://packages.example.com
      - SSO_ALLOW_API_KEY_AUTH=true

      # Google SSO
      - SSO_GOOGLE_ENABLED=true
      - SSO_GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - SSO_GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
      - SSO_GOOGLE_ALLOWED_DOMAINS=example.com

      # GitHub SSO
      - SSO_GITHUB_ENABLED=true
      - SSO_GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - SSO_GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}

      # API Keys (for service accounts)
      - API_KEYS=${API_KEY1},${API_KEY2}
    ports:
      - "8080:8080"
```

## Kubernetes Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sso-secrets
type: Opaque
stringData:
  jwt-secret: "your-jwt-secret-here"
  google-client-secret: "your-google-secret"
  github-client-secret: "your-github-secret"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: sso-config
data:
  SSO_ENABLED: "true"
  SSO_BASE_URL: "https://packages.example.com"
  SSO_GOOGLE_ENABLED: "true"
  SSO_GOOGLE_CLIENT_ID: "your-client-id.apps.googleusercontent.com"
  SSO_GITHUB_ENABLED: "true"
  SSO_GITHUB_CLIENT_ID: "your-github-client-id"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: package-repo
spec:
  template:
    spec:
      containers:
      - name: package-repo
        envFrom:
        - configMapRef:
            name: sso-config
        env:
        - name: SSO_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: sso-secrets
              key: jwt-secret
        - name: SSO_GOOGLE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: sso-secrets
              key: google-client-secret
```

## Security Considerations

### JWT Secret

- Generate a strong random secret: `openssl rand -hex 32`
- Store securely (environment variable, secrets manager)
- Rotate regularly (will invalidate existing sessions)

### HTTPS

- **Always use HTTPS in production** for SSO
- Set `SSO_COOKIE_SECURE=true` to enforce secure cookies
- Configure TLS termination at load balancer or reverse proxy

### Domain/Email Restrictions

- Use `ALLOWED_DOMAINS` to restrict access to your organization
- Use `ALLOWED_EMAILS` for fine-grained control
- Wildcard patterns supported: `*@example.com`

### API Keys

- Keep API keys enabled (`SSO_ALLOW_API_KEY_AUTH=true`) for:
  - CI/CD systems
  - Service accounts
  - Automation tools
- Use separate, long-lived API keys for services
- Rotate API keys regularly

## API Endpoints

The following endpoints are available for SSO authentication:

- `GET /auth/providers` - List available SSO providers
- `GET /auth/login/{provider}` - Initiate OAuth flow
- `GET /auth/callback/{provider}` - OAuth callback (automatic)
- `GET /auth/validate` - Validate current session
- `POST /auth/logout` - Logout (client-side token deletion)

## Testing

Test SSO configuration:

```bash
# Check available providers
curl https://packages.example.com/auth/providers

# Expected response:
{
  "providers": [
    {"id": "google", "name": "Google", "enabled": true},
    {"id": "github", "name": "GitHub", "enabled": true}
  ]
}

# Validate session (with token)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://packages.example.com/auth/validate
```

## Troubleshooting

### "SSO is not enabled" error

- Check `SSO_ENABLED=true` is set
- Verify environment variables are loaded correctly
- Check server logs for configuration errors

### "Provider not found" error

- Ensure `SSO_<PROVIDER>_ENABLED=true`
- Verify client ID and secret are set
- Check provider name matches supported providers

### OAuth redirect errors

- Verify redirect URI matches exactly in provider settings
- Check `SSO_BASE_URL` is correct
- Ensure HTTPS is configured if using `SSO_COOKIE_SECURE=true`

### "Invalid or expired token" error

- Token may have expired (default: 24 hours)
- JWT secret may have changed
- Check system clock sync

### Domain/email restrictions not working

- Verify `ALLOWED_DOMAINS` or `ALLOWED_EMAILS` syntax
- Check user's email domain matches
- Review server logs for authorization failures

## Support

For issues or questions:
- Check server logs: `docker logs package-repo` or `kubectl logs package-repo-xxx`
- Review [Security documentation](./SECURITY.md)
- Open an issue on GitHub
