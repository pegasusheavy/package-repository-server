# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@pegasusheavy.com**

Include the following information in your report:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** of the vulnerability
4. **Suggested fix** (if you have one)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Assessment**: We will investigate and assess the vulnerability within 7 days
- **Resolution**: We aim to release a fix within 30 days for critical vulnerabilities
- **Disclosure**: We will coordinate with you on public disclosure timing

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized and not subject to legal action
- Conducted in good faith
- Helpful to improving our security

We will not pursue legal action against researchers who:

- Follow this responsible disclosure policy
- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Do not exploit vulnerabilities beyond what is necessary to demonstrate them

## Security Best Practices

When deploying Package Repository Server:

1. **Use strong API keys**: Generate random 32+ character keys
   ```bash
   openssl rand -hex 32
   ```

2. **Enable HTTPS**: Always use TLS in production
   ```bash
   docker exec package-repo setup-ssl letsencrypt
   ```

3. **Restrict network access**: Use firewalls/network policies to limit access

4. **Backup GPG keys**: The `/data/gpg` directory contains your signing keys

5. **Rotate API keys**: Periodically rotate API keys and revoke unused ones

6. **Monitor logs**: Watch for unusual activity in logs

7. **Keep updated**: Regularly update to the latest version

## Known Security Considerations

- **API keys** are transmitted in headers - always use HTTPS
- **GPG keys** are auto-generated - backup them for persistence
- **Package uploads** are validated but always review packages before distribution
- **S3 credentials** should use IAM roles when possible instead of access keys

## Security Updates

Security updates will be announced via:

- GitHub Security Advisories
- Release notes
- The project README (for critical issues)

Subscribe to repository notifications to stay informed about security updates.
