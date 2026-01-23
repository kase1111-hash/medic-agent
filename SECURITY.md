# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Medic Agent, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email security concerns to the project maintainers via GitHub's private vulnerability reporting feature
3. Include as much information as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Assessment**: We will assess the vulnerability and determine its severity within 7 days
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days
- **Credit**: We will credit reporters in our security advisories (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

- Authentication and authorization bypasses
- Injection vulnerabilities (SQL, command, etc.)
- Cross-site scripting (XSS)
- Sensitive data exposure
- Denial of service vulnerabilities
- Cryptographic weaknesses
- Configuration issues that could lead to security breaches

### Out of Scope

- Vulnerabilities in dependencies (report to the upstream project)
- Social engineering attacks
- Physical attacks
- Attacks requiring physical access to infrastructure

## Security Best Practices

When deploying Medic Agent, follow these security guidelines:

### API Keys

- Generate strong API keys using cryptographically secure methods:
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```
- Never commit API keys to version control
- Rotate API keys regularly
- Use a secrets manager in production (Vault, AWS Secrets Manager, etc.)

### Environment Configuration

- Set `MEDIC_ENV=production` for production deployments
- Configure CORS origins explicitly (HTTPS only in production)
- Enable rate limiting
- Use TLS/HTTPS for all external communications

### Network Security

- Deploy behind a reverse proxy (nginx, traefik, etc.)
- Use Kubernetes NetworkPolicies to restrict traffic
- Limit Redis access to internal networks only
- Enable authentication for all external services

### Secrets Management

- Use Kubernetes external-secrets operator for production
- Never store secrets in configuration files
- Audit secret access regularly

### Monitoring

- Enable Prometheus metrics export
- Set up alerts for suspicious activity:
  - Unusual API request patterns
  - Authentication failures
  - Rate limit violations
  - Error rate spikes

## Security Features

Medic Agent includes the following security features:

- **API Key Authentication**: SHA-256 hashed key comparison with constant-time validation
- **Role-Based Access Control**: Admin, Operator, Viewer, and API roles
- **Rate Limiting**: Configurable request limits (default: 120 req/min)
- **Request Size Limiting**: Maximum request body size (default: 10MB)
- **Security Headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Input Validation**: Strict validation of all API inputs
- **Audit Logging**: Structured logs with trace correlation

## Security Audit Reports

For detailed security audit information, see:

- [Security Audit Report](SECURITY_AUDIT_REPORT.md) - Complete security assessment
- [Security Status](SECURITY_STATUS.md) - Current security posture
- [Security Fixes](SECURITY_FIXES.md) - Applied security patches

## Disclosure Policy

We follow responsible disclosure principles:

1. Security issues are addressed before public disclosure
2. Security advisories are published after fixes are released
3. CVEs are requested for significant vulnerabilities
4. Credit is given to reporters who follow responsible disclosure

## Contact

For security-related inquiries, use GitHub's private vulnerability reporting feature on this repository.
