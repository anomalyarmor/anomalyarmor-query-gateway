# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in this package, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email security@anomalyarmor.com with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact assessment
4. Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial Assessment**: Within 5 business days, we will provide an initial assessment
- **Resolution Timeline**: Critical vulnerabilities will be addressed within 30 days
- **Credit**: We will credit reporters in our release notes (unless you prefer to remain anonymous)

### Scope

This security policy applies to:

- The `anomalyarmor-query-gateway` Python package
- SQL parsing and validation logic
- Access level enforcement

### Out of Scope

- Vulnerabilities in dependencies (report to upstream maintainers)
- Issues in applications using this package (report to those maintainers)

## Security Design

This package is designed with security as a primary concern:

1. **Fail-Closed**: Any parsing or validation error results in query rejection
2. **No SQL Execution**: This package only validates queries; it never executes them
3. **Pure Python**: No native code or external processes
4. **Minimal Dependencies**: Only `sqlglot` for SQL parsing
