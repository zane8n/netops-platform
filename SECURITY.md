# Security Policy

## Supported Releases

Security fixes are provided for the latest stable release and the active beta.
Older releases should be upgraded before reporting a version-specific issue.

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability, exposed credential,
or unredacted support bundle. Use the repository's private security-advisory
workflow. Include the affected version, platform, reproduction steps, impact,
and any proposed mitigation. Do not include production secrets or raw customer
inventory.

Maintainers will acknowledge a complete report within five business days,
coordinate validation and disclosure, and credit reporters who request it.

## Security Boundaries

- NetOps is local-first and single-user in the 8.5 release line.
- The API and WebUI are experimental and must remain bound to loopback.
- Device changes are disabled unless the active profile and certified built-in
  driver both permit them.
- Plugins are trusted local code. Enable only reviewed packages from known
  sources.
- Support bundles are redacted by design, but operators must inspect an
  artifact before sharing it.
