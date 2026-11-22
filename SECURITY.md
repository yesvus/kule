# Security Policy

Kule provides privileged operations on configured hosts. Security reports are welcome and taken seriously.

## Reporting vulnerabilities

Please use [GitHub Security Advisories](https://github.com/yesvus/kule/security/advisories/new) to disclose a vulnerability privately. Include the affected revision, reproduction steps, impact and any suggested mitigation. Avoid posting exploits, access tokens, private keys or sensitive host details in public issues.

We review reports and coordinate fixes and disclosure through the advisory.

## Supported versions

Kule is in early development. There are no stable releases or long-term support guarantees yet. Please test against the latest maintained revision when reporting a problem.

## Deployment guidance

- Run with a dedicated, least-privileged identity.
- Use TLS for the public MCP endpoint, and authenticate through a trusted OIDC provider.
- Keep execution disabled until host-specific policy, identity and audit storage are configured.
- Store secrets outside Git and avoid exposing raw command output to untrusted clients.
- Keep independent access to the managed host for recovery.
