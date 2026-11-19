# Security Policy

## Reporting a vulnerability

Report security issues privately through
[GitHub Security Advisories](https://github.com/heliopsy/scrim/security/advisories/new).

Please do not open a public issue for a vulnerability, and never include a real secret value in a
report. Use placeholders.

Include what you can: affected version or commit, a description of the issue, reproduction steps,
and the impact you believe it has. You will get an acknowledgement within a few days and an
assessment once the report has been reviewed.

## Supported versions

Until v1.0.0, only the latest release receives security fixes.

## Scope

scrim sits between AI agents and model providers, holds credentials to secret stores, and injects
credentials into outbound traffic. Findings of particular interest:

- **A known secret value reaching a model provider**, in any encoding, through any field, any
  provider API or any streaming path. This is the highest-severity class in this project.
- A request forwarded after redaction failed, instead of being refused.
- A credential injected toward a host it is not bound to, or restored into a command or tool the
  policy does not allow.
- Any path that returns a secret value to an agent: an MCP tool, the CLI, the admin API, an error
  message, a log line, a metric, a trace or the audit log.
- Bypassing an approval or using an expired or revoked just-in-time grant.
- Agent identity spoofing: one agent acting with another agent's grants.
- Injection through a restored value: a value that becomes shell, SQL or interpreter code.
- Disclosure of scrim's own credentials to the secret stores, its placeholder key, or its CA key.
