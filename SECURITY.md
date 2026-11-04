# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository
(GitHub private vulnerability reporting).

Please include the affected version or commit, steps to reproduce and the
impact you observed. You can expect an initial response within 7 days.

## Scope

In scope:

- Bugs that make `pqc-scan` leak secret material (for example private key
  contents) into reports, logs or error messages.
- Bugs that make `pqc-scan` behave non-passively (authenticate, send exploit
  payloads, or connect to hosts it was not asked to scan).
- Vulnerabilities in parsing untrusted input (certificates, keys, network
  responses, source files).

Out of scope: findings about third-party systems discovered *with* `pqc-scan`.
Report those to the system owner.

## Responsible use

`pqc-scan` must only be used against systems you own or have written permission
to test.
