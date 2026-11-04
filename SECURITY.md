# Security policy

## Supported versions

The `main` branch and the latest tagged release receive security fixes.

## Reporting a vulnerability

Please email **security@tigertrust.io** with a description of the issue, steps
to reproduce, and any proof-of-concept. We acknowledge reports within 3
business days and aim to ship fixes within 30 days for critical findings.

Do **not** file public GitHub issues for vulnerabilities.

## Scope

`caa-lint` performs outbound DNS queries only. It does not transmit any data
to third parties and does not open listening sockets. Any deviation is
in-scope.
