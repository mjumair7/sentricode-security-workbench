# Reporting a security issue

If you find a vulnerability in SentriCode itself, please use the repository's **Security → Advisories → Report a vulnerability** option when private vulnerability reporting is enabled. Repository owners should enable that option after publishing. If it is unavailable, open a minimal issue asking for a private reporting channel without posting an exploit, token, private source, or customer data.

Include the affected version/commit, setup, expected behavior, observed behavior, and a small sanitized reproduction. A finding produced by the scanner against another application is not automatically a vulnerability in SentriCode.

The initial `0.1.x` release is intended for personal, single-owner use. There is no paid support agreement or promised response SLA. Updates and fixes will be published through the repository. Keep dependencies and container base images reviewed and current.

Never attach live credentials or an entire private repository to a public issue. Rotate any credential that has been exposed. The [security model](docs/security.md) describes data handling and trust boundaries, and [coverage](docs/coverage.md) describes what the scanner can and cannot establish.
