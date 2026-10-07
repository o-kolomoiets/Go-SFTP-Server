# Security Policy

## Supported versions

gosftpd has no stable release yet. While the project is in 0.x, only the
latest minor release receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue. Report vulnerabilities privately through
GitHub: [Security → Report a vulnerability](https://github.com/o-kolomoiets/go-sftp-server/security/advisories/new).

What to expect (best effort, single maintainer):

- acknowledgement within 72 hours;
- a fix and coordinated disclosure within 90 days;
- a GitHub Security Advisory and, where applicable, a CVE.

## Scope

Especially interesting: escaping a mount (path traversal, symlinks, races),
authentication or authorization bypass, information disclosure such as host
paths, and denial of service that a single client can trigger.
