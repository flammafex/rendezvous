# Security Policy

## Security Status

Matchlock is pre-audit software. The repository includes unit tests, integration tests, and protocol known-answer vectors, but the protocol and implementation have not yet received an independent cryptographic security review.

Before high-stakes production use, review at least:

- protocol privacy assumptions and metadata leakage;
- PSI owner-held key lifecycle and compromise behavior;
- X25519 key validation and private-key storage requirements;
- replay/nullifier behavior in the consuming application;
- browser, Node.js, and server deployment threat models.

## Reporting a Vulnerability

Please report vulnerabilities privately to the maintainers before opening a public issue. Include:

- affected package or crate version;
- a minimal reproduction or proof of concept, if possible;
- expected and observed behavior;
- impact assessment and any suggested fix.

The maintainers should acknowledge reports promptly and coordinate disclosure once a fix is available.
