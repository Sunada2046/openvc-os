# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or data exposure.
Use the repository's private vulnerability reporting feature. If that feature
is unavailable, contact the maintainers through the private security address
published in the repository profile.

Include:

- affected version and deployment mode;
- reproduction steps with synthetic data only;
- expected and observed behavior;
- potential confidentiality, integrity, or availability impact;
- suggested remediation when available.

Never include production credentials, investment records, personal data,
documents, database files, or unredacted logs.

## Response targets

- Acknowledgement: within 3 business days
- Initial severity assessment: within 7 business days
- Critical vulnerability remediation target: 14 days
- Coordinated disclosure: after a fix is available

These are targets, not a service-level agreement.

## Supported versions

Security fixes are provided for the most recent tagged release. Operators should
keep Node.js and locked dependencies current.

## Supply-chain controls

- Dependencies are locked with `package-lock.json`.
- CI uses `npm ci`, fails on moderate-or-higher dependency advisories, and
  verifies available registry signatures and provenance attestations.
- GitHub Actions are pinned to immutable commit SHAs.
- Code scanning runs on pushes, pull requests, and a weekly schedule.
- Dependabot security updates and private vulnerability reporting are enabled.
- `npm run package:release` produces source and SBOM SHA-256 checksums.

## Security boundaries

OpenVC OS is local-first, but local-first does not mean automatically secure.
The operator remains responsible for:

- full-disk encryption and operating-system account security;
- TLS and a trusted reverse proxy when enabling network access;
- encrypted, access-controlled backups;
- credential rotation and connector review;
- applying updates and reviewing audit events;
- legal and regulatory obligations for stored personal and financial data.

The core never promises that an arbitrary third-party connector is safe. Review
adapter source, requested capabilities, destinations, and data access before
installation.
