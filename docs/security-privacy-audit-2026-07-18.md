# Security and Privacy Audit

Date: 2026-07-18  
Scope: OpenVC OS source, reachable Git history, runtime defaults, API, database,
uploads, connector registry, encrypted backup and restore, release packaging,
dependencies, CI, and GitHub repository security settings.

## Executive conclusion

The patched codebase is suitable for local, single-device evaluation with
synthetic or appropriately governed data. It initializes empty, binds to
loopback, has no outbound connector executor, stores no preset credential, and
now fails closed when a network binding lacks secure-cookie and origin controls.

It is not yet approved for direct Internet exposure or high-assurance multi-user
production use. Before such deployment, the operator must add durable account
lifecycle controls, MFA or an equivalent external identity boundary, finer
record scopes, distributed rate limiting, encrypted storage, privacy purge
workflows, tamper-evident audit export, and protected release governance.

No production record, API credential, private key, local user path, or
organization-specific connector preset was found in the scanned source or
reachable Git history. Dependency advisory count was zero at audit time.

## Method

- Manual route-by-route review of authentication, authorization, CSRF,
  organization scoping, field classification, uploads, connector secrets, and
  audit access.
- Adversarial tests for cross-origin setup, DNS rebinding, credential stuffing,
  malformed cookies and JSON, oversized input, ID enumeration, cross-tenant
  access, confidential-field disclosure, attachment authorization, and
  connector credential smuggling.
- Database tests for cross-organization foreign-key relationships and
  append-only audit behavior.
- Authenticated backup round trip plus tampering, path traversal, symbolic-link,
  and unsupported-entry tests.
- Source and reachable-history scans for credentials, private keys, private
  paths, provider presets, and common token formats.
- Dependency advisory, registry-signature, provenance-attestation, SBOM, file
  permission, symlink, CI, CodeQL, Dependabot, and GitHub settings review.

## Remediated findings

| Severity | Finding | Resolution |
| --- | --- | --- |
| High | An empty local instance could be initialized by a cross-site request before its owner completed setup. | Origin checks, loopback validation, and a one-time setup token are now mandatory. |
| High | Confidential custom-field values were returned to a read-only account. | Field definitions and object values are filtered by classification; hidden values survive authorized partial updates without being disclosed. |
| High | Release packaging recursively included untracked files beneath allowed source directories. | Releases are now created from the exact tracked `HEAD` tree, record the source commit, and reject symbolic links. |
| High | An encrypted but malicious restore archive could contain link entries. | Restore now allowlists paths and entry types, rejects links and devices before extraction, rechecks the extracted tree, and normalizes permissions. |
| High | A user with document upload permission could attach a file to an object the user could not view. | Related-object uploads now inherit object visibility and return a uniform not-found response when unauthorized. |
| Medium | Audit rows could be updated or deleted, including silent removal of organization and actor references. | Recreated database triggers make every audit column append-only and reject deletion. |
| Medium | Connector credentials could be hidden under aliases such as `authorization` or inside ordinary string values. | Recursive key normalization and content-level private-key, authorization, token, and JWT detection reject credential material from manifests. |
| Medium | Login throttling could be weakened by rotating candidate email addresses. | Independent hashed IP and email counters, bounded state, session pruning, a session cap, and `Retry-After` are enforced. |
| Medium | A non-loopback bind could start with insecure cookies or no origin allowlist. | The API now refuses unsafe network configuration at startup. |
| Medium | Request parsing and upload handling had broad limits and inconsistent failure behavior. | Endpoint-specific limits, canonical Base64, media-type and control-character checks, generic errors, cleanup on database failure, and HTTP timeouts were added. |
| Medium | Backups copied a live SQLite file directly. | Backup uses SQLite's consistent online backup API; upload consistency still requires the documented maintenance window. |
| Low | GitHub private vulnerability reporting and Dependabot security updates were disabled. | Both repository settings were enabled during this audit. |

## Residual risks and required actions

### High priority before network production

1. Protect `main` with a ruleset or branch protection that requires pull
   requests, successful CI and CodeQL checks, resolved review conversations, and
   protection against force pushes and deletion. The repository currently has
   no branch protection or ruleset.
2. Add production account lifecycle APIs: invitation, activation, password
   change and recovery, session inventory and revocation, administrator
   disablement, last-super-administrator protection, and security-event review.
3. Require MFA or an equivalently strong external identity-provider policy for
   administrators and network deployments. Local single-device mode may remain
   password-only when the operator accepts that reduced assurance.
4. Extend organization-level RBAC to record and business scope: assigned fund,
   assigned project, team, explicit grant, creator, and field-specific
   view/edit/mask rules. The current core does not implement full ABAC.
5. Put network deployments behind TLS, a hardened reverse proxy, firewall,
   durable distributed login throttling, request quotas, and monitored
   application-level availability controls.

### Privacy and data lifecycle

1. SQLite, uploads, and the connector vault key are not application-level
   encrypted at rest. Use full-disk encryption now; use separately managed keys
   or an encrypted database for higher-assurance deployment.
2. Soft deletion is not erasure. Implement reviewed retention, legal hold,
   export, correction, irreversible purge, backup expiration, and data-subject
   request procedures before storing regulated personal data.
3. Audit triggers prevent normal mutation but do not defeat an administrator
   who can replace the database file or schema. Export signed append-only audit
   evidence where non-repudiation is required.
4. Uploads are not malware scanned. The current core neither executes nor serves
   them; scanning becomes mandatory before adding preview, download, sharing, or
   external processing.
5. Backup and restore currently buffer encrypted archives and do not enforce a
   total uncompressed-byte quota. Add streaming and expansion limits before
   operating with very large or externally supplied backups.

### Supply chain and repository governance

1. GitHub Actions currently permits all actions and does not enforce SHA pinning
   as a repository policy, although every checked-in workflow action is pinned
   to an immutable SHA. Restrict allowed actions and enforce SHA pinning after
   confirming the maintenance workflow.
2. Secret scanning and push protection are enabled. Non-provider pattern
   scanning and validity checks remain disabled and should be enabled when the
   repository plan supports them.
3. Release checksums provide integrity, not publisher identity. Add signed tags,
   signed provenance, and a release workflow bound to a protected environment
   before distributing production binaries.

## Verified controls

- Empty initialization: zero organizations, accounts, records, connectors, and
  documents.
- Authentication: Argon2 password hashes, generic login errors, bounded
  attempts, random hashed sessions, HttpOnly SameSite cookies, CSRF rotation,
  revocation, and expiry.
- Authorization: API-level permission checks, organization-filtered queries,
  database tenant triggers, uniform not-found behavior, and confidential-field
  filtering.
- Data boundary: no core outbound connector execution and no preset API, MCP,
  identity, model, storage, or data-source credential.
- Local storage: owner-only database, upload, secret-key, backup, and generated
  artifact permissions.
- Backup: AES-256-GCM authentication, scrypt key derivation, consistent SQLite
  snapshot, path and entry allowlists, tamper rejection, and rollback on failed
  restore.
- Supply chain: locked dependencies, zero known advisories, 177 packages with
  verified registry signatures, 61 packages with provenance attestations,
  immutable Action SHAs, CodeQL, Dependabot, and a CycloneDX SBOM.
- Repository history: seven reachable commits and 51 unique blobs scanned at
  audit time.

## Test evidence

The following completed successfully on the audit workstation:

```text
npm test
npm audit --json
npm audit signatures
git diff --check
```

`npm test` covered clean initialization, source and Git-history privacy scans,
unsafe network configuration, tenant isolation, API abuse cases, encrypted
backup attacks, release privacy, SBOM generation, TypeScript checking, and the
production web build.

GitHub CI on Node 22 and CodeQL both passed on pull request 2 after the
Node-version compatibility correction. CI fetches complete history so the
history privacy scan is not reduced to a shallow checkout. A passing check still
does not replace branch protection or human review.
