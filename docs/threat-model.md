# Threat Model

## Protected assets

- investment records and committee materials;
- investor, employee, founder, and contact information;
- financial values and legal documents;
- authentication credentials and sessions;
- connector credentials and outbound data;
- local uploads, backups, and audit history.

## Trust boundaries

1. Browser to local API
2. Authenticated account to organization-owned records
3. API process to SQLite and local files
4. Core application to optional adapter packages
5. Local device to any explicitly enabled network deployment

## Primary threats and controls

| Threat | Core control |
| --- | --- |
| Repository accidentally contains production data | Empty initialization, strict ignore rules, release allowlist, source scan |
| Credential committed to source | Secret-pattern scan, empty environment template, separate encrypted secret storage |
| Cross-site request forgery | Origin validation, HttpOnly SameSite cookie, and per-session CSRF token |
| Password compromise | Argon2id, minimum password policy, login throttling |
| Cross-organization access | Organization derived from authenticated session on every query |
| Unauthorized operation | API-level role permission checks with default denial |
| Silent external transmission | Empty connector registry and no outbound executor in the core |
| Local account reads files | Owner-only directories and files |
| Path traversal on upload | Basename normalization and server-generated storage names |
| Malicious backup archive | Authenticated encryption plus entry allowlist and link/device rejection |
| Audit log altered through the API | Append-only database triggers and API-level read-only access |
| Sensitive error disclosure | Generic server errors and no filesystem paths in health responses |

## Residual risks

- SQLite and uploads are not application-level encrypted at rest. Use full-disk
  encryption, a protected operating-system account, and encrypted backups.
- The local vault key is stored on the same device as encrypted connector
  secrets. It protects against accidental database disclosure, not complete
  device compromise.
- A separately installed adapter can transmit data according to its code and
  permissions. Review adapters independently.
- Enabling a non-loopback host changes the threat model and requires TLS, a
  hardened reverse proxy, firewall rules, monitoring, and operational review.
- Login throttling is process-local. A network deployment should add a durable,
  distributed rate limiter at the reverse proxy or identity-provider boundary.
- Audit immutability protects normal application access, not an attacker or
  administrator with direct write access to the SQLite file. High-assurance
  deployments should export signed, append-only audit evidence.
- Soft-deleted records and retained backups remain recoverable until an operator
  performs an approved purge. Define retention and deletion procedures before
  storing personal or regulated data.
