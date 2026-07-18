# Privacy and Data Lifecycle

OpenVC OS is software operated by the deploying organization. The project does
not receive workspace data, telemetry, credentials, documents, or usage events.
The operator remains responsible for determining its role under applicable
privacy, employment, financial, and data-protection law.

## Data categories

Typical deployments may contain:

- employee, founder, adviser, and investor identity and contact data;
- fund commitments, payments, valuations, distributions, and bank evidence;
- investment committee opinions, votes, conflicts, and risk conclusions;
- legal agreements, diligence evidence, board materials, and correspondence;
- account identifiers, sessions, security events, and connector metadata.

Field definitions classify values as `public`, `internal`, `restricted`, or
`confidential`. The API enforces those classifications before returning field
definitions or object values. Unknown custom keys default to `internal`.
Operators should classify fields before importing real data and grant
`field.manage` only to trusted administrators.

## Collection and minimization

The repository initializes with no accounts, business records, connectors, or
institution-specific field catalog. Collect only fields required for a defined
investment, legal, operational, or compliance purpose. Do not use free-text
fields as an ungoverned store for identity documents, bank details, health data,
or unrelated personal information.

## Retention and deletion

The core does not impose a universal retention schedule. Operators should define
retention by record type, legal basis, fund term, limitation period, and
regulatory obligation. Object deletion is soft deletion; encrypted backups and
audit events can retain references after an object disappears from the active
interface. A production deployment needs an approved process for:

- legal holds and deletion exceptions;
- irreversible purge of records and associated documents;
- expiration of sessions and disabled accounts;
- backup rotation and destruction;
- responding to access, correction, export, restriction, and erasure requests.

Audit records are append-only and deliberately block deletion of referenced
accounts or organizations. A privacy deletion workflow must preserve required
security evidence through a reviewed pseudonymization or retention process; it
must not silently detach or rewrite audit history.

## Files and backups

Uploads are owner-readable only and remain below the configured storage root.
They are not scanned for malware because the core does not execute or serve
them. Add content scanning before allowing downloads or sharing in a networked
deployment.

Encrypted backups include the database, uploads, and the local connector-vault
key. They therefore contain the same sensitive data as the live workspace.
Store the passphrase separately, restrict access, test restoration, and destroy
expired copies. Restore rejects modified archives, unsafe paths, and links.

## Connectors and international transfers

The core performs no outbound connector execution. Installing an adapter changes
the privacy boundary. Before activation, document its destination, controller or
processor role, data classifications, retention, subprocessors, transfer
mechanism, approval workflow, incident process, and credential-rotation plan.

## Logging and support

Do not send production databases, backups, documents, credentials, or unredacted
logs in public issues. Runtime errors intentionally omit payloads, secrets, stack
traces, and local filesystem paths from HTTP responses. Centralized logging
should preserve that minimization.
