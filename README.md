# OpenVC OS

OpenVC OS is a privacy-first, local-first operating system for venture capital
teams. It provides the application architecture and data model while leaving
business data, field catalogs, accounts, APIs, MCP servers, models, and other
connectors entirely under the operator's control.

## Privacy defaults

- The database starts with zero records.
- There is no default account or password.
- First-time setup is accepted only from the local device.
- The API binds to `127.0.0.1` unless the operator explicitly changes it.
- The connector registry starts empty and disabled.
- The core does not make outbound network calls.
- Runtime data, uploads, credentials, backups, and releases are excluded from Git.
- SQLite files and uploaded assets are created with owner-only permissions.

## Modules

- Fund and limited-partner management
- Deal pipeline and investment committee records
- Portfolio, risk, task, and exit management
- People and responsibility records
- User-defined fields and classifications
- Empty, provider-neutral connector registry
- Role-based access control and local audit history

The application uses one generic object model plus explicit relationships and
field definitions. This keeps the core neutral while allowing each institution
to build its own data structure.

## Requirements

- Node.js 22 or newer
- npm 11 or newer

## Local start

```bash
npm install
npm run db:init
npm run dev:api
```

In a second terminal:

```bash
npm run dev
```

Open `http://127.0.0.1:5173`. The first screen creates the organization and
administrator locally. No external service is contacted.

## Verification

```bash
npm test
npm audit
npm run package:release
```

`npm test` proves that a fresh database is empty, checks the authentication and
CSRF boundary, verifies that the connector registry is empty, scans source files
for credentials and private paths, tests an authenticated encrypted-backup
round trip, rejects a modified backup, and builds the web application.

## Encrypted backups

Stop the API before backup or restore. Keep the passphrase in a password manager,
not in `.env.local`, shell history, the repository, or beside the backup file.

```bash
OPENVC_BACKUP_PASSPHRASE='use-a-long-unique-passphrase' npm run backup:encrypted
```

To restore:

```bash
OPENVC_BACKUP_PASSPHRASE='use-a-long-unique-passphrase' \
  npm run restore:encrypted -- \
  --file=/absolute/path/to/openvc-backup.ovcbak \
  --confirm-replace-storage
```

Backups use authenticated AES-256-GCM encryption with a scrypt-derived key. A
restore preserves the previous storage directory for deliberate cleanup after
verification.

## Connectors

Connectors are not bundled with the core. An administrator may register a
provider-neutral manifest and store encrypted secret values, but the core does
not execute that connector. Network execution belongs in separately reviewed
adapter packages. See [Connector SDK](docs/connector-sdk.md).

## Data templates

The repository intentionally contains no organization-specific field template.
Create fields in the Data Structure module or maintain a separate, private
template package. Templates should never contain record values, credentials,
external record identifiers, or personal data.

## Security

Read [SECURITY.md](SECURITY.md), the [threat model](docs/threat-model.md), and
the [deployment guide](docs/private-deployment.md) before exposing the service
beyond a single device.

## License

Apache License 2.0. See [LICENSE](LICENSE).
