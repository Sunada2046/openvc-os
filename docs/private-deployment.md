# Private Deployment

## Single-device deployment

The default configuration binds both web and API services to loopback. Keep:

```text
OPENVC_HOST=127.0.0.1
```

Use full-disk encryption, a dedicated operating-system account, automatic screen
lock, and encrypted backups stored separately from the device.

## Network deployment

Do not expose the development server directly. Place the API and built web
application behind a trusted reverse proxy with:

- TLS and secure cookies;
- a narrow origin allowlist;
- host firewall restrictions;
- operating-system service isolation;
- encrypted storage and backup policy;
- centralized monitoring without business payload logging;
- tested recovery and incident-response procedures.

The API refuses to bind a non-loopback address unless both
`OPENVC_COOKIE_SECURE=true` and a non-empty `OPENVC_ALLOWED_ORIGINS` allowlist
are configured. This check does not provide TLS by itself; terminate HTTPS at
the reverse proxy and forward only from that trusted proxy. Prefer keeping the
API on `127.0.0.1` even in a network deployment.

Network deployment should add database-level encryption or move to a managed
database with encrypted storage, key rotation, and point-in-time recovery.

## Backup policy

The open core never creates or uploads backups silently. It includes an explicit
local encrypted-backup command:

```bash
OPENVC_BACKUP_PASSPHRASE='use-a-long-unique-passphrase' npm run backup:encrypted
```

The archive contains the SQLite database, local uploads, and the local connector
secret-encryption key when present. It uses authenticated AES-256-GCM encryption
with a scrypt-derived key. The passphrase is not stored in the archive or
application database.

Stop the API before backup and restore. Restore only after verifying the source
of the file:

```bash
OPENVC_BACKUP_PASSPHRASE='use-a-long-unique-passphrase' \
  npm run restore:encrypted -- \
  --file=/absolute/path/to/openvc-backup.ovcbak \
  --confirm-replace-storage
```

The restore command rejects modified archives and unsafe archive paths. It
retains the previous storage directory rather than deleting it automatically.
A deployment should additionally define:

- who can initiate and restore backups;
- passphrases kept in a password manager or key-management service, separately
  from backup files;
- retention and secure deletion periods;
- restore testing cadence;
- audit evidence for backup and restore operations.
