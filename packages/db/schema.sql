PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS account_credentials (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  password_changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  permissions_json TEXT NOT NULL DEFAULT '[]',
  UNIQUE (organization_id, code)
);

CREATE TABLE IF NOT EXISTS account_roles (
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (account_id, role_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS objects (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  object_type TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  data_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL REFERENCES accounts(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_objects_org_type
  ON objects (organization_id, object_type, deleted_at, updated_at);

CREATE TABLE IF NOT EXISTS relations (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  relation_type TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES accounts(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (source_id, target_id, relation_type)
);

CREATE TABLE IF NOT EXISTS field_definitions (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  object_type TEXT NOT NULL,
  field_key TEXT NOT NULL,
  label TEXT NOT NULL,
  data_type TEXT NOT NULL CHECK (
    data_type IN (
      'text', 'long_text', 'number', 'currency', 'percent', 'date',
      'datetime', 'boolean', 'single_select', 'multi_select',
      'relation', 'attachment', 'url', 'email', 'formula'
    )
  ),
  classification TEXT NOT NULL DEFAULT 'internal'
    CHECK (classification IN ('public', 'internal', 'restricted', 'confidential')),
  required INTEGER NOT NULL DEFAULT 0,
  options_json TEXT NOT NULL DEFAULT '[]',
  formula_expression TEXT,
  relation_target_type TEXT,
  position INTEGER NOT NULL DEFAULT 100,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, object_type, field_key)
);

CREATE TABLE IF NOT EXISTS connectors (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  connector_type TEXT NOT NULL CHECK (
    connector_type IN ('api', 'mcp', 'data_source', 'identity', 'storage', 'model', 'custom')
  ),
  status TEXT NOT NULL DEFAULT 'disabled'
    CHECK (status IN ('disabled', 'enabled')),
  manifest_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL REFERENCES accounts(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS connector_secrets (
  id TEXT PRIMARY KEY,
  connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
  secret_name TEXT NOT NULL,
  encrypted_value TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (connector_id, secret_name)
);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  object_id TEXT REFERENCES objects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  media_type TEXT NOT NULL,
  byte_size INTEGER NOT NULL,
  storage_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  uploaded_by TEXT NOT NULL REFERENCES accounts(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  organization_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
  actor_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  result TEXT NOT NULL DEFAULT 'success',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_org_time
  ON audit_logs (organization_id, created_at DESC);
