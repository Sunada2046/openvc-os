import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";

const root = resolve(import.meta.dirname, "..");
const temp = mkdtempSync(join(tmpdir(), "openvc-clean-init-"));
const dbPath = join(temp, "openvc.sqlite");

try {
  const result = spawnSync("node", ["packages/db/scripts/init.mjs"], {
    cwd: root,
    env: { ...process.env, OPENVC_DB_PATH: dbPath },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(statSync(dbPath).mode & 0o777, 0o600, "database must be owner-readable only");
  assert.equal(statSync(temp).mode & 0o077, 0, "database directory must not be accessible to other users");

  const db = new DatabaseSync(dbPath, { readOnly: true });
  const tables = [
    "organizations",
    "accounts",
    "account_credentials",
    "roles",
    "account_roles",
    "sessions",
    "objects",
    "relations",
    "field_definitions",
    "connectors",
    "connector_secrets",
    "documents",
    "audit_logs",
  ];
  for (const table of tables) {
    const count = Number(db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count);
    assert.equal(count, 0, `${table} must be empty after initialization`);
  }
  db.close();
  console.log("Clean initialization passed: schema only, zero records.");
} finally {
  rmSync(temp, { recursive: true, force: true });
}
