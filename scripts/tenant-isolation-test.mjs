import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";

const root = resolve(import.meta.dirname, "..");
const temp = mkdtempSync(join(tmpdir(), "openvc-tenant-test-"));
const dbPath = join(temp, "openvc.sqlite");

try {
  const init = spawnSync("node", ["packages/db/scripts/init.mjs"], {
    cwd: root,
    env: { ...process.env, OPENVC_DB_PATH: dbPath },
    encoding: "utf8",
  });
  assert.equal(init.status, 0, init.stderr || init.stdout);

  const db = new DatabaseSync(dbPath);
  db.exec(`
    INSERT INTO organizations (id, name, slug) VALUES
      ('org_a', 'Organization A', 'organization-a'),
      ('org_b', 'Organization B', 'organization-b');
    INSERT INTO accounts (id, organization_id, email, name) VALUES
      ('account_a', 'org_a', 'a@example.test', 'Account A'),
      ('account_b', 'org_b', 'b@example.test', 'Account B');
    INSERT INTO roles (id, organization_id, code, name) VALUES
      ('role_a', 'org_a', 'role_a', 'Role A'),
      ('role_b', 'org_b', 'role_b', 'Role B');
    INSERT INTO objects (id, organization_id, object_type, name, created_by) VALUES
      ('object_a', 'org_a', 'deal', 'Object A', 'account_a'),
      ('object_b', 'org_b', 'deal', 'Object B', 'account_b');
  `);

  db.prepare("INSERT INTO account_roles (account_id, role_id) VALUES (?, ?)")
    .run("account_a", "role_a");
  assert.throws(
    () => db.prepare("INSERT INTO account_roles (account_id, role_id) VALUES (?, ?)")
      .run("account_a", "role_b"),
    /same organization/,
  );
  assert.throws(
    () => db.prepare(`
      INSERT INTO objects (id, organization_id, object_type, name, created_by)
      VALUES ('object_cross', 'org_a', 'deal', 'Cross', 'account_b')
    `).run(),
    /same organization/,
  );
  assert.throws(
    () => db.prepare(`
      INSERT INTO relations (
        id, organization_id, source_id, target_id, relation_type, created_by
      ) VALUES ('relation_cross', 'org_a', 'object_a', 'object_b', 'related', 'account_a')
    `).run(),
    /same organization/,
  );
  assert.throws(
    () => db.prepare(`
      INSERT INTO connectors (
        id, organization_id, name, connector_type, created_by
      ) VALUES ('connector_cross', 'org_a', 'Cross', 'custom', 'account_b')
    `).run(),
    /same organization/,
  );
  assert.throws(
    () => db.prepare(`
      INSERT INTO documents (
        id, organization_id, object_id, title, media_type, byte_size,
        storage_path, sha256, uploaded_by
      ) VALUES (
        'document_cross', 'org_a', 'object_b', 'Cross', 'text/plain', 1,
        'uploads/cross.txt', '00', 'account_a'
      )
    `).run(),
    /same organization/,
  );
  assert.throws(
    () => db.prepare(`
      INSERT INTO audit_logs (
        id, organization_id, actor_account_id, action, target_type
      ) VALUES ('audit_cross', 'org_a', 'account_b', 'test', 'test')
    `).run(),
    /same organization/,
  );
  assert.throws(
    () => db.prepare("UPDATE account_roles SET role_id = ? WHERE account_id = ?")
      .run("role_b", "account_a"),
    /same organization/,
  );
  assert.throws(
    () => db.prepare("UPDATE objects SET created_by = ? WHERE id = ?")
      .run("account_b", "object_a"),
    /same organization/,
  );
  db.close();
  console.log(
    "Tenant isolation test passed: cross-organization inserts and updates are rejected by SQLite.",
  );
} finally {
  rmSync(temp, { recursive: true, force: true });
}
