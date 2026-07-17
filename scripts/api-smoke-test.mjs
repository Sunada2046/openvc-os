import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer as createNetServer } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as wait } from "node:timers/promises";
import { DatabaseSync } from "node:sqlite";

const root = resolve(import.meta.dirname, "..");
const temp = mkdtempSync(join(tmpdir(), "openvc-api-test-"));
const dbPath = join(temp, "storage", "openvc.sqlite");
const storageDir = join(temp, "storage");
const port = await new Promise((resolvePort, reject) => {
  const listener = createNetServer();
  listener.once("error", reject);
  listener.listen(0, "127.0.0.1", () => {
    const address = listener.address();
    listener.close((error) => error
      ? reject(error)
      : resolvePort(typeof address === "object" && address ? address.port : 0));
  });
});
const baseUrl = `http://127.0.0.1:${port}`;

const init = spawnSync("node", ["packages/db/scripts/init.mjs"], {
  cwd: root,
  env: { ...process.env, OPENVC_DB_PATH: dbPath },
  encoding: "utf8",
});
assert.equal(init.status, 0, init.stderr || init.stdout);

const server = spawn("node", ["apps/api/src/server.mjs"], {
  cwd: root,
  env: {
    ...process.env,
    OPENVC_HOST: "127.0.0.1",
    OPENVC_PORT: String(port),
    OPENVC_DB_PATH: dbPath,
    OPENVC_STORAGE_DIR: storageDir,
    OPENVC_UPLOAD_DIR: join(storageDir, "uploads"),
    OPENVC_ALLOWED_ORIGINS: "",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
server.stdout.on("data", (chunk) => { output += String(chunk); });
server.stderr.on("data", (chunk) => { output += String(chunk); });

async function request(path, { method = "GET", body, cookie = "", csrf = "", expected = 200 } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (cookie) headers.Cookie = cookie;
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  assert.equal(response.status, expected, `${method} ${path}: ${JSON.stringify(payload)}`);
  return { response, payload };
}

try {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      if ((await fetch(`${baseUrl}/health`)).ok) break;
    } catch {
      await wait(100);
    }
    if (attempt === 79) throw new Error(`API failed to start:\n${output}`);
  }

  const status = await request("/api/setup/status");
  assert.equal(status.payload.setupRequired, true);
  assert.equal(status.payload.network.boundToLoopback, true);
  assert.equal(status.payload.network.outboundConnectionsEnabledByDefault, false);

  await request("/api/bootstrap", { expected: 401 });
  const setup = await request("/api/setup/bootstrap", {
    method: "POST",
    body: {
      organizationName: "Test Organization",
      adminName: "Test Administrator",
      email: "admin@example.test",
      password: "OpenVC-Local-Test-2026",
    },
    expected: 201,
  });
  const cookie = setup.response.headers.get("set-cookie")?.split(";")[0] || "";
  const csrf = setup.payload.csrfToken;
  assert.ok(cookie && csrf);
  await request("/api/setup/bootstrap", {
    method: "POST",
    body: {
      organizationName: "Second Organization",
      adminName: "Second Administrator",
      email: "second@example.test",
      password: "OpenVC-Second-Test-2026",
    },
    expected: 409,
  });

  const connectors = await request("/api/connectors", { cookie });
  assert.deepEqual(connectors.payload.items, []);
  const fields = await request("/api/fields", { cookie });
  assert.deepEqual(fields.payload.items, []);
  const funds = await request("/api/objects/fund", { cookie });
  assert.deepEqual(funds.payload.items, []);

  await request("/api/objects/fund", {
    method: "POST",
    body: { name: "Blocked without CSRF" },
    cookie,
    expected: 403,
  });
  const created = await request("/api/objects/fund", {
    method: "POST",
    body: { name: "Synthetic Test Fund" },
    cookie,
    csrf,
    expected: 201,
  });
  assert.equal(created.payload.item.name, "Synthetic Test Fund");

  await request("/api/documents", {
    method: "POST",
    body: { fileName: "invalid.txt", contentBase64: "not-valid-base64" },
    cookie,
    csrf,
    expected: 400,
  });
  const writableDb = new DatabaseSync(dbPath);
  writableDb.exec(`
    INSERT INTO organizations (id, name, slug)
    VALUES ('other_org', 'Other Organization', 'other-organization');
    INSERT INTO accounts (id, organization_id, email, name)
    VALUES ('other_account', 'other_org', 'other@example.test', 'Other Account');
    INSERT INTO objects (id, organization_id, object_type, name, created_by)
    VALUES ('other_object', 'other_org', 'deal', 'Other Object', 'other_account');
  `);
  writableDb.close();
  await request("/api/documents", {
    method: "POST",
    body: {
      objectId: "other_object",
      fileName: "cross-tenant.txt",
      contentBase64: Buffer.from("blocked").toString("base64"),
    },
    cookie,
    csrf,
    expected: 404,
  });
  await request("/api/documents", {
    method: "POST",
    body: {
      objectId: created.payload.item.id,
      fileName: "local-note.txt",
      contentBase64: Buffer.from("local only").toString("base64"),
    },
    cookie,
    csrf,
    expected: 201,
  });

  await request("/api/connectors", {
    method: "POST",
    body: { name: "User connector", connectorType: "custom", manifest: {} },
    cookie,
    csrf,
    expected: 201,
  });
  const connectorList = await request("/api/connectors", { cookie });
  assert.equal(connectorList.payload.items.length, 1);
  assert.equal(connectorList.payload.items[0].status, "disabled");

  const db = new DatabaseSync(dbPath, { readOnly: true });
  assert.equal(Number(db.prepare("SELECT COUNT(*) AS count FROM connectors").get().count), 1);
  assert.equal(Number(db.prepare("SELECT COUNT(*) AS count FROM connector_secrets").get().count), 0);
  const document = db.prepare("SELECT storage_path FROM documents").get();
  assert.equal(document.storage_path.startsWith("/"), false);
  db.close();

  await request("/api/auth/logout", {
    method: "POST",
    cookie,
    expected: 403,
  });
  await request("/api/auth/logout", {
    method: "POST",
    cookie,
    csrf,
  });
  await request("/api/auth/me", { cookie, expected: 401 });
  console.log(
    "API smoke test passed: setup lock, authentication, CSRF, tenant-scoped uploads, and disabled connectors.",
  );
} finally {
  if (server.exitCode === null) {
    server.kill("SIGTERM");
    await new Promise((resolveExit) => server.once("exit", resolveExit));
  }
  rmSync(temp, { recursive: true, force: true });
}
