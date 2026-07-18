import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer as createNetServer } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as wait } from "node:timers/promises";
import { DatabaseSync } from "node:sqlite";
import { hash as hashPassword } from "@node-rs/argon2";

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
    OPENVC_SETUP_TOKEN: "OpenVC-Test-Setup-Token-2026",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
server.stdout.on("data", (chunk) => { output += String(chunk); });
server.stderr.on("data", (chunk) => { output += String(chunk); });

async function request(path, {
  method = "GET",
  body,
  cookie = "",
  csrf = "",
  expected = 200,
  extraHeaders = {},
} = {}) {
  const headers = { ...extraHeaders };
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
  assert.equal(status.payload.setupTokenRequired, true);
  assert.equal(status.payload.network.boundToLoopback, true);
  assert.equal(status.payload.network.outboundConnectionsEnabledByDefault, false);

  await request("/api/bootstrap", { expected: 401 });
  await request("/api/setup/bootstrap", {
    method: "POST",
    body: {
      organizationName: "Wrong token",
      adminName: "Wrong token",
      email: "wrong-token@example.test",
      password: "OpenVC-Wrong-Token-2026",
      setupToken: "not-the-token",
    },
    expected: 403,
  });
  await request("/api/setup/bootstrap", {
    method: "POST",
    body: {
      organizationName: "Cross-site Organization",
      adminName: "Cross-site Administrator",
      email: "cross-site@example.test",
      password: "OpenVC-Cross-Site-2026",
    },
    extraHeaders: {
      Host: "attacker.example",
      Origin: "http://attacker.example",
    },
    expected: 403,
  });
  const setup = await request("/api/setup/bootstrap", {
    method: "POST",
    body: {
      organizationName: "Test Organization",
      adminName: "Test Administrator",
      email: "admin@example.test",
      password: "OpenVC-Local-Test-2026",
      setupToken: "OpenVC-Test-Setup-Token-2026",
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
      setupToken: "OpenVC-Test-Setup-Token-2026",
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
    body: {
      name: "Synthetic Test Fund",
      data: {
        public_note: "Visible to readers",
        confidential_note: "Board only",
      },
    },
    cookie,
    csrf,
    expected: 201,
  });
  assert.equal(created.payload.item.name, "Synthetic Test Fund");
  const fundList = await request("/api/objects/fund", { cookie });
  assert.deepEqual(fundList.payload.items[0].data, {});
  await request("/api/fields", {
    method: "POST",
    body: {
      objectType: "fund",
      fieldKey: "confidential_note",
      label: "Confidential note",
      dataType: "long_text",
      classification: "confidential",
    },
    cookie,
    csrf,
    expected: 201,
  });
  await request("/api/fields", {
    method: "POST",
    body: {
      objectType: "fund",
      fieldKey: "oversized_options",
      label: "Oversized options",
      dataType: "single_select",
      options: ["x".repeat(130 * 1024)],
    },
    cookie,
    csrf,
    expected: 400,
  });

  const accessDb = new DatabaseSync(dbPath);
  const organization = accessDb.prepare("SELECT id FROM organizations LIMIT 1").get();
  const viewerRole = accessDb.prepare("SELECT id FROM roles WHERE code = 'viewer'").get();
  const viewerPassword = "OpenVC-Viewer-Test-2026";
  accessDb.prepare(`
    INSERT INTO accounts (id, organization_id, email, name)
    VALUES ('viewer_account', ?, 'viewer@example.test', 'Viewer')
  `).run(organization.id);
  accessDb.prepare(`
    INSERT INTO account_credentials (account_id, password_hash) VALUES (?, ?)
  `).run("viewer_account", await hashPassword(viewerPassword));
  accessDb.prepare("INSERT INTO account_roles (account_id, role_id) VALUES (?, ?)")
    .run("viewer_account", viewerRole.id);
  accessDb.close();
  const viewerLogin = await request("/api/auth/login", {
    method: "POST",
    body: { email: "viewer@example.test", password: viewerPassword },
  });
  const viewerCookie = viewerLogin.response.headers.get("set-cookie")?.split(";")[0] || "";
  const adminFund = await request(
    `/api/objects/fund/${created.payload.item.id}`,
    { cookie },
  );
  assert.equal(adminFund.payload.item.data.confidential_note, "Board only");
  const viewerFunds = await request("/api/objects/fund", { cookie: viewerCookie });
  const viewerFund = await request(
    `/api/objects/fund/${viewerFunds.payload.items[0].id}`,
    { cookie: viewerCookie },
  );
  assert.equal(viewerFund.payload.item.data.public_note, "Visible to readers");
  assert.equal(
    Object.hasOwn(viewerFund.payload.item.data, "confidential_note"),
    false,
    "A read-only account must not receive confidential field values.",
  );
  const viewerFields = await request("/api/fields", { cookie: viewerCookie });
  assert.equal(
    viewerFields.payload.items.some((field) => field.fieldKey === "confidential_note"),
    false,
    "A read-only account must not receive confidential field definitions.",
  );
  await request("/api/objects/fund", {
    method: "POST",
    body: { name: "Blocked cross-origin mutation" },
    cookie,
    csrf,
    extraHeaders: { Origin: "https://attacker.example" },
    expected: 403,
  });
  await request("/api/auth/me", {
    cookie: "openvc_session=%E0%A4%A",
    expected: 401,
  });
  await request("/api/auth/login", {
    method: "POST",
    body: {
      email: "admin@example.test",
      password: "A".repeat(2000),
    },
    expected: 400,
  });

  const operationsDb = new DatabaseSync(dbPath);
  const operationsRole = operationsDb.prepare("SELECT id FROM roles WHERE code = 'operations'").get();
  const operationsPassword = "OpenVC-Operations-Test-2026";
  operationsDb.prepare(`
    INSERT INTO accounts (id, organization_id, email, name)
    VALUES ('operations_account', ?, 'operations@example.test', 'Operations')
  `).run(organization.id);
  operationsDb.prepare(`
    INSERT INTO account_credentials (account_id, password_hash) VALUES (?, ?)
  `).run("operations_account", await hashPassword(operationsPassword));
  operationsDb.prepare("INSERT INTO account_roles (account_id, role_id) VALUES (?, ?)")
    .run("operations_account", operationsRole.id);
  operationsDb.close();
  const operationsLogin = await request("/api/auth/login", {
    method: "POST",
    body: { email: "operations@example.test", password: operationsPassword },
  });
  const operationsCookie =
    operationsLogin.response.headers.get("set-cookie")?.split(";")[0] || "";
  const operationsCsrf = operationsLogin.payload.csrfToken;
  const operationsFund = await request(
    `/api/objects/fund/${created.payload.item.id}`,
    { cookie: operationsCookie },
  );
  assert.equal(Object.hasOwn(operationsFund.payload.item.data, "confidential_note"), false);
  await request(`/api/objects/fund/${created.payload.item.id}`, {
    method: "PATCH",
    body: { data: { public_note: "Updated without erasing protected data" } },
    cookie: operationsCookie,
    csrf: operationsCsrf,
  });
  await request(`/api/objects/fund/${created.payload.item.id}`, {
    method: "PATCH",
    body: { data: { confidential_note: "Unauthorized overwrite" } },
    cookie: operationsCookie,
    csrf: operationsCsrf,
    expected: 403,
  });
  const preservedFund = await request(
    `/api/objects/fund/${created.payload.item.id}`,
    { cookie },
  );
  assert.equal(preservedFund.payload.item.data.confidential_note, "Board only");
  const restrictedDeal = await request("/api/objects/deal", {
    method: "POST",
    body: { name: "Deal hidden from operations" },
    cookie,
    csrf,
    expected: 201,
  });
  await request("/api/documents", {
    method: "POST",
    body: {
      objectId: restrictedDeal.payload.item.id,
      fileName: "unauthorized-attachment.txt",
      contentBase64: Buffer.from("blocked").toString("base64"),
    },
    cookie: operationsCookie,
    csrf: operationsCsrf,
    expected: 404,
  });

  await request("/api/documents", {
    method: "POST",
    body: { fileName: "invalid.txt", contentBase64: "not-valid-base64" },
    cookie,
    csrf,
    expected: 400,
  });
  await request("/api/documents", {
    method: "POST",
    body: {
      fileName: "non-canonical.txt",
      contentBase64: "AB==",
    },
    cookie,
    csrf,
    expected: 400,
  });
  await request("/api/documents", {
    method: "POST",
    body: {
      fileName: "unsafe.txt",
      mediaType: "text/plain\r\nX-Test: injected",
      contentBase64: Buffer.from("blocked").toString("base64"),
    },
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
    body: {
      name: "Credential smuggling",
      connectorType: "custom",
      manifest: { authorization: "Bearer synthetic-secret" },
    },
    cookie,
    csrf,
    expected: 400,
  });
  await request("/api/connectors", {
    method: "POST",
    body: {
      name: "Token disguised as a value",
      connectorType: "custom",
      manifest: {
        endpoint: "https://connector.invalid",
        value: `sk-${"A".repeat(32)}`,
      },
    },
    cookie,
    csrf,
    expected: 400,
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

  await request("/api/auth/login", {
    method: "POST",
    body: {
      email: "oversized@example.test",
      password: `OpenVC-${"x".repeat(17 * 1024)}-2026`,
    },
    expected: 413,
  });
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await request("/api/auth/login", {
      method: "POST",
      body: {
        email: `rotating-${attempt}@example.test`,
        password: "OpenVC-Invalid-Test-2026",
      },
      expected: 401,
    });
  }
  const throttled = await request("/api/auth/login", {
    method: "POST",
    body: {
      email: "rotating-final@example.test",
      password: "OpenVC-Invalid-Test-2026",
    },
    expected: 429,
  });
  assert.ok(Number(throttled.response.headers.get("retry-after")) > 0);

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
