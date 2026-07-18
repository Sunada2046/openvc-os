import { createServer } from "node:http";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {
  createCipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { hash as hashPassword, verify as verifyPassword } from "@node-rs/argon2";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");

function loadLocalEnv() {
  const path = resolve(root, ".env.local");
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    const value = match[2].replace(/^(['"])(.*)\1$/, "$2");
    process.env[match[1]] = value;
  }
}

loadLocalEnv();

const host = process.env.OPENVC_HOST || "127.0.0.1";
const port = Number(process.env.OPENVC_PORT || 8787);
const storageDir = resolve(root, process.env.OPENVC_STORAGE_DIR || "storage");
const dbPath = resolve(root, process.env.OPENVC_DB_PATH || "storage/openvc.sqlite");
const uploadDir = resolve(root, process.env.OPENVC_UPLOAD_DIR || "storage/uploads");
const cookieSecure = process.env.OPENVC_COOKIE_SECURE === "true";
const allowedOrigins = new Set(
  String(process.env.OPENVC_ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean),
);
const sessionCookieName = "openvc_session";
const maxBodyBytes = 30 * 1024 * 1024;
const sessionTtlMs = 12 * 60 * 60 * 1000;
const loginWindowMs = 15 * 60 * 1000;
const maxLoginFailures = 5;
const maxLoginFailureEntries = 10_000;
const maxObjectDataBytes = 1024 * 1024;
const maxConnectorManifestBytes = 128 * 1024;
const maxSecretBytes = 64 * 1024;
const maxPasswordBytes = 1024;
const maxFieldDefinitionBytes = 128 * 1024;
const configuredSetupToken = String(process.env.OPENVC_SETUP_TOKEN || "").trim();
let setupToken = configuredSetupToken || randomBytes(32).toString("base64url");
const generatedSetupToken = !configuredSetupToken;
const uploadStoragePath = relative(storageDir, uploadDir);

if (uploadStoragePath.startsWith("..") || isAbsolute(uploadStoragePath)) {
  throw new Error("OPENVC_UPLOAD_DIR must remain inside OPENVC_STORAGE_DIR.");
}

if (!isLoopbackHostname(host)) {
  if (!cookieSecure) {
    throw new Error(
      "Non-loopback API binding requires OPENVC_COOKIE_SECURE=true and HTTPS termination.",
    );
  }
  if (allowedOrigins.size === 0) {
    throw new Error(
      "Non-loopback API binding requires an explicit OPENVC_ALLOWED_ORIGINS allowlist.",
    );
  }
}

for (const directory of [storageDir, dirname(dbPath), uploadDir]) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
}

const db = new DatabaseSync(dbPath);
db.exec(readFileSync(resolve(root, "packages/db/schema.sql"), "utf8"));
db.enableDefensive(true);
chmodSync(dbPath, 0o600);

const permissions = [
  "dashboard.view",
  "fund.view", "fund.edit",
  "lp.view", "lp.edit",
  "deal.view", "deal.edit",
  "ic.view", "ic.edit",
  "portfolio.view", "portfolio.edit",
  "exit.view", "exit.edit",
  "person.view", "person.edit",
  "task.view", "task.edit",
  "risk.view", "risk.edit",
  "field.view", "field.manage",
  "connector.view", "connector.manage",
  "document.view", "document.upload",
  "audit.view",
  "account.manage",
  "system.export",
];

const roleTemplates = [
  { code: "super_admin", name: "Super administrator", permissions },
  {
    code: "partner",
    name: "Partner",
    permissions: permissions.filter((permission) =>
      !["account.manage", "connector.manage"].includes(permission)),
  },
  {
    code: "investment",
    name: "Investment team",
    permissions: [
      "dashboard.view", "deal.view", "deal.edit", "ic.view", "ic.edit",
      "task.view", "task.edit", "risk.view", "document.view", "document.upload",
      "person.view", "fund.view",
    ],
  },
  {
    code: "operations",
    name: "Fund operations",
    permissions: [
      "dashboard.view", "fund.view", "fund.edit", "lp.view", "lp.edit",
      "portfolio.view", "exit.view", "task.view", "task.edit",
      "document.view", "document.upload",
    ],
  },
  {
    code: "viewer",
    name: "Read only",
    permissions: permissions.filter((permission) => permission.endsWith(".view")),
  },
];

const objectTypes = new Set([
  "fund", "lp", "deal", "ic", "portfolio", "exit", "person", "task", "risk",
]);
const loginFailures = new Map();
const dummyPasswordHash = await hashPassword(randomBytes(32).toString("base64url"));

function createId(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${randomBytes(8).toString("hex")}`;
}

function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
  return createHash("sha256").update(bytes).digest("hex");
}

function equalHash(left, right) {
  const leftBytes = Buffer.from(String(left));
  const rightBytes = Buffer.from(String(right));
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function slugify(value) {
  const slug = String(value || "")
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48);
  return slug || `organization-${randomBytes(4).toString("hex")}`;
}

function safeJson(value, fallback = {}) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function safeObjectJson(value) {
  const parsed = safeJson(value);
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
}

function isLoopback(request) {
  const address = String(request.socket.remoteAddress || "");
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function isLoopbackHostname(value) {
  return ["127.0.0.1", "::1", "[::1]", "localhost"].includes(
    String(value || "").toLowerCase(),
  );
}

function parseCookies(header = "") {
  return Object.fromEntries(
    header.split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
      const index = part.indexOf("=");
      if (index < 0) return [part, ""];
      try {
        return [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
      } catch {
        return [part.slice(0, index), ""];
      }
    }),
  );
}

function requestOriginAllowed(request) {
  const origin = String(request.headers.origin || "");
  if (!origin) return true;
  if (allowedOrigins.has(origin)) return true;
  try {
    const originUrl = new URL(origin);
    const requestHost = String(request.headers.host || "").toLowerCase();
    if (originUrl.host.toLowerCase() !== requestHost) return false;
    if (!isLoopbackHostname(host)) return true;
    return isLoopbackHostname(originUrl.hostname);
  } catch {
    return false;
  }
}

function securityHeaders(request) {
  const origin = String(request.headers.origin || "");
  const headers = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-site",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
  if (origin && allowedOrigins.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
    headers.Vary = "Origin";
  }
  return headers;
}

function sendJson(request, response, status, payload, extraHeaders = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...securityHeaders(request),
    ...extraHeaders,
  });
  response.end(JSON.stringify(payload));
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

async function readJson(request, limit = maxBodyBytes) {
  const declaredLength = Number(request.headers["content-length"] || 0);
  if (Number.isFinite(declaredLength) && declaredLength > limit) {
    throw new HttpError(413, "Request body is too large.");
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > limit) throw new HttpError(413, "Request body is too large.");
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

function audit(principal, action, targetType, targetId = "", metadata = {}, result = "success") {
  db.prepare(`
    INSERT INTO audit_logs (
      id, organization_id, actor_account_id, action, target_type, target_id, result, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    createId("audit"),
    principal?.organizationId || null,
    principal?.accountId || null,
    action,
    targetType,
    targetId || null,
    result,
    JSON.stringify(metadata),
  );
}

function passwordError(password) {
  const value = String(password || "");
  if (Buffer.byteLength(value) > maxPasswordBytes) return "Password is too long.";
  if (value.length < 12) return "Password must contain at least 12 characters.";
  if (!/[A-Z]/.test(value) || !/[a-z]/.test(value) || !/\d/.test(value)) {
    return "Password must include uppercase, lowercase, and numeric characters.";
  }
  return "";
}

function sessionCookie(token, maxAgeSeconds = sessionTtlMs / 1000) {
  return [
    `${sessionCookieName}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.floor(maxAgeSeconds)}`,
    cookieSecure ? "Secure" : "",
  ].filter(Boolean).join("; ");
}

function principalForAccount(accountId) {
  const account = db.prepare(`
    SELECT id, organization_id, email, name, status FROM accounts WHERE id = ?
  `).get(accountId);
  if (!account || account.status !== "active") return null;
  const roles = db.prepare(`
    SELECT roles.code, roles.name, roles.permissions_json
    FROM roles
    JOIN account_roles ON account_roles.role_id = roles.id
    WHERE account_roles.account_id = ? AND roles.organization_id = ?
  `).all(accountId, account.organization_id);
  return {
    accountId: account.id,
    organizationId: account.organization_id,
    email: account.email,
    name: account.name,
    roles: roles.map((role) => ({ code: role.code, name: role.name })),
    permissions: Array.from(new Set(roles.flatMap((role) => safeJson(role.permissions_json, [])))),
  };
}

function authenticate(request) {
  const token = parseCookies(request.headers.cookie || "")[sessionCookieName];
  if (!token) return null;
  const session = db.prepare(`
    SELECT * FROM sessions
    WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
  `).get(sha256(token), new Date().toISOString());
  if (!session) return null;
  const principal = principalForAccount(session.account_id);
  if (!principal) return null;
  db.prepare("UPDATE sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?").run(session.id);
  return { principal, session };
}

function requirePermission(request, response, permission) {
  const auth = authenticate(request);
  if (!auth) {
    sendJson(request, response, 401, { error: "Authentication required." });
    return null;
  }
  if (!auth.principal.permissions.includes(permission)) {
    audit(auth.principal, "access.denied", "permission", permission, {}, "denied");
    sendJson(request, response, 403, { error: "Permission denied." });
    return null;
  }
  return auth;
}

function requireCsrf(request, response, auth) {
  const supplied = String(request.headers["x-csrf-token"] || "");
  if (!supplied || !equalHash(sha256(supplied), auth.session.csrf_hash)) {
    audit(auth.principal, "csrf.denied", "session", auth.session.id, {}, "denied");
    sendJson(request, response, 403, { error: "CSRF validation failed." });
    return false;
  }
  return true;
}

function pruneLoginFailures(now = Date.now()) {
  for (const [key, value] of loginFailures) {
    if (now - value.firstAt >= loginWindowMs) loginFailures.delete(key);
  }
  while (loginFailures.size > maxLoginFailureEntries) {
    const oldestKey = loginFailures.keys().next().value;
    if (oldestKey === undefined) break;
    loginFailures.delete(oldestKey);
  }
}

function loginFailureKeys(request, email) {
  const address = String(request.socket.remoteAddress || "unknown");
  return [`ip:${sha256(address)}`, `email:${sha256(email)}`];
}

function blockedLoginFailure(keys) {
  const now = Date.now();
  return keys.some((key) => {
    const failure = loginFailures.get(key);
    return failure &&
      failure.count >= maxLoginFailures &&
      now - failure.firstAt < loginWindowMs;
  });
}

function recordLoginFailure(keys) {
  const now = Date.now();
  for (const key of keys) {
    const previous = loginFailures.get(key);
    const current = previous && now - previous.firstAt < loginWindowMs
      ? previous
      : { count: 0, firstAt: now };
    loginFailures.set(key, { ...current, count: current.count + 1 });
  }
}

function createSession(request, accountId) {
  const now = new Date().toISOString();
  db.prepare("DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL").run(now);
  db.prepare(`
    UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
    WHERE id IN (
      SELECT id FROM sessions
      WHERE account_id = ? AND revoked_at IS NULL
      ORDER BY created_at DESC LIMIT -1 OFFSET 19
    )
  `).run(accountId);
  const token = randomBytes(32).toString("base64url");
  const csrf = randomBytes(24).toString("base64url");
  const expiresAt = new Date(Date.now() + sessionTtlMs).toISOString();
  db.prepare(`
    INSERT INTO sessions (id, account_id, token_hash, csrf_hash, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(createId("session"), accountId, sha256(token), sha256(csrf), expiresAt);
  return { token, csrf, expiresAt };
}

function fieldClassifications(organizationId, objectType) {
  return new Map(db.prepare(`
    SELECT field_key, classification
    FROM field_definitions
    WHERE organization_id = ? AND object_type = ?
  `).all(organizationId, objectType).map((field) => [field.field_key, field.classification]));
}

function canViewClassification(principal, objectType, classification) {
  if (["public", "internal"].includes(classification)) return true;
  if (principal.permissions.includes("field.manage")) return true;
  if (classification === "restricted") {
    return principal.permissions.includes(`${objectType}.edit`) ||
      principal.permissions.includes("data.restricted.view");
  }
  return principal.permissions.includes("data.confidential.view");
}

function visibleObjectData(row, principal, classifications = null) {
  const fields = classifications ||
    fieldClassifications(principal.organizationId, row.object_type);
  return Object.fromEntries(
    Object.entries(safeObjectJson(row.data_json)).filter(([key]) =>
      canViewClassification(
        principal,
        row.object_type,
        fields.get(key) || "internal",
      )),
  );
}

function protectedObjectData(principal, objectType, nextData, currentData = {}) {
  const classifications = fieldClassifications(principal.organizationId, objectType);
  const protectedKeys = Array.from(classifications.entries())
    .filter(([, classification]) =>
      !canViewClassification(principal, objectType, classification))
    .map(([key]) => key);
  if (protectedKeys.some((key) => Object.hasOwn(nextData, key))) {
    return { error: "One or more field values are not editable by this account." };
  }
  const merged = { ...nextData };
  for (const key of protectedKeys) {
    if (Object.hasOwn(currentData, key)) merged[key] = currentData[key];
  }
  return { data: merged };
}

function publicObject(row, principal, includeData = true, classifications = null) {
  return {
    id: row.id,
    objectType: row.object_type,
    name: row.name,
    status: row.status,
    data: includeData ? visibleObjectData(row, principal, classifications) : {},
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function containsCredentialMaterial(value) {
  const sensitiveKeys = new Set([
    "apikey", "accesstoken", "refreshtoken", "token", "password", "passwd",
    "secret", "clientsecret", "credential", "credentials", "authorization",
    "privatekey", "accesskey", "authheader",
  ]);
  const pending = [value];
  while (pending.length) {
    const current = pending.pop();
    if (typeof current === "string") {
      if (
        /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(current) ||
        /^\s*(?:Bearer|Basic)\s+\S+/i.test(current) ||
        /\b(?:sk-|AIza|xox[baprs]-|AKIA|gh[pousr]_|npm_)[A-Za-z0-9_-]{16,}\b/.test(current) ||
        /\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/.test(current)
      ) return true;
      continue;
    }
    if (!current || typeof current !== "object") continue;
    for (const [key, child] of Object.entries(current)) {
      if (sensitiveKeys.has(key.replace(/[^a-z0-9]/gi, "").toLowerCase())) return true;
      pending.push(child);
    }
  }
  return false;
}

function sanitizeName(value) {
  return basename(String(value || "file"))
    .replace(/[^\p{L}\p{N}._ -]/gu, "_")
    .slice(0, 120) || "file";
}

function secretKey() {
  const path = resolve(storageDir, "connector-secrets.key");
  if (!existsSync(path)) {
    writeFileSync(path, randomBytes(32), { mode: 0o600 });
  }
  chmodSync(path, 0o600);
  const key = readFileSync(path);
  if (key.length !== 32) throw new Error("Connector secret key is invalid.");
  return key;
}

function encryptSecret(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", secretKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return [
    "v1",
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

function setupStatus() {
  return {
    setupRequired: Number(db.prepare("SELECT COUNT(*) AS count FROM accounts").get().count) === 0,
    setupTokenRequired: true,
    network: {
      boundToLoopback: host === "127.0.0.1" || host === "::1" || host === "localhost",
      outboundConnectionsEnabledByDefault: false,
    },
  };
}

async function bootstrap(request, response) {
  if (!setupStatus().setupRequired) {
    sendJson(request, response, 409, { error: "Setup has already been completed." });
    return;
  }
  if (!isLoopback(request)) {
    sendJson(request, response, 403, { error: "First-time setup is only available from this device." });
    return;
  }
  const input = await readJson(request, 16 * 1024);
  const organizationName = String(input.organizationName || "").trim();
  const adminName = String(input.adminName || "").trim();
  const email = normalizeEmail(input.email);
  const invalidPassword = passwordError(input.password);
  const suppliedSetupToken = String(input.setupToken || "");
  if (
    Buffer.byteLength(suppliedSetupToken) > maxPasswordBytes ||
    !equalHash(sha256(suppliedSetupToken), sha256(setupToken))
  ) {
    sendJson(request, response, 403, { error: "A valid one-time setup token is required." });
    return;
  }
  if (
    !organizationName ||
    organizationName.length > 200 ||
    /[\u0000-\u001F\u007F]/u.test(organizationName) ||
    !adminName ||
    adminName.length > 200 ||
    /[\u0000-\u001F\u007F]/u.test(adminName) ||
    email.length > 254 ||
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ||
    invalidPassword
  ) {
    sendJson(request, response, 400, {
      error: invalidPassword || "Organization, administrator name, and a valid email are required.",
    });
    return;
  }
  const organizationId = createId("org");
  const accountId = createId("account");
  const passwordHash = await hashPassword(input.password);
  db.exec("BEGIN IMMEDIATE");
  try {
    if (!setupStatus().setupRequired) {
      db.exec("ROLLBACK");
      sendJson(request, response, 409, { error: "Setup has already been completed." });
      return;
    }
    db.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .run(organizationId, organizationName, slugify(organizationName));
    db.prepare(`
      INSERT INTO accounts (id, organization_id, email, name) VALUES (?, ?, ?, ?)
    `).run(accountId, organizationId, email, adminName);
    db.prepare(`
      INSERT INTO account_credentials (account_id, password_hash) VALUES (?, ?)
    `).run(accountId, passwordHash);
    for (const template of roleTemplates) {
      const roleId = createId("role");
      db.prepare(`
        INSERT INTO roles (id, organization_id, code, name, permissions_json)
        VALUES (?, ?, ?, ?, ?)
      `).run(roleId, organizationId, template.code, template.name, JSON.stringify(template.permissions));
      if (template.code === "super_admin") {
        db.prepare("INSERT INTO account_roles (account_id, role_id) VALUES (?, ?)")
          .run(accountId, roleId);
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  const principal = principalForAccount(accountId);
  audit(principal, "system.setup.completed", "organization", organizationId);
  const session = createSession(request, accountId);
  setupToken = randomBytes(32).toString("base64url");
  sendJson(request, response, 201, {
    authenticated: true,
    account: principal,
    csrfToken: session.csrf,
    expiresAt: session.expiresAt,
  }, { "Set-Cookie": sessionCookie(session.token) });
}

async function login(request, response) {
  const input = await readJson(request, 16 * 1024);
  const email = normalizeEmail(input.email);
  if (email.length > 254 || Buffer.byteLength(String(input.password || "")) > maxPasswordBytes) {
    sendJson(request, response, 400, { error: "A valid email and password are required." });
    return;
  }
  pruneLoginFailures();
  const failureKeys = loginFailureKeys(request, email);
  if (blockedLoginFailure(failureKeys)) {
    sendJson(
      request,
      response,
      429,
      { error: "Too many login attempts. Try again later." },
      { "Retry-After": String(Math.ceil(loginWindowMs / 1000)) },
    );
    return;
  }
  const account = db.prepare("SELECT * FROM accounts WHERE email = ?").get(email);
  const credential = account
    ? db.prepare("SELECT * FROM account_credentials WHERE account_id = ?").get(account.id)
    : null;
  const passwordMatches = await verifyPassword(
    credential?.password_hash || dummyPasswordHash,
    String(input.password || ""),
  ).catch(() => false);
  const valid = Boolean(
    account &&
    credential &&
    account.status === "active" &&
    passwordMatches,
  );
  if (!valid) {
    recordLoginFailure(failureKeys);
    sendJson(request, response, 401, { error: "Email or password is incorrect." });
    return;
  }
  for (const key of failureKeys) loginFailures.delete(key);
  const principal = principalForAccount(account.id);
  const session = createSession(request, account.id);
  audit(principal, "auth.login", "account", account.id);
  sendJson(request, response, 200, {
    authenticated: true,
    account: principal,
    csrfToken: session.csrf,
    expiresAt: session.expiresAt,
  }, { "Set-Cookie": sessionCookie(session.token) });
}

async function route(request, response) {
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

  if (
    !requestOriginAllowed(request) &&
    !["GET", "HEAD"].includes(request.method || "")
  ) {
    sendJson(request, response, 403, { error: "Request origin is not allowed." });
    return;
  }

  if (request.method === "OPTIONS") {
    sendJson(request, response, 204, {}, {
      "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
      "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    });
    return;
  }

  if (request.method === "GET" && url.pathname === "/health") {
    sendJson(request, response, 200, { ok: true });
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/setup/status") {
    sendJson(request, response, 200, setupStatus());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/setup/bootstrap") {
    await bootstrap(request, response);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/auth/login") {
    await login(request, response);
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/auth/me") {
    const auth = authenticate(request);
    if (!auth) {
      sendJson(request, response, 401, { error: "Authentication required." });
      return;
    }
    const csrf = randomBytes(24).toString("base64url");
    db.prepare("UPDATE sessions SET csrf_hash = ? WHERE id = ?").run(sha256(csrf), auth.session.id);
    sendJson(request, response, 200, {
      authenticated: true,
      account: auth.principal,
      csrfToken: csrf,
      expiresAt: auth.session.expires_at,
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/auth/logout") {
    const auth = authenticate(request);
    if (auth && !requireCsrf(request, response, auth)) return;
    if (auth) {
      db.prepare("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?").run(auth.session.id);
    }
    sendJson(request, response, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/bootstrap") {
    const auth = requirePermission(request, response, "dashboard.view");
    if (!auth) return;
    const counts = {};
    for (const type of objectTypes) {
      counts[type] = Number(db.prepare(`
        SELECT COUNT(*) AS count FROM objects
        WHERE organization_id = ? AND object_type = ? AND deleted_at IS NULL
      `).get(auth.principal.organizationId, type).count);
    }
    sendJson(request, response, 200, {
      account: auth.principal,
      counts,
      setup: setupStatus(),
    });
    return;
  }

  const objectCollection = url.pathname.match(/^\/api\/objects\/([^/]+)$/);
  if (objectCollection && request.method === "GET") {
    const type = decodeURIComponent(objectCollection[1]);
    if (!objectTypes.has(type)) {
      sendJson(request, response, 404, { error: "Unknown object type." });
      return;
    }
    const auth = requirePermission(request, response, `${type}.view`);
    if (!auth) return;
    const requestedLimit = Number(url.searchParams.get("limit") || 100);
    const limit = Number.isSafeInteger(requestedLimit)
      ? Math.min(Math.max(requestedLimit, 1), 100)
      : 100;
    const rows = db.prepare(`
      SELECT * FROM objects
      WHERE organization_id = ? AND object_type = ? AND deleted_at IS NULL
      ORDER BY updated_at DESC LIMIT ?
    `).all(auth.principal.organizationId, type, limit);
    sendJson(request, response, 200, {
      items: rows.map((row) => publicObject(row, auth.principal, false)),
    });
    return;
  }
  if (objectCollection && request.method === "POST") {
    const type = decodeURIComponent(objectCollection[1]);
    if (!objectTypes.has(type)) {
      sendJson(request, response, 404, { error: "Unknown object type." });
      return;
    }
    const auth = requirePermission(request, response, `${type}.edit`);
    if (!auth || !requireCsrf(request, response, auth)) return;
    const input = await readJson(request, 2 * 1024 * 1024);
    const name = String(input.name || "").trim();
    const status = String(input.status || "active").trim();
    const data = input.data && typeof input.data === "object" && !Array.isArray(input.data)
      ? input.data
      : {};
    const protectedData = protectedObjectData(auth.principal, type, data);
    if (protectedData.error) {
      sendJson(request, response, 403, { error: protectedData.error });
      return;
    }
    const serializedData = JSON.stringify(protectedData.data);
    if (
      !name ||
      name.length > 200 ||
      /[\u0000-\u001F\u007F]/u.test(name) ||
      !/^[^\u0000-\u001F\u007F]{1,64}$/u.test(status)
    ) {
      sendJson(request, response, 400, { error: "A valid name and status are required." });
      return;
    }
    if (Buffer.byteLength(serializedData) > maxObjectDataBytes) {
      sendJson(request, response, 413, { error: "Structured record data is too large." });
      return;
    }
    const id = createId(type);
    db.prepare(`
      INSERT INTO objects (
        id, organization_id, object_type, name, status, data_json, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      auth.principal.organizationId,
      type,
      name,
      status,
      serializedData,
      auth.principal.accountId,
    );
    audit(auth.principal, "object.created", type, id);
    const row = db.prepare("SELECT * FROM objects WHERE id = ?").get(id);
    sendJson(request, response, 201, { item: publicObject(row, auth.principal) });
    return;
  }

  const objectItem = url.pathname.match(/^\/api\/objects\/([^/]+)\/([^/]+)$/);
  if (objectItem && ["GET", "PATCH", "DELETE"].includes(request.method)) {
    const type = decodeURIComponent(objectItem[1]);
    const id = decodeURIComponent(objectItem[2]);
    if (!objectTypes.has(type)) {
      sendJson(request, response, 404, { error: "Unknown object type." });
      return;
    }
    const permission = request.method === "GET" ? `${type}.view` : `${type}.edit`;
    const auth = requirePermission(request, response, permission);
    if (!auth || (request.method !== "GET" && !requireCsrf(request, response, auth))) return;
    const current = db.prepare(`
      SELECT * FROM objects
      WHERE id = ? AND organization_id = ? AND object_type = ? AND deleted_at IS NULL
    `).get(id, auth.principal.organizationId, type);
    if (!current) {
      sendJson(request, response, 404, { error: "Record not found." });
      return;
    }
    if (request.method === "GET") {
      sendJson(request, response, 200, { item: publicObject(current, auth.principal) });
      return;
    }
    if (request.method === "DELETE") {
      db.prepare("UPDATE objects SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .run(id);
      audit(auth.principal, "object.deleted", type, id);
      sendJson(request, response, 200, { ok: true });
      return;
    }
    const input = await readJson(request, 2 * 1024 * 1024);
    const nextName = input.name === undefined ? current.name : String(input.name).trim();
    const nextStatus = input.status === undefined ? current.status : String(input.status).trim();
    const nextData = input.data === undefined
      ? safeObjectJson(current.data_json)
      : input.data;
    if (
      !nextName ||
      nextName.length > 200 ||
      /[\u0000-\u001F\u007F]/u.test(nextName) ||
      !/^[^\u0000-\u001F\u007F]{1,64}$/u.test(nextStatus) ||
      !nextData ||
      typeof nextData !== "object" ||
      Array.isArray(nextData)
    ) {
      sendJson(request, response, 400, { error: "A valid name, status, and data object are required." });
      return;
    }
    const protectedData = protectedObjectData(
      auth.principal,
      type,
      nextData,
      safeObjectJson(current.data_json),
    );
    if (protectedData.error) {
      sendJson(request, response, 403, { error: protectedData.error });
      return;
    }
    const serializedData = JSON.stringify(protectedData.data);
    if (Buffer.byteLength(serializedData) > maxObjectDataBytes) {
      sendJson(request, response, 413, { error: "Structured record data is too large." });
      return;
    }
    db.prepare(`
      UPDATE objects SET name = ?, status = ?, data_json = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      nextName,
      nextStatus,
      serializedData,
      id,
    );
    audit(auth.principal, "object.updated", type, id);
    sendJson(request, response, 200, {
      item: publicObject(
        db.prepare("SELECT * FROM objects WHERE id = ?").get(id),
        auth.principal,
      ),
    });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/fields") {
    const auth = requirePermission(request, response, "field.view");
    if (!auth) return;
    const rows = db.prepare(`
      SELECT * FROM field_definitions WHERE organization_id = ?
      ORDER BY object_type, position, label
    `).all(auth.principal.organizationId);
    sendJson(request, response, 200, {
      items: rows.filter((row) =>
        canViewClassification(auth.principal, row.object_type, row.classification))
        .map((row) => ({
        id: row.id,
        objectType: row.object_type,
        fieldKey: row.field_key,
        label: row.label,
        dataType: row.data_type,
        classification: row.classification,
        required: Boolean(row.required),
        options: safeJson(row.options_json, []),
        formulaExpression: row.formula_expression || "",
        relationTargetType: row.relation_target_type || "",
        position: row.position,
      })),
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/fields") {
    const auth = requirePermission(request, response, "field.manage");
    if (!auth || !requireCsrf(request, response, auth)) return;
    const input = await readJson(request, 256 * 1024);
    const allowedDataTypes = new Set([
      "text", "long_text", "number", "currency", "percent", "date",
      "datetime", "boolean", "single_select", "multi_select",
      "relation", "attachment", "url", "email", "formula",
    ]);
    const allowedClassifications = new Set(["public", "internal", "restricted", "confidential"]);
    const label = String(input.label || input.fieldKey || "").trim();
    const options = Array.isArray(input.options) ? input.options : [];
    const formulaExpression = String(input.formulaExpression || "");
    const relationTargetType = String(input.relationTargetType || "");
    const serializedOptions = JSON.stringify(options);
    const serializedDefinition = JSON.stringify({
      label,
      options,
      formulaExpression,
      relationTargetType,
    });
    const position = Number(input.position ?? 100);
    if (
      !objectTypes.has(input.objectType) ||
      !/^[a-z][a-z0-9_]{1,63}$/.test(input.fieldKey || "") ||
      !allowedDataTypes.has(input.dataType || "text") ||
      !allowedClassifications.has(input.classification || "internal") ||
      !label ||
      label.length > 120 ||
      /[\u0000-\u001F\u007F]/u.test(label) ||
      formulaExpression.length > 4096 ||
      (
        input.dataType === "relation" &&
        !objectTypes.has(relationTargetType)
      ) ||
      !Number.isSafeInteger(position) ||
      position < -100_000 ||
      position > 100_000 ||
      Buffer.byteLength(serializedDefinition) > maxFieldDefinitionBytes
    ) {
      sendJson(request, response, 400, { error: "A valid, bounded field definition is required." });
      return;
    }
    const id = createId("field");
    db.prepare(`
      INSERT INTO field_definitions (
        id, organization_id, object_type, field_key, label, data_type,
        classification, required, options_json, formula_expression,
        relation_target_type, position
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      auth.principal.organizationId,
      input.objectType,
      input.fieldKey,
      label,
      input.dataType || "text",
      input.classification || "internal",
      input.required ? 1 : 0,
      serializedOptions,
      formulaExpression || null,
      relationTargetType || null,
      position,
    );
    audit(auth.principal, "field.created", "field", id);
    sendJson(request, response, 201, { id });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/connectors") {
    const auth = requirePermission(request, response, "connector.view");
    if (!auth) return;
    const rows = db.prepare(`
      SELECT connectors.*,
        (SELECT COUNT(*) FROM connector_secrets WHERE connector_id = connectors.id) AS secret_count
      FROM connectors WHERE organization_id = ? ORDER BY name
    `).all(auth.principal.organizationId);
    sendJson(request, response, 200, {
      items: rows.map((row) => ({
        id: row.id,
        name: row.name,
        connectorType: row.connector_type,
        status: row.status,
        manifest: safeJson(row.manifest_json),
        configuredSecretCount: Number(row.secret_count),
      })),
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/connectors") {
    const auth = requirePermission(request, response, "connector.manage");
    if (!auth || !requireCsrf(request, response, auth)) return;
    const input = await readJson(request, 256 * 1024);
    const name = String(input.name || "").trim();
    const connectorType = String(input.connectorType || "custom").trim();
    if (
      !name ||
      name.length > 120 ||
      /[\u0000-\u001F\u007F]/u.test(name) ||
      !/^[a-z][a-z0-9_-]{1,63}$/.test(connectorType) ||
      (
        input.manifest !== undefined &&
        (!input.manifest || typeof input.manifest !== "object" || Array.isArray(input.manifest))
      )
    ) {
      sendJson(request, response, 400, {
        error: "A connector name and a valid lowercase connector type are required.",
      });
      return;
    }
    const manifest = input.manifest &&
      typeof input.manifest === "object" &&
      !Array.isArray(input.manifest)
      ? input.manifest
      : {};
    const serialized = JSON.stringify(manifest);
    if (Buffer.byteLength(serialized) > maxConnectorManifestBytes) {
      sendJson(request, response, 413, { error: "Connector manifest is too large." });
      return;
    }
    if (containsCredentialMaterial(manifest)) {
      sendJson(request, response, 400, {
        error: "Connector manifests must not contain credentials. Add secrets separately.",
      });
      return;
    }
    const id = createId("connector");
    db.prepare(`
      INSERT INTO connectors (
        id, organization_id, name, connector_type, status, manifest_json, created_by
      ) VALUES (?, ?, ?, ?, 'disabled', ?, ?)
    `).run(
      id,
      auth.principal.organizationId,
      name,
      connectorType,
      serialized,
      auth.principal.accountId,
    );
    audit(auth.principal, "connector.registered", "connector", id);
    sendJson(request, response, 201, { id, status: "disabled" });
    return;
  }

  const connectorSecret = url.pathname.match(/^\/api\/connectors\/([^/]+)\/secrets$/);
  if (connectorSecret && request.method === "POST") {
    const auth = requirePermission(request, response, "connector.manage");
    if (!auth || !requireCsrf(request, response, auth)) return;
    const connectorId = decodeURIComponent(connectorSecret[1]);
    const connector = db.prepare(`
      SELECT id FROM connectors WHERE id = ? AND organization_id = ?
    `).get(connectorId, auth.principal.organizationId);
    if (!connector) {
      sendJson(request, response, 404, { error: "Connector not found." });
      return;
    }
    const input = await readJson(request, 128 * 1024);
    const secretName = String(input.name || "").trim();
    const secretValue = String(input.value || "");
    if (
      !/^[A-Z][A-Z0-9_]{1,63}$/.test(secretName) ||
      !secretValue ||
      Buffer.byteLength(secretValue) > maxSecretBytes
    ) {
      sendJson(request, response, 400, { error: "A valid secret name and value are required." });
      return;
    }
    db.prepare(`
      INSERT INTO connector_secrets (id, connector_id, secret_name, encrypted_value)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(connector_id, secret_name) DO UPDATE SET
        encrypted_value = excluded.encrypted_value,
        updated_at = CURRENT_TIMESTAMP
    `).run(createId("secret"), connectorId, secretName, encryptSecret(secretValue));
    audit(auth.principal, "connector.secret.updated", "connector", connectorId, { secretName });
    sendJson(request, response, 201, { ok: true });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/documents") {
    const auth = requirePermission(request, response, "document.upload");
    if (!auth || !requireCsrf(request, response, auth)) return;
    const input = await readJson(request);
    const encoded = String(input.contentBase64 || "");
    const validBase64 = encoded.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(encoded);
    const bytes = validBase64 ? Buffer.from(encoded, "base64") : Buffer.alloc(0);
    const canonicalBase64 = validBase64 && bytes.toString("base64") === encoded;
    const objectId = input.objectId ? String(input.objectId) : null;
    const fileName = String(input.fileName || "");
    const mediaType = String(input.mediaType || "application/octet-stream");
    if (objectId) {
      const object = db.prepare(`
        SELECT id, object_type FROM objects
        WHERE id = ? AND organization_id = ? AND deleted_at IS NULL
      `).get(objectId, auth.principal.organizationId);
      if (
        !object ||
        !auth.principal.permissions.includes(`${object.object_type}.view`)
      ) {
        sendJson(request, response, 404, { error: "Related record not found." });
        return;
      }
    }
    if (
      !fileName ||
      fileName.length > 200 ||
      /[\u0000-\u001F\u007F]/u.test(fileName) ||
      !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(mediaType) ||
      mediaType.length > 255 ||
      !canonicalBase64 ||
      !bytes.length ||
      bytes.length > 25 * 1024 * 1024
    ) {
      sendJson(request, response, 400, { error: "A file up to 25 MB is required." });
      return;
    }
    const id = createId("document");
    const organizationDirectory = resolve(uploadDir, auth.principal.organizationId);
    mkdirSync(organizationDirectory, { recursive: true, mode: 0o700 });
    chmodSync(organizationDirectory, 0o700);
    const path = resolve(organizationDirectory, `${id}-${sanitizeName(fileName)}`);
    writeFileSync(path, bytes, { mode: 0o600 });
    chmodSync(path, 0o600);
    try {
      db.prepare(`
        INSERT INTO documents (
          id, organization_id, object_id, title, media_type, byte_size,
          storage_path, sha256, uploaded_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        auth.principal.organizationId,
        objectId,
        fileName,
        mediaType,
        bytes.length,
        relative(storageDir, path),
        sha256(bytes),
        auth.principal.accountId,
      );
    } catch (error) {
      unlinkSync(path);
      throw error;
    }
    audit(auth.principal, "document.uploaded", "document", id, { byteSize: bytes.length });
    sendJson(request, response, 201, { id, title: fileName, byteSize: bytes.length });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/audit") {
    const auth = requirePermission(request, response, "audit.view");
    if (!auth) return;
    const rows = db.prepare(`
      SELECT id, action, target_type, target_id, result, metadata_json, created_at
      FROM audit_logs WHERE organization_id = ?
      ORDER BY created_at DESC LIMIT 200
    `).all(auth.principal.organizationId);
    sendJson(request, response, 200, {
      items: rows.map((row) => ({
        id: row.id,
        action: row.action,
        targetType: row.target_type,
        targetId: row.target_id || "",
        result: row.result,
        metadata: safeJson(row.metadata_json),
        createdAt: row.created_at,
      })),
    });
    return;
  }

  sendJson(request, response, 404, { error: "Not found." });
}

const server = createServer((request, response) => {
  route(request, response).catch((error) => {
    console.error("Request failed.", {
      method: request.method,
      path: String(request.url || "").split("?")[0],
      errorType: error instanceof Error ? error.name : "UnknownError",
    });
    const status = error instanceof HttpError ? error.status : 500;
    sendJson(request, response, status, {
      error: error instanceof HttpError ? error.message : "Internal server error.",
    });
  });
});

server.requestTimeout = 30_000;
server.headersTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 100;

server.listen(port, host, () => {
  console.log(`OpenVC OS API listening on http://${host}:${port}`);
  if (setupStatus().setupRequired && generatedSetupToken) {
    console.log(`One-time setup token: ${setupToken}`);
  }
});
