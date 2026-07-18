import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const ignoredDirectories = new Set([".git", "node_modules", "dist", "storage", "releases"]);
const sourceExtensions = new Set([
  ".js", ".mjs", ".ts", ".tsx", ".json", ".md", ".sql", ".yml", ".yaml", ".html", ".css", ".example",
]);
const findings = [];

function extension(path) {
  const index = path.lastIndexOf(".");
  return index < 0 ? "" : path.slice(index);
}

function walk(directory) {
  for (const name of readdirSync(directory)) {
    if (ignoredDirectories.has(name)) continue;
    const path = join(directory, name);
    const stats = statSync(path);
    if (stats.isDirectory()) {
      walk(path);
      continue;
    }
    if (!sourceExtensions.has(extension(path)) && name !== ".gitignore") continue;
    const content = readFileSync(path, "utf8");
    const relativePath = relative(root, path);
    if ([
      "scripts/security-audit.mjs",
      "scripts/git-history-audit.mjs",
    ].includes(relativePath)) continue;
    const rules = [
      ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
      ["OpenAI-style secret", /\bsk-[A-Za-z0-9_-]{24,}\b/],
      ["Google-style secret", /\bAIza[A-Za-z0-9_-]{30,}\b/],
      ["Slack-style secret", /\bxox[baprs]-[A-Za-z0-9-]+\b/],
      ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
      ["absolute user path", /\/Users\/[A-Za-z0-9._-]+\//],
      ["vendor preset", /\b(?:feishu|lark|openai|anthropic|gemini|codex|claude|capitalnuts)\b/i],
      ["provider-specific identifier", /\b(?:app_token|table_id|field_id)\b/i],
    ];
    for (const [label, pattern] of rules) {
      if (pattern.test(content)) findings.push(`${relativePath}: ${label}`);
    }
  }
}

walk(root);
assert.deepEqual(findings, [], `Security audit findings:\n${findings.join("\n")}`);

const gitignore = readFileSync(join(root, ".gitignore"), "utf8");
for (const required of [
  ".env.*",
  "storage/",
  "uploads/",
  "backups/",
  "releases/",
  "test-results/",
  ".playwright-cli/",
  "*.sqlite",
  "*.tar.gz",
]) {
  assert.ok(gitignore.includes(required), `.gitignore must exclude ${required}`);
}

const envExample = readFileSync(join(root, ".env.example"), "utf8");
assert.equal(/=[\s]*["'][^"']+["']/.test(
  envExample
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("OPENVC_"))
    .join("\n"),
), false, "environment template must not include secret values");

const server = readFileSync(join(root, "apps/api/src/server.mjs"), "utf8");
assert.ok(server.includes('const host = process.env.OPENVC_HOST || "127.0.0.1"'));
assert.ok(server.includes("outboundConnectionsEnabledByDefault: false"));
assert.equal(server.includes('listen(port, "0.0.0.0"'), false);

console.log("Security audit passed: no secrets, private paths, vendor presets, or unsafe default binding.");
