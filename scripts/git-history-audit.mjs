import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const excludedPaths = new Set([
  "scripts/security-audit.mjs",
  "scripts/git-history-audit.mjs",
]);
const patterns = [
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ["high-risk token", /\b(?:sk-|AIza|xox[baprs]-|AKIA|gh[pousr]_|npm_)[A-Za-z0-9_-]{16,}\b/],
  ["JSON web token", /\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/],
  ["absolute user path", /\/Users\/[A-Za-z0-9._-]+\//],
];

function git(args, encoding = "utf8") {
  const result = spawnSync("git", args, {
    cwd: root,
    encoding,
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(result.stderr || "Git history query failed.");
  return result.stdout;
}

const commits = git(["rev-list", "--all"]).trim().split(/\r?\n/).filter(Boolean);
const blobs = new Map();
for (const commit of commits) {
  const entries = git(["ls-tree", "-r", "-z", "--full-tree", commit], "buffer")
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  for (const entry of entries) {
    const match = entry.match(/^\d+\s+blob\s+([0-9a-f]+)\t(.+)$/s);
    if (!match || excludedPaths.has(match[2])) continue;
    if (!blobs.has(match[1])) blobs.set(match[1], match[2]);
  }
}

const findings = [];
for (const [sha, path] of blobs) {
  const content = git(["cat-file", "blob", sha], "buffer");
  if (content.includes(0)) continue;
  const text = content.toString("utf8");
  for (const [label, pattern] of patterns) {
    if (pattern.test(text)) findings.push(`${sha.slice(0, 12)} ${path}: ${label}`);
  }
}

const messages = git(["log", "--all", "--format=%B"]);
for (const [label, pattern] of patterns) {
  if (pattern.test(messages)) findings.push(`commit messages: ${label}`);
}

assert.deepEqual(findings, [], `Git history privacy findings:\n${findings.join("\n")}`);
console.log(`Git history audit passed: ${commits.length} commits and ${blobs.size} unique blobs scanned.`);
