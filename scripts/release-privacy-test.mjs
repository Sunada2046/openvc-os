import assert from "node:assert/strict";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const sentinel = resolve(root, "apps/api/src/private-release-sentinel.txt");
const release = resolve(root, "releases/openvc-os-0.1.0.tar.gz");

try {
  writeFileSync(sentinel, "untracked workspace content must never enter a release\n");
  mkdirSync(resolve(root, "releases"), { recursive: true });
  const packaged = spawnSync(process.execPath, ["scripts/package-release.mjs"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(packaged.status, 0, packaged.stderr || packaged.stdout);
  assert.ok(existsSync(release), "Release archive was not created.");

  const listed = spawnSync("tar", ["-tzf", release], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(listed.status, 0, listed.stderr);
  assert.equal(
    listed.stdout.includes("private-release-sentinel.txt"),
    false,
    "Release archive leaked an untracked workspace file.",
  );
  console.log("Release privacy test passed: untracked workspace files are excluded.");
} finally {
  rmSync(sentinel, { force: true });
  rmSync(release, { force: true });
  rmSync(`${release}.sha256`, { force: true });
}
