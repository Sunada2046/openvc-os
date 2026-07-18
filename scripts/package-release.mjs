import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const releaseDir = join(root, "releases");
const stage = mkdtempSync(join(tmpdir(), "openvc-release-"));
const entries = [
  ".env.example",
  ".gitattributes",
  ".github",
  ".gitignore",
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "apps",
  "docs",
  "package.json",
  "package-lock.json",
  "packages",
  "scripts",
];

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `${command} failed.`);
  }
  return result.stdout;
}

function rejectLinks(directory) {
  for (const name of readdirSync(directory)) {
    const path = resolve(directory, name);
    const stats = lstatSync(path);
    if (stats.isSymbolicLink()) {
      throw new Error(`Release source contains a symbolic link: ${path.slice(stage.length + 1)}`);
    }
    if (stats.isDirectory()) rejectLinks(path);
  }
}

mkdirSync(releaseDir, { recursive: true, mode: 0o700 });
try {
  for (const entry of entries) {
    if (!existsSync(join(root, entry))) throw new Error(`Release entry is missing: ${entry}`);
  }
  const sourceArchive = join(stage, "source.tar");
  run("git", [
    "archive",
    "--format=tar",
    `--output=${sourceArchive}`,
    "HEAD",
    "--",
    ...entries,
  ]);
  run("tar", ["-xf", sourceArchive, "-C", stage]);
  rmSync(sourceArchive, { force: true });
  rejectLinks(stage);

  const version = JSON.parse(readFileSync(join(stage, "package.json"), "utf8")).version;
  const archive = join(releaseDir, `openvc-os-${version}.tar.gz`);
  const commit = run("git", ["rev-parse", "HEAD"]).trim();
  writeFileSync(join(stage, "SOURCE_COMMIT"), `${commit}\n`, { mode: 0o600 });
  const audit = spawnSync("node", ["scripts/security-audit.mjs"], {
    cwd: stage,
    encoding: "utf8",
  });
  if (audit.status !== 0) throw new Error(audit.stderr || audit.stdout);
  run("tar", ["-czf", archive, "-C", stage, "."], {
    env: { ...process.env, COPYFILE_DISABLE: "1" },
  });
  const checksum = createHash("sha256").update(readFileSync(archive)).digest("hex");
  writeFileSync(`${archive}.sha256`, `${checksum}  ${basename(archive)}\n`, { mode: 0o600 });
  console.log(`Clean release created from ${commit}: ${archive}`);
} finally {
  rmSync(stage, { recursive: true, force: true });
}
