import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const releaseDir = join(root, "releases");
const stage = mkdtempSync(join(tmpdir(), "openvc-release-"));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const archive = join(releaseDir, `openvc-os-${version}.tar.gz`);
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

mkdirSync(releaseDir, { recursive: true, mode: 0o700 });
try {
  for (const entry of entries) {
    if (!existsSync(join(root, entry))) throw new Error(`Release entry is missing: ${entry}`);
    cpSync(join(root, entry), join(stage, entry), {
      recursive: true,
      filter(source) {
        const relative = source.slice(root.length + 1);
        return !relative.split("/").some((part) =>
          ["node_modules", "dist", "storage", "releases"].includes(part));
      },
    });
  }
  const audit = spawnSync("node", ["scripts/security-audit.mjs"], {
    cwd: stage,
    encoding: "utf8",
  });
  if (audit.status !== 0) throw new Error(audit.stderr || audit.stdout);
  const packed = spawnSync("tar", ["-czf", archive, "-C", stage, "."], {
    cwd: root,
    encoding: "utf8",
  });
  if (packed.status !== 0) throw new Error(packed.stderr || packed.stdout);
  const checksum = createHash("sha256").update(readFileSync(archive)).digest("hex");
  writeFileSync(`${archive}.sha256`, `${checksum}  ${basename(archive)}\n`, { mode: 0o600 });
  console.log(`Clean release created: ${archive}`);
} finally {
  rmSync(stage, { recursive: true, force: true });
}
