import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { basename, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const version = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")).version;
const releaseDir = resolve(root, "releases");
const outputPath = resolve(releaseDir, `openvc-os-${version}.cdx.json`);

mkdirSync(releaseDir, { recursive: true, mode: 0o700 });
chmodSync(releaseDir, 0o700);

const generated = spawnSync(
  "npm",
  ["sbom", "--sbom-format", "cyclonedx", "--omit=dev"],
  {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  },
);
if (generated.status !== 0) {
  throw new Error(generated.stderr || generated.stdout || "SBOM generation failed.");
}
const sbom = JSON.parse(generated.stdout);
if (sbom.bomFormat !== "CycloneDX" || !Array.isArray(sbom.components)) {
  throw new Error("Generated SBOM is not a valid CycloneDX document.");
}
const serialized = `${JSON.stringify(sbom, null, 2)}\n`;
writeFileSync(outputPath, serialized, { mode: 0o600 });
chmodSync(outputPath, 0o600);
const checksum = createHash("sha256").update(serialized).digest("hex");
writeFileSync(
  `${outputPath}.sha256`,
  `${checksum}  ${basename(outputPath)}\n`,
  { mode: 0o600 },
);
process.stdout.write(`CycloneDX SBOM created: ${outputPath}\n`);
