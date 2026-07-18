import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const temp = mkdtempSync(resolve(tmpdir(), "openvc-network-config-"));

try {
  const result = spawnSync(process.execPath, ["apps/api/src/server.mjs"], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      OPENVC_HOST: "0.0.0.0",
      OPENVC_PORT: "0",
      OPENVC_STORAGE_DIR: temp,
      OPENVC_DB_PATH: resolve(temp, "openvc.sqlite"),
      OPENVC_UPLOAD_DIR: resolve(temp, "uploads"),
      OPENVC_COOKIE_SECURE: "false",
      OPENVC_ALLOWED_ORIGINS: "",
    },
    timeout: 10_000,
  });

  assert.notEqual(result.status, 0, "Unsafe non-loopback configuration must fail closed.");
  assert.match(
    `${result.stdout}\n${result.stderr}`,
    /Non-loopback API binding requires OPENVC_COOKIE_SECURE=true/,
  );
  console.log("Network configuration fail-closed test passed.");
} finally {
  rmSync(temp, { recursive: true, force: true });
}
