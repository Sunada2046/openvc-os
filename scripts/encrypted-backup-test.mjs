import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";

const root = resolve(import.meta.dirname, "..");
const testRoot = mkdtempSync(resolve(tmpdir(), "openvc-backup-test-"));
const storageDir = resolve(testRoot, "storage");
const backupDir = resolve(testRoot, "backups");
const passphrase = "OpenVC-test-backup-passphrase-2026";
const environment = {
  ...process.env,
  OPENVC_STORAGE_DIR: storageDir,
  OPENVC_DB_PATH: resolve(storageDir, "openvc.sqlite"),
  OPENVC_UPLOAD_DIR: resolve(storageDir, "uploads"),
  OPENVC_BACKUP_DIR: backupDir,
  OPENVC_BACKUP_PASSPHRASE: passphrase,
};

try {
  execFileSync(process.execPath, [resolve(root, "packages/db/scripts/init.mjs")], {
    cwd: root,
    env: environment,
  });
  const database = new DatabaseSync(resolve(storageDir, "openvc.sqlite"));
  database.prepare(`
    INSERT INTO organizations (id, name, slug) VALUES ('org_test', 'Backup test', 'backup-test')
  `).run();
  database.close();
  const backupPath = execFileSync(
    process.execPath,
    [resolve(root, "scripts/backup-encrypted.mjs")],
    { cwd: root, env: environment, encoding: "utf8" },
  ).trim();
  if (!existsSync(backupPath)) throw new Error("Encrypted backup was not created.");

  rmSync(storageDir, { recursive: true, force: true });
  execFileSync(
    process.execPath,
    [
      resolve(root, "scripts/restore-encrypted.mjs"),
      `--file=${backupPath}`,
      "--confirm-replace-storage",
    ],
    { cwd: root, env: environment },
  );
  const restored = new DatabaseSync(resolve(storageDir, "openvc.sqlite"), { readOnly: true });
  const organization = restored.prepare("SELECT name FROM organizations WHERE id = 'org_test'").get();
  restored.close();
  if (organization?.name !== "Backup test") throw new Error("Restored database did not match.");

  const tamperedPath = resolve(testRoot, "tampered.ovcbak");
  const tampered = readFileSync(backupPath);
  tampered[tampered.length - 1] ^= 0xff;
  writeFileSync(tamperedPath, tampered);
  let tamperRejected = false;
  try {
    execFileSync(
      process.execPath,
      [
        resolve(root, "scripts/restore-encrypted.mjs"),
        `--file=${tamperedPath}`,
        "--confirm-replace-storage",
      ],
      { cwd: root, env: environment, stdio: "pipe" },
    );
  } catch {
    tamperRejected = true;
  }
  if (!tamperRejected) throw new Error("Tampered backup was accepted.");
  process.stdout.write("Encrypted backup test passed: round trip and tamper rejection.\n");
} finally {
  rmSync(testRoot, { recursive: true, force: true });
}
