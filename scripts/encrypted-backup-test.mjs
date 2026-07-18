import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { createCipheriv, randomBytes, scryptSync } from "node:crypto";
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

  const maliciousPayload = resolve(testRoot, "malicious-payload");
  const maliciousUploads = resolve(maliciousPayload, "uploads");
  const externalTarget = resolve(testRoot, "external-target");
  mkdirSync(maliciousUploads, { recursive: true });
  mkdirSync(externalTarget);
  execFileSync("cp", [
    resolve(storageDir, "openvc.sqlite"),
    resolve(maliciousPayload, "openvc.sqlite"),
  ]);
  writeFileSync(
    resolve(maliciousPayload, "manifest.json"),
    JSON.stringify({
      format: "openvc-encrypted-backup",
      version: 1,
      database: "openvc.sqlite",
      uploads: "uploads",
      connectorSecretsKey: null,
    }),
  );
  symlinkSync(externalTarget, resolve(maliciousUploads, "org_test"), "dir");
  const maliciousArchive = resolve(testRoot, "malicious.tar.gz");
  execFileSync("tar", ["-czf", maliciousArchive, "-C", maliciousPayload, "."]);
  const plaintext = readFileSync(maliciousArchive);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const maliciousBackup = resolve(testRoot, "malicious.ovcbak");
  writeFileSync(maliciousBackup, Buffer.concat([
    Buffer.from("OPENVCBK1"),
    salt,
    iv,
    cipher.getAuthTag(),
    ciphertext,
  ]));
  let symlinkRejected = false;
  try {
    execFileSync(
      process.execPath,
      [
        resolve(root, "scripts/restore-encrypted.mjs"),
        `--file=${maliciousBackup}`,
        "--confirm-replace-storage",
      ],
      { cwd: root, env: environment, stdio: "pipe" },
    );
  } catch {
    symlinkRejected = true;
  }
  if (!symlinkRejected) throw new Error("Backup containing a symbolic link was accepted.");
  process.stdout.write(
    "Encrypted backup test passed: consistent snapshot, round trip, tamper rejection, and link rejection.\n",
  );
} finally {
  rmSync(testRoot, { recursive: true, force: true });
}
