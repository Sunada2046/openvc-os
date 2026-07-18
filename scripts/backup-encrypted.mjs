import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createCipheriv, randomBytes, scryptSync } from "node:crypto";
import { backup, DatabaseSync } from "node:sqlite";
import { execFileSync } from "node:child_process";
import { basename, dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const storageDir = resolve(root, process.env.OPENVC_STORAGE_DIR || "storage");
const dbPath = resolve(root, process.env.OPENVC_DB_PATH || "storage/openvc.sqlite");
const uploadDir = resolve(root, process.env.OPENVC_UPLOAD_DIR || "storage/uploads");
const backupDir = resolve(root, process.env.OPENVC_BACKUP_DIR || "backups");
const passphrase = String(process.env.OPENVC_BACKUP_PASSPHRASE || "");

if (passphrase.length < 16) {
  throw new Error("OPENVC_BACKUP_PASSPHRASE must contain at least 16 characters.");
}
if (!existsSync(dbPath)) {
  throw new Error(`Database not found: ${dbPath}`);
}

mkdirSync(backupDir, { recursive: true, mode: 0o700 });
chmodSync(backupDir, 0o700);

const temporaryDirectory = mkdtempSync(resolve(tmpdir(), "openvc-backup-"));
const stagingDirectory = resolve(temporaryDirectory, "payload");
mkdirSync(stagingDirectory, { mode: 0o700 });

try {
  const manifest = {
    format: "openvc-encrypted-backup",
    version: 1,
    createdAt: new Date().toISOString(),
    database: "openvc.sqlite",
    uploads: existsSync(uploadDir) ? "uploads" : null,
    connectorSecretsKey: existsSync(resolve(storageDir, "connector-secrets.key"))
      ? "connector-secrets.key"
      : null,
  };

  const sourceDatabase = new DatabaseSync(dbPath, { readOnly: true });
  try {
    await backup(sourceDatabase, resolve(stagingDirectory, "openvc.sqlite"));
  } finally {
    sourceDatabase.close();
  }
  if (manifest.uploads) {
    execFileSync("cp", ["-R", uploadDir, resolve(stagingDirectory, "uploads")]);
  }
  if (manifest.connectorSecretsKey) {
    execFileSync("cp", [
      "-p",
      resolve(storageDir, "connector-secrets.key"),
      resolve(stagingDirectory, "connector-secrets.key"),
    ]);
  }
  writeFileSync(
    resolve(stagingDirectory, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    { mode: 0o600 },
  );

  const archivePath = resolve(temporaryDirectory, "payload.tar.gz");
  execFileSync("tar", ["-czf", archivePath, "-C", stagingDirectory, "."], {
    env: { ...process.env, COPYFILE_DISABLE: "1" },
  });
  const plaintext = readFileSync(archivePath);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const output = Buffer.concat([
    Buffer.from("OPENVCBK1"),
    salt,
    iv,
    tag,
    ciphertext,
  ]);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outputPath = resolve(backupDir, `openvc-${stamp}.ovcbak`);
  writeFileSync(outputPath, output, { mode: 0o600 });
  chmodSync(outputPath, 0o600);
  process.stdout.write(`${outputPath}\n`);
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
