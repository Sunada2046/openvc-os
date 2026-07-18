import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createDecipheriv, scryptSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const storageDir = resolve(root, process.env.OPENVC_STORAGE_DIR || "storage");
const passphrase = String(process.env.OPENVC_BACKUP_PASSPHRASE || "");
const fileArgument = process.argv.find((argument) => argument.startsWith("--file="));
const confirmed = process.argv.includes("--confirm-replace-storage");

if (!fileArgument || !confirmed) {
  throw new Error(
    "Use --file=/absolute/path/to/backup.ovcbak --confirm-replace-storage. Stop the API first.",
  );
}
if (passphrase.length < 16) {
  throw new Error("OPENVC_BACKUP_PASSPHRASE must contain at least 16 characters.");
}

const backupPath = resolve(fileArgument.slice("--file=".length));
const bytes = readFileSync(backupPath);
const magic = bytes.subarray(0, 9).toString("utf8");
if (magic !== "OPENVCBK1" || bytes.length < 54) {
  throw new Error("Unsupported or corrupt backup file.");
}

const salt = bytes.subarray(9, 25);
const iv = bytes.subarray(25, 37);
const tag = bytes.subarray(37, 53);
const ciphertext = bytes.subarray(53);
const key = scryptSync(passphrase, salt, 32);
const decipher = createDecipheriv("aes-256-gcm", key, iv);
decipher.setAuthTag(tag);

let plaintext;
try {
  plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
} catch {
  throw new Error("Backup authentication failed. The passphrase is wrong or the file was modified.");
}

const temporaryDirectory = mkdtempSync(resolve(tmpdir(), "openvc-restore-"));
const archivePath = resolve(temporaryDirectory, "payload.tar.gz");
const extractedDirectory = resolve(temporaryDirectory, "payload");
mkdirSync(extractedDirectory, { mode: 0o700 });

try {
  writeFileSync(archivePath, plaintext, { mode: 0o600 });
  const tarEnvironment = { ...process.env, COPYFILE_DISABLE: "1" };
  const entries = execFileSync("tar", ["-tzf", archivePath], {
    encoding: "utf8",
    env: tarEnvironment,
  })
    .split(/\r?\n/)
    .filter(Boolean);
  const normalizedEntries = entries.map((entry) =>
    entry.replace(/^\.\//, "").replace(/\/$/, "")).filter(Boolean);
  if (
    entries.length > 100_000 ||
    normalizedEntries.some((entry) =>
      !entry ||
      entry.startsWith("/") ||
      entry.split("/").some((part) => part === "..") ||
      !(
        entry === "manifest.json" ||
        entry === "openvc.sqlite" ||
        entry === "connector-secrets.key" ||
        entry === "uploads" ||
        entry.startsWith("uploads/")
      ))
  ) {
    throw new Error("Backup contains an unsafe archive path.");
  }
  const verboseEntries = execFileSync("tar", ["-tvzf", archivePath], {
    encoding: "utf8",
    env: tarEnvironment,
  }).split(/\r?\n/).filter(Boolean);
  if (verboseEntries.some((entry) => !["-", "d"].includes(entry.trimStart()[0]))) {
    throw new Error("Backup contains a link or unsupported archive entry.");
  }
  execFileSync("tar", ["-xzf", archivePath, "-C", extractedDirectory], {
    env: tarEnvironment,
  });

  function secureExtractedTree(directory) {
    for (const name of readdirSync(directory)) {
      const path = resolve(directory, name);
      const stats = lstatSync(path);
      if (stats.isSymbolicLink() || (!stats.isDirectory() && !stats.isFile())) {
        throw new Error("Backup extracted an unsupported filesystem entry.");
      }
      if (stats.isDirectory()) {
        chmodSync(path, 0o700);
        secureExtractedTree(path);
      } else {
        chmodSync(path, 0o600);
      }
    }
  }
  secureExtractedTree(extractedDirectory);
  const manifestPath = resolve(extractedDirectory, "manifest.json");
  const databasePath = resolve(extractedDirectory, "openvc.sqlite");
  if (!existsSync(manifestPath) || !existsSync(databasePath)) {
    throw new Error("Backup is missing its manifest or database.");
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.format !== "openvc-encrypted-backup" || manifest.version !== 1) {
    throw new Error("Backup manifest is not supported.");
  }

  const previousDirectory = `${storageDir}.before-restore-${Date.now()}`;
  if (existsSync(storageDir)) renameSync(storageDir, previousDirectory);
  try {
    mkdirSync(storageDir, { recursive: true, mode: 0o700 });
    execFileSync("cp", ["-p", databasePath, resolve(storageDir, "openvc.sqlite")]);
    if (existsSync(resolve(extractedDirectory, "uploads"))) {
      execFileSync("cp", [
        "-R",
        resolve(extractedDirectory, "uploads"),
        resolve(storageDir, "uploads"),
      ]);
    }
    if (existsSync(resolve(extractedDirectory, "connector-secrets.key"))) {
      execFileSync("cp", [
        "-p",
        resolve(extractedDirectory, "connector-secrets.key"),
        resolve(storageDir, "connector-secrets.key"),
      ]);
    }
    chmodSync(storageDir, 0o700);
    chmodSync(resolve(storageDir, "openvc.sqlite"), 0o600);
    if (existsSync(resolve(storageDir, "connector-secrets.key"))) {
      chmodSync(resolve(storageDir, "connector-secrets.key"), 0o600);
    }
    if (existsSync(resolve(storageDir, "uploads"))) {
      secureExtractedTree(resolve(storageDir, "uploads"));
    }
  } catch (error) {
    rmSync(storageDir, { recursive: true, force: true });
    if (existsSync(previousDirectory)) renameSync(previousDirectory, storageDir);
    throw error;
  }
  process.stdout.write(
    `Restore completed. Previous storage retained at ${previousDirectory}\n`,
  );
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
