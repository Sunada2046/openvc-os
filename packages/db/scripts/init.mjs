import { chmodSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const dbPath = resolve(root, process.env.OPENVC_DB_PATH || "storage/openvc.sqlite");

mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });
chmodSync(dirname(dbPath), 0o700);

const db = new DatabaseSync(dbPath);
db.exec(readFileSync(resolve(here, "../schema.sql"), "utf8"));
db.close();
chmodSync(dbPath, 0o600);

console.log(`Initialized empty OpenVC OS database at ${dbPath}`);
