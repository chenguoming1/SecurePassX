#!/usr/bin/env node
/**
 * Decrypt an automated SecurePassX backup (.db.enc) back into a SQLite file.
 *
 * Backup format: [12-byte IV][16-byte GCM tag][ciphertext]
 * Key: HKDF-SHA256(masterKey, info="securepassx/backup/v1"), where
 *      masterKey = SHA256(DB_ENCRYPTION_KEY or contents of securepassx.key)
 *
 * Usage:
 *   DB_ENCRYPTION_KEY=... node scripts/decrypt-backup.mjs backup.db.enc out.db
 *   node scripts/decrypt-backup.mjs backup.db.enc out.db /path/to/securepassx.key
 */

import crypto from "crypto";
import fs from "fs";

const [, , inFile, outFile, keyFile] = process.argv;

if (!inFile || !outFile) {
  console.error("Usage: decrypt-backup.mjs <backup.db.enc> <out.db> [keyfile]");
  process.exit(1);
}

let material = process.env.DB_ENCRYPTION_KEY;
if (!material && keyFile) {
  material = fs.readFileSync(keyFile, "utf8").trim();
}
if (!material) {
  console.error("Provide DB_ENCRYPTION_KEY env var or a key file path as the 3rd argument.");
  process.exit(1);
}

const masterKey = crypto.createHash("sha256").update(material).digest();
const backupKey = Buffer.from(
  crypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), Buffer.from("securepassx/backup/v1"), 32)
);

const blob = fs.readFileSync(inFile);
const iv = blob.subarray(0, 12);
const tag = blob.subarray(12, 28);
const ciphertext = blob.subarray(28);

const decipher = crypto.createDecipheriv("aes-256-gcm", backupKey, iv);
decipher.setAuthTag(tag);
const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

fs.writeFileSync(outFile, plain, { mode: 0o600 });
console.log(`Decrypted ${inFile} -> ${outFile} (${plain.length} bytes)`);
