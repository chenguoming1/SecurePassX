/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express, { Request, Response, NextFunction } from "express";
import path from "path";
import crypto from "crypto";
import sqlite3 from "sqlite3";
import { open, Database } from "sqlite";
import { createServer as createViteServer } from "vite";
import fs from "fs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/server";

interface AuthenticatedRequest extends Request {
  userId?: number;
  userUsername?: string;
}

const IS_PRODUCTION = process.env.NODE_ENV === "production";
const DEFAULT_KDF_ITERATIONS = 600_000;
const MIN_KDF_ITERATIONS = 100_000;
const MAX_KDF_ITERATIONS = 5_000_000;
const TOKEN_TTL = "8h";

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------
// Master key material comes from DB_ENCRYPTION_KEY. If unset, a random key is
// generated once and persisted next to the database (never a hardcoded
// default). All working keys are derived from the master key via HKDF so the
// at-rest key, JWT secret, and backup key are independent.

const dbPath = process.env.DB_PATH || "./securepassx.db";
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

function loadMasterKeyMaterial(): string {
  const fromEnv = process.env.DB_ENCRYPTION_KEY;
  if (fromEnv && fromEnv.trim().length >= 16) {
    return fromEnv;
  }
  if (fromEnv) {
    console.error("FATAL: DB_ENCRYPTION_KEY must be at least 16 characters.");
    process.exit(1);
  }

  const keyFilePath = path.join(dbDir, "securepassx.key");
  if (fs.existsSync(keyFilePath)) {
    const material = fs.readFileSync(keyFilePath, "utf8").trim();
    if (material.length < 32) {
      console.error(`FATAL: key file ${keyFilePath} is corrupt or too short.`);
      process.exit(1);
    }
    return material;
  }

  const generated = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(keyFilePath, generated, { mode: 0o600 });
  console.warn(
    `WARNING: DB_ENCRYPTION_KEY not set. A random key was generated and saved to ${keyFilePath}. ` +
      "Back this file up: without it (or the env var) the database cannot be decrypted."
  );
  return generated;
}

const MASTER_KEY = crypto.createHash("sha256").update(loadMasterKeyMaterial()).digest();

function deriveSubKey(info: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync("sha256", MASTER_KEY, Buffer.alloc(0), Buffer.from(info, "utf8"), 32)
  );
}

const DATA_KEY = deriveSubKey("securepassx/at-rest/v2");
const JWT_SECRET = deriveSubKey("securepassx/jwt/v1");
const BACKUP_KEY = deriveSubKey("securepassx/backup/v1");
const DECOY_KEY = deriveSubKey("securepassx/salt-decoy/v1");

// Legacy key (v1 CBC data written by older builds) - reads only.
const LEGACY_KEY = crypto
  .createHash("sha256")
  .update(process.env.DB_ENCRYPTION_KEY || "securepassx_offline_default_salt_2026")
  .digest();

// ---------------------------------------------------------------------------
// At-rest encryption: AES-256-GCM (authenticated). Legacy CBC still readable.
// ---------------------------------------------------------------------------

function dbEncrypt(text: string): string {
  if (!text) return "";
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", DATA_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v2:${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

function dbDecrypt(cipherText: string): string {
  if (!cipherText) return "";
  try {
    if (cipherText.startsWith("v2:")) {
      const [, ivHex, tagHex, dataHex] = cipherText.split(":");
      const decipher = crypto.createDecipheriv("aes-256-gcm", DATA_KEY, Buffer.from(ivHex, "hex"));
      decipher.setAuthTag(Buffer.from(tagHex, "hex"));
      return Buffer.concat([
        decipher.update(Buffer.from(dataHex, "hex")),
        decipher.final(),
      ]).toString("utf8");
    }

    // Legacy v1 format: <ivHex>:<cipherHex> with AES-256-CBC (unauthenticated)
    const parts = cipherText.split(":");
    if (parts.length !== 2) return "";
    const decipher = crypto.createDecipheriv("aes-256-cbc", LEGACY_KEY, Buffer.from(parts[0], "hex"));
    return Buffer.concat([
      decipher.update(Buffer.from(parts[1], "hex")),
      decipher.final(),
    ]).toString("utf8");
  } catch (err) {
    console.error("DB decryption failed");
    return "";
  }
}

// ---------------------------------------------------------------------------
// Server-side auth-key storage: scrypt (one-way, per-user salt)
// Format: s2$<saltHex>$<hashHex>
// ---------------------------------------------------------------------------

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function hashAuthKey(clientAuthHash: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(clientAuthHash, salt, 64, SCRYPT_PARAMS);
  return `s2$${salt.toString("hex")}$${hash.toString("hex")}`;
}

function verifyAuthKey(clientAuthHash: string, stored: string): boolean {
  try {
    if (stored.startsWith("s2$")) {
      const [, saltHex, hashHex] = stored.split("$");
      const expected = Buffer.from(hashHex, "hex");
      const actual = crypto.scryptSync(clientAuthHash, Buffer.from(saltHex, "hex"), expected.length, SCRYPT_PARAMS);
      return crypto.timingSafeEqual(actual, expected);
    }
    // Legacy: reversible dbEncrypt(hash). Compare via fixed-length digests.
    const legacyPlain = dbDecrypt(stored);
    if (!legacyPlain) return false;
    return crypto.timingSafeEqual(
      crypto.createHash("sha256").update(legacyPlain).digest(),
      crypto.createHash("sha256").update(clientAuthHash).digest()
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Sessions: signed JWT (HS256) with revocation via jti blacklist
// ---------------------------------------------------------------------------

function generateSessionToken(userId: number, username: string): string {
  return jwt.sign({ sub: String(userId), username, jti: crypto.randomUUID() }, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: TOKEN_TTL,
  });
}

// ---------------------------------------------------------------------------
// WebAuthn challenge store (single-instance, in-memory, 5 min TTL)
// ---------------------------------------------------------------------------

const challengeStore = new Map<string, { challenge: string; expires: number }>();

function putChallenge(key: string, challenge: string): void {
  challengeStore.set(key, { challenge, expires: Date.now() + 5 * 60 * 1000 });
}

function takeChallenge(key: string): string | null {
  const entry = challengeStore.get(key);
  challengeStore.delete(key);
  if (!entry || entry.expires < Date.now()) return null;
  return entry.challenge;
}

function getRpParams(req: Request): { rpID: string; origin: string } {
  const origin = (req.headers.origin as string) || `${req.protocol}://${req.get("host")}`;
  const rpID = new URL(origin).hostname;
  return { rpID, origin };
}

function usernameHashOf(username: string): string {
  return crypto.createHash("sha256").update(username.trim().toLowerCase()).digest("hex");
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238, SHA-1, 6 digits, 30s period)
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function hotp(secret: Buffer, counter: number): string {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", secret).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return String(code % 1_000_000).padStart(6, "0");
}

/**
 * Verify a TOTP code within a +/-1 step window. Returns the matched counter
 * (for replay protection) or null. Codes at counters <= lastCounter are
 * rejected so each code can only be used once.
 */
function verifyTotpCode(secretHex: string, code: string, lastCounter: number): number | null {
  const secret = Buffer.from(secretHex, "hex");
  const current = Math.floor(Date.now() / 1000 / 30);
  const normalized = String(code).replace(/\s+/g, "");
  if (!/^\d{6}$/.test(normalized)) return null;
  for (const counter of [current, current - 1, current + 1]) {
    if (counter <= lastCounter) continue;
    const expected = hotp(secret, counter);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(normalized))) {
      return counter;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Account lockout policy
// ---------------------------------------------------------------------------
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

// ---------------------------------------------------------------------------
// Device sync: sealed transport. Every sync request/response body is
// AES-256-GCM encrypted with a key derived from the shared pairing secret,
// so sync works safely even over plain HTTP on a LAN/VPN. Payloads carry a
// timestamp to bound replays. Note the vault data inside is E2EE blobs
// anyway - peers never exchange plaintext passwords.
// ---------------------------------------------------------------------------

const SYNC_TS_SKEW_MS = 5 * 60 * 1000;
const SYNC_INTERVAL_MS = 5 * 60 * 1000;

function syncKeyFrom(secretHex: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync("sha256", Buffer.from(secretHex, "hex"), Buffer.alloc(0), Buffer.from("securepassx/sync/v1"), 32)
  );
}

function syncSeal(payload: unknown, secretHex: string): { iv: string; tag: string; data: string } {
  const key = syncKeyFrom(secretHex);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return { iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), data: encrypted.toString("hex") };
}

function syncOpen(body: any, secretHex: string): any | null {
  try {
    const key = syncKeyFrom(secretHex);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(body.iv, "hex"));
    decipher.setAuthTag(Buffer.from(body.tag, "hex"));
    const plain = Buffer.concat([decipher.update(Buffer.from(body.data, "hex")), decipher.final()]).toString("utf8");
    const payload = JSON.parse(plain);
    if (!payload.ts || Math.abs(Date.now() - payload.ts) > SYNC_TS_SKEW_MS) return null;
    return payload;
  } catch {
    return null;
  }
}

async function startServer() {
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json({ limit: "256kb" }));

  // Security headers. CSP only in production (the Vite dev client needs inline scripts).
  app.use(
    helmet({
      contentSecurityPolicy: IS_PRODUCTION
        ? {
            directives: {
              defaultSrc: ["'self'"],
              scriptSrc: ["'self'"],
              styleSrc: ["'self'", "'unsafe-inline'"],
              imgSrc: ["'self'", "data:"],
              objectSrc: ["'none'"],
              frameAncestors: ["'none'"],
            },
          }
        : false,
      hsts: IS_PRODUCTION ? { maxAge: 31536000, includeSubDomains: true } : false,
      crossOriginEmbedderPolicy: false,
    })
  );

  // HTTPS enforcement is opt-in (FORCE_HTTPS=true) for deployments behind a
  // TLS reverse proxy. Left off by default so direct LAN/Tailscale access
  // over plain HTTP isn't redirected to a nonexistent HTTPS listener.
  if (IS_PRODUCTION && process.env.FORCE_HTTPS === "true") {
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (req.secure || req.headers["x-forwarded-proto"] === "https" || req.hostname === "localhost") {
        return next();
      }
      res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
    });
  }

  // Brute-force protection
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many authentication attempts. Try again later." },
  });
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 600,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests." },
  });
  app.use("/api/auth", authLimiter);
  app.use("/api", apiLimiter);

  const PORT = 3000;

  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database,
  });

  await db.exec("PRAGMA foreign_keys = ON;");

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username_hash TEXT UNIQUE,
      username_enc TEXT,
      salt TEXT,
      password_hash TEXT,
      biometric_credential_id TEXT,
      biometric_public_key TEXT,
      created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      title_enc TEXT,
      username_enc TEXT,
      password_enc TEXT,
      url_enc TEXT,
      notes_enc TEXT,
      category_enc TEXT,
      iv TEXT,
      modified_at INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      action TEXT,
      item_name TEXT,
      timestamp INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti TEXT PRIMARY KEY,
      expires_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      cred_id TEXT,
      pubkey TEXT,
      counter INTEGER DEFAULT 0,
      transports TEXT,
      label TEXT,
      created_at INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS tombstones (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      deleted_at INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS sync_config (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      role TEXT,
      peer_url TEXT,
      username_hash TEXT,
      secret_enc TEXT,
      pull_since INTEGER DEFAULT 0,
      push_since INTEGER DEFAULT 0,
      last_sync_at INTEGER DEFAULT 0,
      last_sync_error TEXT
    );
  `);

  // Idempotent column migrations for older databases
  const migrations = [
    "ALTER TABLE users ADD COLUMN kdf_iterations INTEGER",
    "ALTER TABLE users ADD COLUMN webauthn_cred_id TEXT",
    "ALTER TABLE users ADD COLUMN webauthn_pubkey TEXT",
    "ALTER TABLE users ADD COLUMN webauthn_counter INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN webauthn_transports TEXT",
    "ALTER TABLE audit_logs ADD COLUMN iv TEXT",
    "ALTER TABLE users ADD COLUMN totp_secret_enc TEXT",
    "ALTER TABLE users ADD COLUMN totp_pending_enc TEXT",
    "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN totp_last_counter INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN lock_until INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN updated_at INTEGER DEFAULT 0",
  ];
  for (const migration of migrations) {
    try {
      await db.exec(migration);
    } catch {
      /* column already exists */
    }
  }

  // One-time migration: move single-credential columns into the
  // multi-credential table.
  const legacyCredUsers = await db.all(
    "SELECT id, webauthn_cred_id, webauthn_pubkey, webauthn_counter, webauthn_transports FROM users WHERE webauthn_cred_id IS NOT NULL"
  );
  for (const u of legacyCredUsers) {
    await db.run(
      `INSERT INTO webauthn_credentials (user_id, cred_id, pubkey, counter, transports, label, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [u.id, u.webauthn_cred_id, u.webauthn_pubkey, u.webauthn_counter || 0, u.webauthn_transports, dbEncrypt("Migrated device"), Date.now()]
    );
    await db.run("UPDATE users SET webauthn_cred_id = NULL, webauthn_pubkey = NULL WHERE id = ?", [u.id]);
  }

  // Server-generated audit entries (auth events). Stored encrypted at rest;
  // iv stays NULL so the client renders them as plain (non-E2EE) messages.
  async function serverAudit(userId: number, action: string, message: string): Promise<void> {
    try {
      await db.run(
        "INSERT INTO audit_logs (id, user_id, action, item_name, timestamp) VALUES (?, ?, ?, ?, ?)",
        [crypto.randomUUID(), userId, dbEncrypt(action), dbEncrypt(message), Date.now()]
      );
    } catch {
      /* never block auth on audit failure */
    }
  }

  // Record a failed auth attempt; lock the account after too many.
  async function recordAuthFailure(userId: number, what: string): Promise<void> {
    const user = await db.get("SELECT failed_attempts FROM users WHERE id = ?", [userId]);
    const failures = (user?.failed_attempts || 0) + 1;
    if (failures >= MAX_FAILED_ATTEMPTS) {
      await db.run("UPDATE users SET failed_attempts = 0, lock_until = ? WHERE id = ?", [
        Date.now() + LOCKOUT_MS,
        userId,
      ]);
      await serverAudit(userId, "account_locked", `Account locked for 15 minutes after ${MAX_FAILED_ATTEMPTS} failed attempts`);
    } else {
      await db.run("UPDATE users SET failed_attempts = ? WHERE id = ?", [failures, userId]);
    }
    await serverAudit(userId, "login_failed", what);
  }

  console.log("Secure SQLite database initialized successfully.");

  // Purge expired revocations periodically
  const purgeRevoked = () =>
    db.run("DELETE FROM revoked_tokens WHERE expires_at < ?", [Date.now()]).catch(() => {});
  purgeRevoked();
  setInterval(purgeRevoked, 60 * 60 * 1000).unref?.();

  // -------------------------------------------------------------------------
  // Auth middleware
  // -------------------------------------------------------------------------
  async function authenticateToken(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      res.status(401).json({ error: "Authentication token is required." });
      return;
    }

    try {
      const payload = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] }) as jwt.JwtPayload;
      if (!payload.sub || !payload.jti) {
        res.status(403).json({ error: "Invalid session token." });
        return;
      }
      const revoked = await db.get("SELECT jti FROM revoked_tokens WHERE jti = ?", [payload.jti]);
      if (revoked) {
        res.status(403).json({ error: "Session has been revoked." });
        return;
      }
      req.userId = Number(payload.sub);
      req.userUsername = payload.username as string;
      (req as any).tokenJti = payload.jti;
      (req as any).tokenExp = payload.exp;
      next();
    } catch {
      res.status(403).json({ error: "Invalid or expired session token." });
    }
  }

  // -------------------------------------------------------------------------
  // API ROUTE: Fetch Username Salt + KDF params
  // Returns a deterministic decoy for unknown users to prevent enumeration.
  // -------------------------------------------------------------------------
  app.post("/api/auth/salt", async (req: Request, res: Response) => {
    try {
      const { username } = req.body;
      if (!username || typeof username !== "string") {
        res.status(400).json({ error: "Username is required." });
        return;
      }

      const usernameHash = usernameHashOf(username);
      const user = await db.get("SELECT salt, kdf_iterations FROM users WHERE username_hash = ?", [
        usernameHash,
      ]);

      if (!user) {
        // Deterministic decoy: same username always yields the same fake salt.
        const decoy = crypto
          .createHmac("sha256", DECOY_KEY)
          .update(usernameHash)
          .digest()
          .subarray(0, 16)
          .toString("base64");
        res.json({ salt: decoy, iterations: DEFAULT_KDF_ITERATIONS });
        return;
      }

      res.json({
        salt: dbDecrypt(user.salt),
        iterations: user.kdf_iterations || MIN_KDF_ITERATIONS,
      });
    } catch (error) {
      console.error("Fetch salt error:", error);
      res.status(500).json({ error: "Internal server authentication error." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Registration
  // -------------------------------------------------------------------------
  app.post("/api/auth/register", async (req: Request, res: Response) => {
    try {
      const { username, salt, passwordHash, iterations } = req.body;
      if (!username || !salt || !passwordHash) {
        res.status(400).json({ error: "Username, salt, and verification credentials are required." });
        return;
      }

      const kdfIterations = Math.min(
        MAX_KDF_ITERATIONS,
        Math.max(MIN_KDF_ITERATIONS, Number(iterations) || DEFAULT_KDF_ITERATIONS)
      );

      const trimmedUsername = String(username).trim().toLowerCase();
      const usernameHash = usernameHashOf(trimmedUsername);

      const existing = await db.get("SELECT id FROM users WHERE username_hash = ?", [usernameHash]);
      if (existing) {
        res.status(409).json({ error: "Username is already registered." });
        return;
      }

      const result = await db.run(
        `INSERT INTO users (username_hash, username_enc, salt, password_hash, kdf_iterations, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          usernameHash,
          dbEncrypt(trimmedUsername),
          dbEncrypt(salt),
          hashAuthKey(String(passwordHash)),
          kdfIterations,
          Date.now(),
          Date.now(),
        ]
      );

      const userId = result.lastID;
      const token = generateSessionToken(userId!, trimmedUsername);

      res.status(201).json({
        message: "Account master vault created successfully.",
        token,
        userId,
        username: trimmedUsername,
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ error: "Internal server error creating the vault." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Login
  // -------------------------------------------------------------------------
  app.post("/api/auth/login", async (req: Request, res: Response) => {
    try {
      const { username, authKeyHex, totpCode } = req.body;
      if (!username || !authKeyHex) {
        res.status(400).json({ error: "Username and password proof are required." });
        return;
      }

      const trimmedUsername = String(username).trim().toLowerCase();
      const usernameHash = usernameHashOf(trimmedUsername);

      const user = await db.get(
        "SELECT id, username_enc, password_hash, totp_enabled, totp_secret_enc, totp_last_counter, failed_attempts, lock_until FROM users WHERE username_hash = ?",
        [usernameHash]
      );

      // Per-account lockout (independent of IP rate limiting)
      if (user && user.lock_until && user.lock_until > Date.now()) {
        const minutes = Math.ceil((user.lock_until - Date.now()) / 60000);
        res.status(429).json({ error: `Account temporarily locked. Try again in ${minutes} minute(s).` });
        return;
      }

      if (!user || !verifyAuthKey(String(authKeyHex), user.password_hash)) {
        if (user) await recordAuthFailure(user.id, "Master password verification failed");
        res.status(401).json({ error: "Invalid credentials." });
        return;
      }

      // Second factor
      if (user.totp_enabled) {
        if (!totpCode) {
          res.status(401).json({ totpRequired: true, error: "Verification code required." });
          return;
        }
        const matched = verifyTotpCode(dbDecrypt(user.totp_secret_enc), String(totpCode), user.totp_last_counter || 0);
        if (matched === null) {
          await recordAuthFailure(user.id, "Invalid or reused TOTP code");
          res.status(401).json({ totpRequired: true, error: "Invalid verification code." });
          return;
        }
        await db.run("UPDATE users SET totp_last_counter = ? WHERE id = ?", [matched, user.id]);
      }

      // Lazy upgrade of legacy reversible storage to one-way scrypt
      if (!String(user.password_hash).startsWith("s2$")) {
        await db.run("UPDATE users SET password_hash = ? WHERE id = ?", [
          hashAuthKey(String(authKeyHex)),
          user.id,
        ]);
      }

      await db.run("UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE id = ?", [user.id]);
      await serverAudit(user.id, "login_success", "Vault unlocked with master password");

      const credCount = await db.get("SELECT COUNT(*) as n FROM webauthn_credentials WHERE user_id = ?", [user.id]);
      const decryptedUsername = dbDecrypt(user.username_enc);
      const token = generateSessionToken(user.id, decryptedUsername);

      res.json({
        message: "Vault unlocked.",
        token,
        userId: user.id,
        username: decryptedUsername,
        biometricEnabled: (credCount?.n || 0) > 0,
        totpEnabled: !!user.totp_enabled,
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ error: "Internal server login verification error." });
    }
  });

  // -------------------------------------------------------------------------
  // TOTP two-factor authentication
  // -------------------------------------------------------------------------
  app.get("/api/auth/totp/status", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const user = await db.get("SELECT totp_enabled FROM users WHERE id = ?", [req.userId]);
    res.json({ enabled: !!user?.totp_enabled });
  });

  app.post("/api/auth/totp/setup", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const secret = crypto.randomBytes(20);
      await db.run("UPDATE users SET totp_pending_enc = ? WHERE id = ?", [
        dbEncrypt(secret.toString("hex")),
        req.userId,
      ]);
      const base32Secret = base32Encode(secret);
      const label = encodeURIComponent(`SecurePassX:${req.userUsername || "vault"}`);
      res.json({
        secret: base32Secret,
        otpauthUri: `otpauth://totp/${label}?secret=${base32Secret}&issuer=SecurePassX&algorithm=SHA1&digits=6&period=30`,
      });
    } catch (error) {
      console.error("TOTP setup error:", error);
      res.status(500).json({ error: "Failed to initialize two-factor setup." });
    }
  });

  app.post("/api/auth/totp/enable", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { code } = req.body;
      const user = await db.get("SELECT totp_pending_enc FROM users WHERE id = ?", [req.userId]);
      if (!user?.totp_pending_enc) {
        res.status(400).json({ error: "No pending two-factor setup. Start setup first." });
        return;
      }
      const secretHex = dbDecrypt(user.totp_pending_enc);
      const matched = verifyTotpCode(secretHex, String(code || ""), 0);
      if (matched === null) {
        res.status(401).json({ error: "Code does not match. Check your authenticator app." });
        return;
      }
      await db.run(
        "UPDATE users SET totp_secret_enc = ?, totp_pending_enc = NULL, totp_enabled = 1, totp_last_counter = ?, updated_at = ? WHERE id = ?",
        [dbEncrypt(secretHex), matched, Date.now(), req.userId]
      );
      await serverAudit(req.userId!, "totp_enabled", "Two-factor authentication enabled");
      res.json({ success: true });
    } catch (error) {
      console.error("TOTP enable error:", error);
      res.status(500).json({ error: "Failed to enable two-factor authentication." });
    }
  });

  app.post("/api/auth/totp/disable", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { code } = req.body;
      const user = await db.get("SELECT totp_enabled, totp_secret_enc, totp_last_counter FROM users WHERE id = ?", [req.userId]);
      if (!user?.totp_enabled) {
        res.status(400).json({ error: "Two-factor authentication is not enabled." });
        return;
      }
      const matched = verifyTotpCode(dbDecrypt(user.totp_secret_enc), String(code || ""), user.totp_last_counter || 0);
      if (matched === null) {
        res.status(401).json({ error: "Invalid verification code." });
        return;
      }
      await db.run(
        "UPDATE users SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_enabled = 0, totp_last_counter = 0, updated_at = ? WHERE id = ?",
        [Date.now(), req.userId]
      );
      await serverAudit(req.userId!, "totp_disabled", "Two-factor authentication disabled");
      res.json({ success: true });
    } catch (error) {
      console.error("TOTP disable error:", error);
      res.status(500).json({ error: "Failed to disable two-factor authentication." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Logout (revoke current token)
  // -------------------------------------------------------------------------
  app.post("/api/auth/logout", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const jti = (req as any).tokenJti as string;
      const exp = (((req as any).tokenExp as number) || Math.floor(Date.now() / 1000) + 86400) * 1000;
      await db.run("INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)", [jti, exp]);
      res.json({ success: true });
    } catch (error) {
      console.error("Logout error:", error);
      res.status(500).json({ error: "Failed to revoke session." });
    }
  });

  // -------------------------------------------------------------------------
  // WebAuthn: registration (authenticated)
  // -------------------------------------------------------------------------
  app.post(
    "/api/auth/webauthn/register/options",
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const { rpID } = getRpParams(req);
        const existing = await db.all("SELECT cred_id, transports FROM webauthn_credentials WHERE user_id = ?", [
          req.userId,
        ]);
        const options = await generateRegistrationOptions({
          rpName: "SecurePassX",
          rpID,
          userName: req.userUsername || `user-${req.userId}`,
          attestationType: "none",
          excludeCredentials: existing.map((c) => ({
            id: dbDecrypt(c.cred_id),
            transports: JSON.parse(dbDecrypt(c.transports) || "[]"),
          })),
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required",
            residentKey: "preferred",
          },
        });
        putChallenge(`reg:${req.userId}`, options.challenge);
        res.json(options);
      } catch (error) {
        console.error("WebAuthn register options error:", error);
        res.status(500).json({ error: "Failed to create registration challenge." });
      }
    }
  );

  app.post(
    "/api/auth/webauthn/register/verify",
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const { response, label } = req.body as { response: RegistrationResponseJSON; label?: string };
        const expectedChallenge = takeChallenge(`reg:${req.userId}`);
        if (!expectedChallenge) {
          res.status(400).json({ error: "Registration challenge expired. Try again." });
          return;
        }

        const { rpID, origin } = getRpParams(req);
        const verification = await verifyRegistrationResponse({
          response,
          expectedChallenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          requireUserVerification: true,
        });

        if (!verification.verified || !verification.registrationInfo) {
          res.status(400).json({ error: "Biometric registration could not be verified." });
          return;
        }

        const { credential } = verification.registrationInfo;
        await db.run(
          `INSERT INTO webauthn_credentials (user_id, cred_id, pubkey, counter, transports, label, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            req.userId,
            dbEncrypt(credential.id),
            dbEncrypt(Buffer.from(credential.publicKey).toString("base64")),
            credential.counter,
            dbEncrypt(JSON.stringify(credential.transports || [])),
            dbEncrypt(String(label || "Unnamed device").slice(0, 64)),
            Date.now(),
          ]
        );

        await serverAudit(req.userId!, "passkey_added", `Passkey registered: ${String(label || "Unnamed device").slice(0, 64)}`);
        res.json({ verified: true, message: "Biometrics mapped successfully to master vault." });
      } catch (error) {
        console.error("WebAuthn register verify error:", error);
        res.status(400).json({ error: "Biometric registration verification failed." });
      }
    }
  );

  app.get(
    "/api/auth/webauthn/credentials",
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      const rows = await db.all(
        "SELECT id, label, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
        [req.userId]
      );
      res.json(rows.map((r) => ({ id: r.id, label: dbDecrypt(r.label) || "Unnamed device", createdAt: r.created_at })));
    }
  );

  app.delete(
    "/api/auth/webauthn/credentials/:id",
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      const row = await db.get("SELECT id, label FROM webauthn_credentials WHERE id = ? AND user_id = ?", [
        req.params.id,
        req.userId,
      ]);
      if (!row) {
        res.status(404).json({ error: "Passkey not found." });
        return;
      }
      await db.run("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
      await serverAudit(req.userId!, "passkey_removed", `Passkey removed: ${dbDecrypt(row.label) || "Unnamed device"}`);
      res.json({ success: true });
    }
  );

  // -------------------------------------------------------------------------
  // WebAuthn: authentication
  // -------------------------------------------------------------------------
  app.post("/api/auth/webauthn/login/options", async (req: Request, res: Response) => {
    try {
      const { username } = req.body;
      if (!username || typeof username !== "string") {
        res.status(400).json({ error: "Username is required." });
        return;
      }

      const usernameHash = usernameHashOf(username);
      const user = await db.get("SELECT id FROM users WHERE username_hash = ?", [usernameHash]);
      const creds = user
        ? await db.all("SELECT cred_id, transports FROM webauthn_credentials WHERE user_id = ?", [user.id])
        : [];

      if (!user || creds.length === 0) {
        res.status(401).json({ error: "Biometrics not configured on this account." });
        return;
      }

      const { rpID } = getRpParams(req);
      const options = await generateAuthenticationOptions({
        rpID,
        userVerification: "required",
        allowCredentials: creds.map((c) => ({
          id: dbDecrypt(c.cred_id),
          transports: JSON.parse(dbDecrypt(c.transports) || "[]"),
        })),
      });
      putChallenge(`auth:${usernameHash}`, options.challenge);
      res.json(options);
    } catch (error) {
      console.error("WebAuthn login options error:", error);
      res.status(500).json({ error: "Failed to create authentication challenge." });
    }
  });

  app.post("/api/auth/webauthn/login/verify", async (req: Request, res: Response) => {
    try {
      const { username, response } = req.body as {
        username: string;
        response: AuthenticationResponseJSON;
      };
      if (!username || !response) {
        res.status(400).json({ error: "Username and assertion are required." });
        return;
      }

      const usernameHash = usernameHashOf(username);
      const user = await db.get(
        "SELECT id, username_enc, lock_until FROM users WHERE username_hash = ?",
        [usernameHash]
      );

      if (user && user.lock_until && user.lock_until > Date.now()) {
        const minutes = Math.ceil((user.lock_until - Date.now()) / 60000);
        res.status(429).json({ error: `Account temporarily locked. Try again in ${minutes} minute(s).` });
        return;
      }

      // Find the credential matching the assertion among the user's passkeys
      const creds = user
        ? await db.all("SELECT id, cred_id, pubkey, counter FROM webauthn_credentials WHERE user_id = ?", [user.id])
        : [];
      const matching = creds.find((c) => dbDecrypt(c.cred_id) === response.id);

      if (!user || !matching) {
        if (user) await recordAuthFailure(user.id, "WebAuthn assertion with unknown credential");
        res.status(401).json({ error: "Biometrics not configured on this account." });
        return;
      }

      const expectedChallenge = takeChallenge(`auth:${usernameHash}`);
      if (!expectedChallenge) {
        res.status(400).json({ error: "Authentication challenge expired. Try again." });
        return;
      }

      const { rpID, origin } = getRpParams(req);
      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
        credential: {
          id: dbDecrypt(matching.cred_id),
          publicKey: new Uint8Array(Buffer.from(dbDecrypt(matching.pubkey), "base64")),
          counter: matching.counter || 0,
        },
      });

      if (!verification.verified) {
        await recordAuthFailure(user.id, "WebAuthn signature verification failed");
        res.status(401).json({ error: "Biometric signature verification failed." });
        return;
      }

      await db.run("UPDATE webauthn_credentials SET counter = ? WHERE id = ?", [
        verification.authenticationInfo.newCounter,
        matching.id,
      ]);
      await db.run("UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE id = ?", [user.id]);
      await serverAudit(user.id, "login_success", "Vault unlocked with biometric passkey");

      const decryptedUsername = dbDecrypt(user.username_enc);
      const token = generateSessionToken(user.id, decryptedUsername);

      res.json({
        message: "Vault unlocked via biometric authentication.",
        token,
        userId: user.id,
        username: decryptedUsername,
      });
    } catch (error) {
      console.error("WebAuthn login verify error:", error);
      res.status(401).json({ error: "Biometric verification failed." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Fetch Credentials E2EE payloads
  // -------------------------------------------------------------------------
  app.get("/api/credentials", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const rows = await db.all(
        "SELECT * FROM credentials WHERE user_id = ? ORDER BY modified_at DESC",
        [req.userId]
      );

      const decryptedRows = rows.map((row) => ({
        id: row.id,
        title: dbDecrypt(row.title_enc),
        usernameEnc: dbDecrypt(row.username_enc),
        passwordEnc: dbDecrypt(row.password_enc),
        urlEnc: dbDecrypt(row.url_enc),
        notesEnc: dbDecrypt(row.notes_enc),
        category: dbDecrypt(row.category_enc),
        iv: dbDecrypt(row.iv),
        modifiedAt: row.modified_at,
      }));

      res.json(decryptedRows);
    } catch (error) {
      console.error("Fetch credentials error:", error);
      res.status(500).json({ error: "Failed to retrieve decrypted database collections." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Create Encrypted Password Entry
  // -------------------------------------------------------------------------
  app.post("/api/credentials", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { id, title, usernameEnc, passwordEnc, urlEnc, notesEnc, category, iv, modifiedAt } = req.body;

      if (!id || !title || !iv) {
        res.status(400).json({ error: "Required encryption parameters are missing." });
        return;
      }

      await db.run(
        `INSERT INTO credentials (id, user_id, title_enc, username_enc, password_enc, url_enc, notes_enc, category_enc, iv, modified_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          req.userId,
          dbEncrypt(title),
          dbEncrypt(usernameEnc || ""),
          dbEncrypt(passwordEnc || ""),
          dbEncrypt(urlEnc || ""),
          dbEncrypt(notesEnc || ""),
          dbEncrypt(category || "General"),
          dbEncrypt(iv),
          modifiedAt || Date.now(),
        ]
      );

      res.status(201).json({ success: true, message: "Credential synced to host SQLite db." });
    } catch (error) {
      console.error("Create credential error:", error);
      res.status(500).json({ error: "Failed to securely write credentials record." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Update Encrypted Password Entry
  // -------------------------------------------------------------------------
  app.put("/api/credentials/:id", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const credentialId = req.params.id;
      const { title, usernameEnc, passwordEnc, urlEnc, notesEnc, category, iv, modifiedAt } = req.body;

      const existing = await db.get("SELECT id FROM credentials WHERE id = ? AND user_id = ?", [
        credentialId,
        req.userId,
      ]);

      if (!existing) {
        res.status(404).json({ error: "Credential record not found or unauthorized editing access." });
        return;
      }

      await db.run(
        `UPDATE credentials
         SET title_enc = ?, username_enc = ?, password_enc = ?, url_enc = ?, notes_enc = ?, category_enc = ?, iv = ?, modified_at = ?
         WHERE id = ? AND user_id = ?`,
        [
          dbEncrypt(title),
          dbEncrypt(usernameEnc || ""),
          dbEncrypt(passwordEnc || ""),
          dbEncrypt(urlEnc || ""),
          dbEncrypt(notesEnc || ""),
          dbEncrypt(category || "General"),
          dbEncrypt(iv),
          modifiedAt || Date.now(),
          credentialId,
          req.userId,
        ]
      );

      res.json({ success: true, message: "Item successfully modified on host SQLite db." });
    } catch (error) {
      console.error("Update credential error:", error);
      res.status(500).json({ error: "Failed to accurately update target record." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Delete Encrypted Password Entry
  // -------------------------------------------------------------------------
  app.delete("/api/credentials/:id", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const credentialId = req.params.id;

      const existing = await db.get("SELECT id FROM credentials WHERE id = ? AND user_id = ?", [
        credentialId,
        req.userId,
      ]);

      if (!existing) {
        res.status(404).json({ error: "Credential record not found or unauthorized removal request." });
        return;
      }

      await db.run("DELETE FROM credentials WHERE id = ? AND user_id = ?", [credentialId, req.userId]);
      // Tombstone so the deletion propagates to synced peers
      await db.run("INSERT OR REPLACE INTO tombstones (id, user_id, deleted_at) VALUES (?, ?, ?)", [
        credentialId,
        req.userId,
        Date.now(),
      ]);
      res.json({ success: true, message: "Item securely purged from server storage." });
    } catch (error) {
      console.error("Delete credential error:", error);
      res.status(500).json({ error: "Failed to successfully delete credentials asset." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Master password change / vault key rotation.
  // The client decrypts everything with the old key, re-encrypts with the new
  // key, and submits the whole vault; the swap is applied atomically. Every
  // credential must be covered or the request is rejected (otherwise some
  // entries would become undecryptable).
  // -------------------------------------------------------------------------
  app.post("/api/vault/rotate", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { currentAuthKeyHex, newPasswordHash, newSalt, iterations, credentials, audits } = req.body;
      if (!currentAuthKeyHex || !newPasswordHash || !newSalt || !Array.isArray(credentials)) {
        res.status(400).json({ error: "Rotation parameters are incomplete." });
        return;
      }

      const user = await db.get(
        "SELECT id, password_hash, lock_until FROM users WHERE id = ?",
        [req.userId]
      );
      if (user.lock_until && user.lock_until > Date.now()) {
        res.status(429).json({ error: "Account temporarily locked." });
        return;
      }
      if (!verifyAuthKey(String(currentAuthKeyHex), user.password_hash)) {
        await recordAuthFailure(user.id, "Password change: current password verification failed");
        res.status(401).json({ error: "Current master password is incorrect." });
        return;
      }

      // Coverage check: every stored credential must be re-encrypted
      const existingRows = await db.all("SELECT id FROM credentials WHERE user_id = ?", [req.userId]);
      const providedIds = new Set(credentials.map((c: any) => String(c.id)));
      const missing = existingRows.filter((r) => !providedIds.has(String(r.id)));
      if (missing.length > 0) {
        res.status(400).json({
          error: `Rotation payload is missing ${missing.length} vault entr(ies). Aborting to prevent data loss.`,
        });
        return;
      }

      const kdfIterations = Math.min(
        MAX_KDF_ITERATIONS,
        Math.max(MIN_KDF_ITERATIONS, Number(iterations) || DEFAULT_KDF_ITERATIONS)
      );

      await db.exec("BEGIN TRANSACTION");
      try {
        await db.run(
          "UPDATE users SET salt = ?, password_hash = ?, kdf_iterations = ?, updated_at = ? WHERE id = ?",
          [dbEncrypt(String(newSalt)), hashAuthKey(String(newPasswordHash)), kdfIterations, Date.now(), req.userId]
        );

        for (const c of credentials) {
          await db.run(
            `UPDATE credentials
             SET title_enc = ?, username_enc = ?, password_enc = ?, url_enc = ?, notes_enc = ?, category_enc = ?, iv = ?, modified_at = ?
             WHERE id = ? AND user_id = ?`,
            [
              dbEncrypt(c.title),
              dbEncrypt(c.usernameEnc || ""),
              dbEncrypt(c.passwordEnc || ""),
              dbEncrypt(c.urlEnc || ""),
              dbEncrypt(c.notesEnc || ""),
              dbEncrypt(c.category || "General"),
              dbEncrypt(c.iv),
              Date.now(),
              String(c.id),
              req.userId,
            ]
          );
        }

        for (const a of Array.isArray(audits) ? audits : []) {
          await db.run(
            "UPDATE audit_logs SET item_name = ?, iv = ? WHERE id = ? AND user_id = ?",
            [dbEncrypt(String(a.itemNameEnc || "")), dbEncrypt(String(a.iv || "")), String(a.id), req.userId]
          );
        }

        await db.exec("COMMIT");
      } catch (txErr) {
        await db.exec("ROLLBACK");
        throw txErr;
      }

      await serverAudit(req.userId!, "password_changed", "Master password changed; vault re-encrypted");
      res.json({ success: true, message: "Master password changed. Vault re-encrypted." });
    } catch (error) {
      console.error("Vault rotation error:", error);
      res.status(500).json({ error: "Failed to rotate vault keys." });
    }
  });

  // -------------------------------------------------------------------------
  // API ROUTE: Audit logs (item names are E2EE blobs from the client)
  // -------------------------------------------------------------------------
  app.get("/api/audits", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const rows = await db.all(
        "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100",
        [req.userId]
      );

      const decryptedLogs = rows.map((row) => ({
        id: row.id,
        action: dbDecrypt(row.action),
        itemNameEnc: dbDecrypt(row.item_name),
        iv: row.iv ? dbDecrypt(row.iv) : "",
        timestamp: row.timestamp,
      }));

      res.json(decryptedLogs);
    } catch (error) {
      console.error("Fetch audit logs error:", error);
      res.status(500).json({ error: "Failed to reconstruct activity history charts." });
    }
  });

  app.post("/api/audits", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { action, itemNameEnc, iv } = req.body;
      if (!action || !itemNameEnc) {
        res.status(400).json({ error: "Log context params required." });
        return;
      }

      await db.run(
        `INSERT INTO audit_logs (id, user_id, action, item_name, iv, timestamp) VALUES (?, ?, ?, ?, ?, ?)`,
        [
          crypto.randomUUID(),
          req.userId,
          dbEncrypt(String(action)),
          dbEncrypt(String(itemNameEnc)),
          dbEncrypt(String(iv || "")),
          Date.now(),
        ]
      );

      res.status(201).json({ success: true });
    } catch (error) {
      console.error("Create audit entry error:", error);
      res.status(500).json({ error: "Failed to log event operation." });
    }
  });

  // -------------------------------------------------------------------------
  // DEVICE SYNC (hub-and-spoke)
  // The "hub" holds the pairing secret and passively serves /api/sync/exchange.
  // A "joiner" imports the account once, then periodically exchanges deltas:
  // it pushes its local changes and receives the hub's. Merges are
  // last-write-wins per credential with deletion tombstones.
  // -------------------------------------------------------------------------

  const getSyncConfig = () => db.get("SELECT * FROM sync_config WHERE id = 1");

  // Collect this server's state for one account since a watermark
  async function gatherSyncData(userId: number, since: number) {
    const user = await db.get("SELECT * FROM users WHERE id = ?", [userId]);
    const creds = await db.all("SELECT * FROM credentials WHERE user_id = ? AND modified_at > ?", [userId, since]);
    const tombs = await db.all("SELECT * FROM tombstones WHERE user_id = ? AND deleted_at > ?", [userId, since]);
    const passkeys = await db.all("SELECT * FROM webauthn_credentials WHERE user_id = ?", [userId]);

    return {
      account: {
        usernameHash: user.username_hash,
        username: dbDecrypt(user.username_enc),
        salt: dbDecrypt(user.salt),
        passwordHash: user.password_hash, // one-way scrypt string
        kdfIterations: user.kdf_iterations,
        totpEnabled: !!user.totp_enabled,
        totpSecretHex: user.totp_secret_enc ? dbDecrypt(user.totp_secret_enc) : "",
        totpLastCounter: user.totp_last_counter || 0,
        createdAt: user.created_at,
        updatedAt: user.updated_at || 0,
      },
      credentials: creds.map((row) => ({
        id: row.id,
        title: dbDecrypt(row.title_enc),
        usernameEnc: dbDecrypt(row.username_enc),
        passwordEnc: dbDecrypt(row.password_enc),
        urlEnc: dbDecrypt(row.url_enc),
        notesEnc: dbDecrypt(row.notes_enc),
        category: dbDecrypt(row.category_enc),
        iv: dbDecrypt(row.iv),
        modifiedAt: row.modified_at,
      })),
      tombstones: tombs.map((t) => ({ id: t.id, deletedAt: t.deleted_at })),
      webauthn: passkeys.map((p) => ({
        credId: dbDecrypt(p.cred_id),
        pubkey: dbDecrypt(p.pubkey),
        counter: p.counter || 0,
        transports: dbDecrypt(p.transports) || "[]",
        label: dbDecrypt(p.label) || "Synced device",
        createdAt: p.created_at,
      })),
    };
  }

  // Merge a peer's state into this server. Returns stats.
  async function applySyncData(data: any, allowCreateAccount: boolean) {
    const stats = { credsApplied: 0, credsDeleted: 0, accountUpdated: false, passkeysAdded: 0 };
    const acc = data.account;
    if (!acc?.usernameHash) throw new Error("Sync payload missing account.");

    let user = await db.get("SELECT * FROM users WHERE username_hash = ?", [acc.usernameHash]);

    if (!user) {
      if (!allowCreateAccount) throw new Error("Account not present on this server.");
      await db.run(
        `INSERT INTO users (username_hash, username_enc, salt, password_hash, kdf_iterations, totp_secret_enc, totp_enabled, totp_last_counter, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          acc.usernameHash,
          dbEncrypt(acc.username),
          dbEncrypt(acc.salt),
          acc.passwordHash,
          acc.kdfIterations || MIN_KDF_ITERATIONS,
          acc.totpSecretHex ? dbEncrypt(acc.totpSecretHex) : null,
          acc.totpEnabled ? 1 : 0,
          acc.totpLastCounter || 0,
          acc.createdAt || Date.now(),
          acc.updatedAt || Date.now(),
        ]
      );
      user = await db.get("SELECT * FROM users WHERE username_hash = ?", [acc.usernameHash]);
      stats.accountUpdated = true;
    } else if ((acc.updatedAt || 0) > (user.updated_at || 0)) {
      // Peer has newer account material (password rotation / TOTP change)
      await db.run(
        `UPDATE users SET username_enc = ?, salt = ?, password_hash = ?, kdf_iterations = ?, totp_secret_enc = ?, totp_enabled = ?, updated_at = ? WHERE id = ?`,
        [
          dbEncrypt(acc.username),
          dbEncrypt(acc.salt),
          acc.passwordHash,
          acc.kdfIterations || MIN_KDF_ITERATIONS,
          acc.totpSecretHex ? dbEncrypt(acc.totpSecretHex) : null,
          acc.totpEnabled ? 1 : 0,
          acc.updatedAt,
          user.id,
        ]
      );
      stats.accountUpdated = true;
    }

    // TOTP replay guard advances regardless of account version
    if ((acc.totpLastCounter || 0) > (user.totp_last_counter || 0)) {
      await db.run("UPDATE users SET totp_last_counter = ? WHERE id = ?", [acc.totpLastCounter, user.id]);
    }

    // Tombstones first: a delete beats older edits, a newer edit beats the delete
    for (const t of data.tombstones || []) {
      const local = await db.get("SELECT id, modified_at FROM credentials WHERE id = ? AND user_id = ?", [t.id, user.id]);
      if (!local || local.modified_at < t.deletedAt) {
        if (local) {
          await db.run("DELETE FROM credentials WHERE id = ? AND user_id = ?", [t.id, user.id]);
          stats.credsDeleted++;
        }
        await db.run("INSERT OR REPLACE INTO tombstones (id, user_id, deleted_at) VALUES (?, ?, ?)", [t.id, user.id, t.deletedAt]);
      }
    }

    // Credentials: last-write-wins by modifiedAt, respecting newer tombstones
    for (const c of data.credentials || []) {
      const tomb = await db.get("SELECT deleted_at FROM tombstones WHERE id = ? AND user_id = ?", [c.id, user.id]);
      if (tomb && tomb.deleted_at >= c.modifiedAt) continue;

      const local = await db.get("SELECT id, modified_at FROM credentials WHERE id = ? AND user_id = ?", [c.id, user.id]);
      if (local && local.modified_at >= c.modifiedAt) continue;

      await db.run(
        `INSERT OR REPLACE INTO credentials (id, user_id, title_enc, username_enc, password_enc, url_enc, notes_enc, category_enc, iv, modified_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          c.id,
          user.id,
          dbEncrypt(c.title),
          dbEncrypt(c.usernameEnc || ""),
          dbEncrypt(c.passwordEnc || ""),
          dbEncrypt(c.urlEnc || ""),
          dbEncrypt(c.notesEnc || ""),
          dbEncrypt(c.category || "General"),
          dbEncrypt(c.iv),
          c.modifiedAt,
        ]
      );
      // Entry resurrected/updated: clear any older tombstone
      await db.run("DELETE FROM tombstones WHERE id = ? AND user_id = ? AND deleted_at < ?", [c.id, user.id, c.modifiedAt]);
      stats.credsApplied++;
    }

    // Passkeys: additive union by credential id; counters advance to max
    const localPasskeys = await db.all("SELECT id, cred_id, counter FROM webauthn_credentials WHERE user_id = ?", [user.id]);
    const localById = new Map(localPasskeys.map((p) => [dbDecrypt(p.cred_id), p]));
    for (const pk of data.webauthn || []) {
      const existing = localById.get(pk.credId);
      if (existing) {
        if ((pk.counter || 0) > (existing.counter || 0)) {
          await db.run("UPDATE webauthn_credentials SET counter = ? WHERE id = ?", [pk.counter, existing.id]);
        }
      } else {
        await db.run(
          `INSERT INTO webauthn_credentials (user_id, cred_id, pubkey, counter, transports, label, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [user.id, dbEncrypt(pk.credId), dbEncrypt(pk.pubkey), pk.counter || 0, dbEncrypt(pk.transports), dbEncrypt(pk.label), pk.createdAt || Date.now()]
        );
        stats.passkeysAdded++;
      }
    }

    return { stats, userId: user.id };
  }

  // Joiner-side: run one full exchange with the hub
  async function runSyncExchange(): Promise<{ ok: boolean; detail: string }> {
    const cfg = await getSyncConfig();
    if (!cfg || cfg.role !== "joiner" || !cfg.peer_url) {
      return { ok: false, detail: "Sync is not configured on this server (joiner role required)." };
    }
    const secretHex = dbDecrypt(cfg.secret_enc);

    try {
      const localUser = await db.get("SELECT id FROM users WHERE username_hash = ?", [cfg.username_hash]);
      const localNow = Date.now();
      const outbound = localUser ? await gatherSyncData(localUser.id, cfg.push_since || 0) : null;

      const requestPayload = {
        ts: Date.now(),
        usernameHash: cfg.username_hash,
        since: cfg.pull_since || 0,
        data: outbound,
      };

      const response = await fetch(`${cfg.peer_url.replace(/\/$/, "")}/api/sync/exchange`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(syncSeal(requestPayload, secretHex)),
      });
      if (!response.ok) throw new Error(`Peer responded ${response.status}`);

      const sealed = await response.json();
      const inbound = syncOpen(sealed, secretHex);
      if (!inbound) throw new Error("Peer response could not be authenticated.");

      const { stats } = await applySyncData(inbound.data, true);

      await db.run(
        "UPDATE sync_config SET pull_since = ?, push_since = ?, last_sync_at = ?, last_sync_error = NULL WHERE id = 1",
        [inbound.now, localNow, Date.now()]
      );

      const changed = stats.credsApplied + stats.credsDeleted + stats.passkeysAdded;
      if ((changed > 0 || stats.accountUpdated) && localUser) {
        await serverAudit(localUser.id, "sync_applied", `Sync: ${stats.credsApplied} updated, ${stats.credsDeleted} deleted, ${stats.passkeysAdded} passkeys added`);
      }
      return { ok: true, detail: `Applied ${stats.credsApplied} update(s), ${stats.credsDeleted} deletion(s).` };
    } catch (err: any) {
      const detail = err?.message || "Sync failed.";
      await db.run("UPDATE sync_config SET last_sync_error = ? WHERE id = 1", [detail]).catch(() => {});
      return { ok: false, detail };
    }
  }

  // Hub-side: generate (or rotate) the pairing secret
  app.post("/api/sync/pairing-code", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const user = await db.get("SELECT username_hash FROM users WHERE id = ?", [req.userId]);
      const secretHex = crypto.randomBytes(32).toString("hex");
      await db.run(
        `INSERT INTO sync_config (id, role, peer_url, username_hash, secret_enc)
         VALUES (1, 'hub', NULL, ?, ?)
         ON CONFLICT(id) DO UPDATE SET role='hub', username_hash=excluded.username_hash, secret_enc=excluded.secret_enc`,
        [user.username_hash, dbEncrypt(secretHex)]
      );
      await serverAudit(req.userId!, "sync_pairing", "Sync pairing secret generated (hub role)");
      res.json({ secret: secretHex });
    } catch (error) {
      console.error("Pairing code error:", error);
      res.status(500).json({ error: "Failed to generate pairing secret." });
    }
  });

  // Hub-side: serve an exchange (merge joiner's changes, return ours)
  app.post("/api/sync/exchange", async (req: Request, res: Response) => {
    try {
      const cfg = await getSyncConfig();
      if (!cfg || cfg.role !== "hub") {
        res.status(404).json({ error: "Sync is not enabled on this server." });
        return;
      }
      const secretHex = dbDecrypt(cfg.secret_enc);
      const payload = syncOpen(req.body, secretHex);
      if (!payload || payload.usernameHash !== cfg.username_hash) {
        res.status(401).json({ error: "Sync request could not be authenticated." });
        return;
      }

      // Merge the joiner's outbound changes (if it has local state yet)
      if (payload.data) {
        await applySyncData(payload.data, false);
      }

      // Reply with our state since the joiner's watermark
      const user = await db.get("SELECT id FROM users WHERE username_hash = ?", [cfg.username_hash]);
      const now = Date.now();
      const data = await gatherSyncData(user.id, payload.since || 0);
      res.json(syncSeal({ ts: Date.now(), now, data }, secretHex));
    } catch (error) {
      console.error("Sync exchange error:", error);
      res.status(500).json({ error: "Sync exchange failed." });
    }
  });

  // Joiner-side: pair with a hub and import the account (bootstrap).
  // Open only while this server has no accounts; afterwards requires auth.
  app.post("/api/sync/join", authLimiter, async (req: Request, res: Response) => {
    try {
      const { peerUrl, secret, username } = req.body;
      if (!peerUrl || !secret || !username) {
        res.status(400).json({ error: "Peer URL, pairing secret, and username are required." });
        return;
      }

      const userCount = await db.get("SELECT COUNT(*) as n FROM users");
      if ((userCount?.n || 0) > 0) {
        res.status(403).json({ error: "This server already has accounts. Joining is only allowed on a fresh server." });
        return;
      }

      const usernameHash = usernameHashOf(String(username));
      await db.run(
        `INSERT INTO sync_config (id, role, peer_url, username_hash, secret_enc, pull_since, push_since)
         VALUES (1, 'joiner', ?, ?, ?, 0, 0)
         ON CONFLICT(id) DO UPDATE SET role='joiner', peer_url=excluded.peer_url, username_hash=excluded.username_hash, secret_enc=excluded.secret_enc, pull_since=0, push_since=0`,
        [String(peerUrl), usernameHash, dbEncrypt(String(secret))]
      );

      const result = await runSyncExchange();
      if (!result.ok) {
        await db.run("DELETE FROM sync_config WHERE id = 1");
        res.status(502).json({ error: `Could not reach or authenticate with the hub: ${result.detail}` });
        return;
      }

      res.json({ success: true, message: "Vault imported. Log in with your master password.", detail: result.detail });
    } catch (error) {
      console.error("Sync join error:", error);
      res.status(500).json({ error: "Failed to join sync." });
    }
  });

  // Manual sync trigger + status (any logged-in user)
  app.post("/api/sync/now", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const result = await runSyncExchange();
    res.status(result.ok ? 200 : 502).json(result);
  });

  app.get("/api/sync/status", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const cfg = await getSyncConfig();
    res.json(
      cfg
        ? {
            role: cfg.role,
            peerUrl: cfg.peer_url,
            lastSyncAt: cfg.last_sync_at || 0,
            lastSyncError: cfg.last_sync_error || null,
          }
        : { role: "none" }
    );
  });

  // Periodic exchange on the joiner
  setInterval(async () => {
    const cfg = await getSyncConfig().catch(() => null);
    if (cfg?.role === "joiner" && cfg.peer_url) {
      await runSyncExchange();
    }
  }, SYNC_INTERVAL_MS).unref?.();

  // Prune old tombstones (older than 90 days)
  await db.run("DELETE FROM tombstones WHERE deleted_at < ?", [Date.now() - 90 * 24 * 60 * 60 * 1000]).catch(() => {});

  // -------------------------------------------------------------------------
  // Automated encrypted backups (daily). Snapshot via VACUUM INTO, then
  // encrypt with AES-256-GCM using a backup-specific derived key.
  // Decrypt with scripts/decrypt-backup.mjs.
  // -------------------------------------------------------------------------
  const backupsDir = path.join(dbDir, "backups");

  async function backupDatabase(): Promise<void> {
    try {
      if (!fs.existsSync(backupsDir)) fs.mkdirSync(backupsDir, { recursive: true });
      const tmpPath = path.join(backupsDir, `.snapshot-${Date.now()}.db`);
      await db.exec(`VACUUM INTO '${tmpPath.replace(/'/g, "''")}'`);

      const plain = fs.readFileSync(tmpPath);
      fs.unlinkSync(tmpPath);

      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", BACKUP_KEY, iv);
      const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
      const tag = cipher.getAuthTag();

      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      const outPath = path.join(backupsDir, `securepassx-${stamp}.db.enc`);
      fs.writeFileSync(outPath, Buffer.concat([iv, tag, encrypted]), { mode: 0o600 });

      // Keep the 7 most recent backups
      const backups = fs
        .readdirSync(backupsDir)
        .filter((f) => f.endsWith(".db.enc"))
        .sort()
        .reverse();
      for (const stale of backups.slice(7)) {
        fs.unlinkSync(path.join(backupsDir, stale));
      }

      console.log(`Encrypted backup written: ${outPath}`);
    } catch (err) {
      console.error("Backup failed:", err);
    }
  }

  backupDatabase();
  setInterval(backupDatabase, 24 * 60 * 60 * 1000).unref?.();

  // -------------------------------------------------------------------------
  // Vite dev server / production static hosting
  // -------------------------------------------------------------------------
  if (!IS_PRODUCTION) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`SecurePassX server fully active on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Fatal: failed to boot SecurePassX core engine server.", err);
  process.exit(1);
});
