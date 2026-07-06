# SecurePassX

A self-hosted, end-to-end encrypted (E2EE) password manager. All vault content is encrypted in the browser with a key derived from your master password; the server and its SQLite database only ever see ciphertext.

> **Zero-knowledge means zero recovery**: if you lose the master password, the vault cannot be decrypted. Keep an encrypted export and its passphrase somewhere safe.

## Security Architecture

### Client-side (zero-knowledge)

- **Key derivation**: PBKDF2-HMAC-SHA-256, 600,000 iterations (Web Crypto API), producing an AES-256-GCM vault key and an independent server-auth proof. The master password never leaves the browser. Existing accounts keep their original iteration count (served per-account by `/api/auth/salt`).
- **E2EE**: every credential field and audit-log item name is AES-256-GCM encrypted client-side, each field with its own random IV.
- **Biometric unlock (WebAuthn + PRF)**: passkey registration and login use server-verified challenges (`@simplewebauthn/server`). If the authenticator supports the PRF extension, its output derives (via HKDF) a local key that wraps the master password — biometric login then fully decrypts the vault. Without PRF, biometrics authenticate the session only. Multiple passkeys per account are supported and managed in the Security Center.
- **Two-factor auth (TOTP)**: RFC 6238 codes required on password logins once enabled (QR-code setup). Passkey logins skip TOTP (already two factors).

### Server-side

- **At rest**: every value is AES-256-GCM encrypted with a data key HKDF-derived from `DB_ENCRYPTION_KEY`. If the env var is unset, a random key is generated once and persisted as `securepassx.key` next to the database — no hardcoded defaults. Back that file up.
- **Auth-proof storage**: one-way scrypt with per-user salt, compared with `timingSafeEqual` — a DB + key leak does not permit login.
- **Sessions**: signed HS256 JWTs (8h TTL) with server-side revocation on logout/auto-lock.
- **Abuse protection**: rate limiting on auth routes, per-account lockout (15 min after 5 failures), `helmet` headers (CSP + HSTS in production), HTTPS redirect behind a proxy, and anti-enumeration decoy salts for unknown usernames.
- **Backups**: consistent snapshots (`VACUUM INTO`) at startup and every 24h, encrypted with a derived backup key, last 7 kept under `<db-dir>/backups/`. Restore: `node scripts/decrypt-backup.mjs <backup.db.enc> <out.db> [keyfile]`.
- **Master password change**: Security Center re-encrypts the whole vault client-side and swaps it atomically on the server; passkey containers must be re-registered afterwards.

## Features

- Create, edit, search, categorize, and favorite credential entries; password generator with configurable policy.
- Security Center: passkey management, TOTP 2FA, master password rotation.
- Passphrase-encrypted portable backup export and import (restorable into any account).
- Audit trail of vault actions and auth events (logins, failures, lockouts, passkey/2FA changes).
- Auto-lock after 5 minutes of inactivity; copied secrets wiped from the clipboard after 30 seconds and on lock.

## Quick Start

### Local development

```bash
npm install
npm run dev        # Vite + Express on http://localhost:3000
```

WebAuthn/biometrics require a secure context: use `localhost` or HTTPS.

### Docker

```bash
cp .env.example .env   # set DB_ENCRYPTION_KEY (openssl rand -hex 32)
docker compose up --build
```

Serves on port 3001; database, key file, and backups persist in the `securepassx_storage` volume.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DB_ENCRYPTION_KEY` | auto-generated `securepassx.key` | Master key material for at-rest encryption, JWT signing, and backups (min 16 chars) |
| `DB_PATH` | `./securepassx.db` | SQLite database location |

## Deployment Notes

- Prefer keeping the app off the public internet (localhost, LAN, or a VPN like Tailscale). If it must be public, front it with a TLS reverse proxy.
- Back up `securepassx.key` (or your `DB_ENCRYPTION_KEY`) separately from the database; without it, the DB and automated backups are unrecoverable.
- For whole-file DB encryption on top of value-level GCM, swap `sqlite3` for `@journeyapps/sqlcipher` and set `PRAGMA key` after opening.

## Project Structure

- `server.ts` — Express API: auth, WebAuthn, TOTP, vault CRUD, key rotation, backups, at-rest encryption.
- `src/App.tsx` — root component switching between auth screen and dashboard.
- `src/components/AuthScreen.tsx` — login/register with KDF, TOTP step, and biometric unlock.
- `src/components/VaultDashboard.tsx` — vault UI, import/export, audit log.
- `src/components/SecurityCenter.tsx` — passkeys, 2FA, master password change.
- `src/components/BiometricPrompt.tsx` — WebAuthn ceremony UI.
- `src/lib/crypto.ts` — Web Crypto helpers (PBKDF2, AES-GCM, HKDF/PRF).
- `src/lib/webauthn.ts` — WebAuthn ceremony serialization + PRF evaluation.
- `src/lib/vault.ts` — shared E2EE credential payload builder.
- `scripts/decrypt-backup.mjs` — offline backup restore tool.
