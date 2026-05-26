# SecurePassX

**SecurePassX** is a modern, high-performance, and visually gorgeous End-to-End Encrypted (E2EE) password manager designed around a modular **Bento Grid** user interface. It combines client-side zero-knowledge cryptographic operations with an encrypted, light-weight SQLite database backend.

---

## 🎨 Visual Identity & Bento Theme

SecurePassX utilizes a stunning, dark-mode **Bento-Grid** interface layout that offers high visual rhythm, generous negative space, and responsive modular widgets:
* **Slate & Emerald Palette**: High-contrast, easy-on-the-eyes slate primary containers accented with vibrant emerald interactive indicators.
* **Responsive Bento Layout**: Beautifully organized cards for credentials streams, interactive biometric bypass, rapid password generators, local system metrics, and auto-lock timers.
* **Micro-interactions**: Elegant state transition curves, real-time keyboard/mouse activity auto-lock counts, and copy-feedback indicators.

---

## 🔒 Security & Cryptographic Architecture

### 1. Zero-Knowledge Proof (Client-side)
* **Master Keys Derivation**: Your Master Password never goes to the server in cleartext. High-iteration **PBKDF2 with HMAC-SHA-256** runs purely in your browser using the Native Web Crypto API to derive both the **Symmetric Encryption Key** and the **Server Authorization Token**.
* **E2EE Symmetric Encryption**: Records (including titles, user identifiers, passwords, notes, URLs, and categories) are fully encrypted inside your browser using **AES-256-GCM** before transmission. Encryption vectors (IVs) are generated via cryptographically secure random values.
* **Local Crypto Storage**: Secure biometric authentication utilizes a localized metadata container inside your browser’s localStorage to hold and decrypt credentials safely without exposing master parameters.

### 2. Double-Layered Server Encryption (SQLite)
* **Encryption at Rest**: The Node.js SQLite (`securepassx.db`) database uses dual-layered **AES-256-CBC value-level ciphers** using the `DB_ENCRYPTION_KEY` environment variable.
* Even if an attacker obtains a full copy of the raw SQLite database, the content of your cards remains doubly garbled and completely unbreakable without the specific user Master Password.

---

## 🚀 Key Functional Features

- **Decentralized Credentials Stream**: Create, read, update, categorize, tag favorites, search, and purge password entries in real-time.
- **Auto-Lock Sequence**: Monitored user activity counters automatically lock your unlocked sessions after **5 minutes of inactivity** to prevent physical intrusion.
- **Biometric FaceID/TouchID bypass (WebAuthn Emulated)**: Fast secure unlocking from trusted browsers after registration.
- **Password Strength Audit**: Real-time analytical grading scorecard for your passive credential hygiene.
- **Secure Exports**: Instantly download your database in either a master-encrypted E2EE backup package or a human-readable decrypted plaintext JSON bundle.
- **Flexible Password Generator**: Detailed entropy customizer supporting symbols, numbers, capitalizations, and length parameters.

---

## ⚙️ Development & Quick Start

### 1. Local Development
Ensure you have Node.js (v18+) and your system dependencies installed:

```bash
# Install core packages
npm install

# Start the dev server (Vite + Express on TSX)
npm run dev
```

The application dev server will boot instantly on http://localhost:3000.

### 2. Docker Deployment
Ensure you have Docker and Docker Compose installed:

```bash
# Boot the fully containerized server and volumes
docker-compose up --build
```

The Compose environment binds port `3000`, links custom volume storage securely, and configures database parameters for production.

---

## 📂 Project Architecture

* `/server.ts` — Standalone production Express API handling SQLite queries, SQLite value ciphers at rest, and Vite middleware.
* `/src/App.tsx` — Root component routing between the unified Login/Register view and the primary dashboard.
* `/src/components/VaultDashboard.tsx` — Modular dashboard constructed within bento elements.
* `/src/components/AuthScreen.tsx` — E2E login/register portal executing PBKDF2 hashing.
* `/src/components/BiometricPrompt.tsx` — Local biometric touch registers.
* `/src/lib/crypto.ts` — Web Cryptography helpers mapping named browser ciphers.
* `/src/types.ts` — Centralized TypeScript interfaces for strict typing.
