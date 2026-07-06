/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { KeyRound, ShieldAlert, Fingerprint, RefreshCw, UserCheck, ShieldCheck, DatabaseZap } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import {
  deriveUserKeys,
  generateSalt,
  hashSHA256,
  deriveKeyFromPrfSecret,
  decryptString,
  DEFAULT_KDF_ITERATIONS,
} from "../lib/crypto";
import BiometricPrompt, { BiometricAuthResult } from "./BiometricPrompt";

interface AuthScreenProps {
  onUnlockSuccess: (
    userId: number,
    username: string,
    key: CryptoKey,
    token: string,
    biometricsSupported: boolean
  ) => void;
}

export default function AuthScreen({ onUnlockSuccess }: AuthScreenProps) {
  const [formMode, setFormMode] = useState<"login" | "register" | "join">("login");

  // Device-sync join (pair this fresh server with a hub)
  const [joinPeerUrl, setJoinPeerUrl] = useState("");
  const [joinSecret, setJoinSecret] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Biometric login triggers
  const [bioPromptOpen, setBioPromptOpen] = useState(false);

  // TOTP second-factor step. Derived keys from the first (password) attempt
  // are cached so the code retry skips the expensive KDF.
  const [totpRequired, setTotpRequired] = useState(false);
  const [totpCode, setTotpCode] = useState("");
  const pendingLoginRef = React.useRef<{ encryptionKey: CryptoKey; clientAuthHash: string } | null>(null);

  const triggerPostSession = async (userId: number, uName: string, encKey: CryptoKey, token: string, bioEnabled: boolean) => {
    onUnlockSuccess(userId, uName, encKey, token, bioEnabled);
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!username.trim() || !password) {
      setError("Please fill out all mandatory registration elements.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Master password configurations do not match.");
      return;
    }

    if (password.length < 8) {
      setError("Master password is too weak. Ensure it is at least 8 characters long.");
      return;
    }

    setLoading(true);

    try {
      // 1. Generate fresh secure salt for KDF
      const salt = generateSalt();

      // 2. Perform PBKDF2 Master Keys derivation (600k iterations)
      const { encryptionKey, authKeyHex } = await deriveUserKeys(password, salt, DEFAULT_KDF_ITERATIONS);

      // 3. Sha256 the authentication key for server validation storage
      const passwordHash = await hashSHA256(authKeyHex);

      // 4. Submit registration requests to SQLite host
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username.trim(),
          salt,
          passwordHash,
          iterations: DEFAULT_KDF_ITERATIONS,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Account activation rejected.");
      }

      setSuccess("Secure master vault created successfully! Unlocking...");
      
      // Delay slightly for a satisfying onboarding welcome transition
      setTimeout(() => {
        triggerPostSession(data.userId, data.username, encryptionKey, data.token, false);
      }, 1000);
    } catch (err: any) {
      setError(err.message || "Failed to create security account.");
      setLoading(false);
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!username.trim() || !password) {
      setError("Please key in your username and master vault password.");
      return;
    }

    setLoading(true);

    try {
      let encryptionKey: CryptoKey;
      let clientAuthHash: string;

      if (totpRequired && pendingLoginRef.current) {
        // Second-factor retry: reuse derived keys from the password step
        ({ encryptionKey, clientAuthHash } = pendingLoginRef.current);
      } else {
        // 1. Retreive server encryption salt for target profile
        const saltRes = await fetch("/api/auth/salt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: username.trim() }),
        });

        const saltData = await saltRes.json();
        if (!saltRes.ok) {
          throw new Error(saltData.error || "User vault registration not detected.");
        }

        const { salt, iterations } = saltData;

        // 2. Derive authentic keys from master inputs (per-account KDF params)
        const derived = await deriveUserKeys(password, salt, iterations);
        encryptionKey = derived.encryptionKey;

        // 3. Hash derived AuthKey for safe checking
        clientAuthHash = await hashSHA256(derived.authKeyHex);
        pendingLoginRef.current = { encryptionKey, clientAuthHash };
      }

      // 4. Submit login check to the server (with 2FA code when requested)
      const loginRes = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username.trim(),
          authKeyHex: clientAuthHash,
          ...(totpRequired && totpCode ? { totpCode } : {}),
        }),
      });

      const loginData = await loginRes.json();
      if (!loginRes.ok) {
        if (loginData.totpRequired) {
          setTotpRequired(true);
          setLoading(false);
          if (totpCode) setError(loginData.error || "Invalid verification code.");
          setTotpCode("");
          return;
        }
        pendingLoginRef.current = null;
        throw new Error(loginData.error || "Master credential verification failed.");
      }

      pendingLoginRef.current = null;
      setTotpRequired(false);
      setTotpCode("");

      setSuccess("Master password valid. Vault unlocked!");
      setTimeout(() => {
        triggerPostSession(
          loginData.userId,
          loginData.username,
          encryptionKey,
          loginData.token,
          loginData.biometricEnabled
        );
      }, 800);
    } catch (err: any) {
      setError(err.message || "Invalid authentication coordinates.");
      setLoading(false);
    }
  };

  // Pair this server with a sync hub and import the vault
  const handleJoinSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!joinPeerUrl.trim() || !joinSecret.trim() || !username.trim()) {
      setError("Hub URL, pairing secret, and your vault username are required.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/sync/join", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          peerUrl: joinPeerUrl.trim(),
          secret: joinSecret.trim(),
          username: username.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Pairing failed.");

      setSuccess("Vault imported from hub! Log in with your master password.");
      setJoinSecret("");
      setTimeout(() => {
        setFormMode("login");
        setSuccess("Vault synced to this device. Unlock with your master password.");
        setLoading(false);
      }, 1200);
    } catch (err: any) {
      setError(err.message || "Pairing failed.");
      setLoading(false);
    }
  };

  // Read the local biometric key container (v2: PRF-wrapped master password)
  const readBioMeta = (): { prfSalt: string; iv: string; cipherMaster: string } | null => {
    try {
      const raw = localStorage.getItem(`securepassx-bio-meta-${username.trim().toLowerCase()}`);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (parsed?.v !== 2 || !parsed.prfSalt || !parsed.iv || !parsed.cipherMaster) return null;
      return parsed;
    } catch {
      return null;
    }
  };

  // Handler for a server-verified WebAuthn assertion. The session token is
  // real, but the vault key only becomes available if the authenticator's
  // PRF output can unwrap the locally cached master password.
  const handleBiometricSuccess = async (result: BiometricAuthResult) => {
    setBioPromptOpen(false);
    setError("");
    setLoading(true);

    try {
      const meta = readBioMeta();
      if (!meta) {
        throw new Error(
          "Biometric identity verified, but no local key container exists on this device. " +
            "Unlock with your master password, then re-register biometrics from the dashboard."
        );
      }
      if (!result.prfSecret) {
        throw new Error(
          "Biometric identity verified, but the authenticator did not return a PRF secret " +
            "(this browser/authenticator may not support the PRF extension). Unlock with your master password."
        );
      }

      // 1. Unwrap the cached master password with the PRF-derived key
      const wrapKey = await deriveKeyFromPrfSecret(result.prfSecret, meta.prfSalt);
      const rawDecryptedMaster = await decryptString(meta.cipherMaster, meta.iv, wrapKey);

      // 2. Re-derive the vault key with the account's salt + KDF params
      const saltRes = await fetch("/api/auth/salt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim() }),
      });
      const saltData = await saltRes.json();
      if (!saltRes.ok) {
        throw new Error("Unable to synchronize master salt records.");
      }

      const { encryptionKey } = await deriveUserKeys(rawDecryptedMaster, saltData.salt, saltData.iterations);

      setSuccess("Biometric identity confirmed. Vault decrypted successfully.");
      setTimeout(() => {
        triggerPostSession(result.userId, result.username, encryptionKey, result.token, true);
      }, 800);
    } catch (err: any) {
      setError(err.message || "Failed to unlock using biometrics.");
      setLoading(false);
    }
  };

  // Password Strength estimator for feedback during registration
  const estimateMasterStrength = () => {
    if (!password) return { label: "Empty", color: "text-slate-500", bar: "bg-slate-800", width: "0%" };
    if (password.length < 8) return { label: "Too Short (Unsafe)", color: "text-rose-500", bar: "bg-rose-500", width: "15%" };

    let flags = 0;
    if (/[a-z]/.test(password)) flags++;
    if (/[A-Z]/.test(password)) flags++;
    if (/[0-9]/.test(password)) flags++;
    if (/[^A-Za-z0-9]/.test(password)) flags++;

    if (flags <= 2) return { label: "Weak Master", color: "text-amber-500", bar: "bg-amber-500", width: "40%" };
    if (password.length < 12) return { label: "Standard Protection", color: "text-teal-400", bar: "bg-teal-400", width: "70%" };
    return { label: "Industrial-Strength", color: "text-emerald-400", bar: "bg-emerald-400", width: "100%" };
  };

  const strength = estimateMasterStrength();

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#020617] p-4 relative overflow-hidden select-none font-sans">
      {/* Visual Ambient Grid Backdrops */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#10b98108_1px,transparent_1px),linear-gradient(to_bottom,#10b98108_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/[0.03] rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/[0.03] rounded-full blur-3xl pointer-events-none" />

      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
        className="relative w-full max-w-md bento-card p-8 z-10 shadow-2xl"
      >
        <div className="text-center mb-8">
          <div className="mx-auto w-12 h-12 flex items-center justify-center bg-emerald-500/10 border border-emerald-500/20 rounded-2xl mb-4">
            <KeyRound className="w-6 h-6 text-emerald-500" />
          </div>
          <h2 className="font-display font-bold text-3xl text-slate-100 tracking-tight">
            SecurePass<span className="text-emerald-500">X</span>
          </h2>
          <p className="font-sans text-xs text-slate-400 mt-2">
            Defensive End-to-End Cryptography Password Manager
          </p>
        </div>

        {/* Form Alerts */}
        <AnimatePresence mode="wait">
          {error && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="mb-5 flex items-start gap-2.5 p-4 bg-rose-500/10 border border-rose-500/20 rounded-2xl text-rose-300 text-xs text-left"
            >
              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </motion.div>
          )}

          {success && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="mb-5 flex items-start gap-2.5 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl text-emerald-300 text-xs text-left"
            >
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>{success}</span>
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence mode="wait">
          {formMode === "login" ? (
            <motion.form
              key="login-form"
              onSubmit={handleLoginSubmit}
              initial={{ opacity: 0, x: -15 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 15 }}
              className="space-y-4 text-left"
            >
              <div>
                <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 ml-1">
                  Master Vault Username
                </label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="name@email.com or username"
                  className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-sans"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 ml-1">
                  Master Vault Password/Key
                </label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    // Cached derived keys are stale once the password changes
                    pendingLoginRef.current = null;
                    setTotpRequired(false);
                  }}
                  placeholder="Master Key passphrase"
                  className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-sans"
                />
              </div>

              {totpRequired && (
                <div>
                  <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-amber-400 mb-1.5 ml-1">
                    Two-Factor Verification Code
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    autoFocus
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                    placeholder="6-digit code from authenticator app"
                    className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-mono tracking-widest"
                  />
                </div>
              )}

              <div className="flex items-start gap-2.5 pt-1 font-sans text-xs text-slate-400 leading-relaxed bg-[#020617]/50 p-4 rounded-2xl border border-[#1e293b]">
                <DatabaseZap className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                <span>
                  <strong>Decryption Notice:</strong> Passwords are decryptable solely on your terminal. The backend never receives your clear master credentials.
                </span>
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  type="submit"
                  disabled={loading}
                  id="btn-login-submit"
                  className="flex-1 flex items-center justify-center gap-2 bento-btn-emerald text-white text-xs py-3.5 px-4 cursor-pointer disabled:opacity-50 transition-all"
                >
                  {loading ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <>
                      <KeyRound className="w-4 h-4" />
                      Unlock Vault
                    </>
                  )}
                </button>

                <button
                  type="button"
                  id="btn-login-biometric"
                  onClick={() => {
                    if (!username.trim()) {
                      setError("Identify your Master Vault Username first to retrieve device biometric bindings.");
                      return;
                    }
                    setBioPromptOpen(true);
                  }}
                  title="Unlock via Touch ID / Face ID"
                  className="px-4 bg-[#1e293b] hover:bg-[#334155] border border-[#1e293b] rounded-2xl text-slate-300 hover:text-white transition-all cursor-pointer flex items-center justify-center"
                >
                  <Fingerprint className="w-5 h-5 text-emerald-500" />
                </button>
              </div>

              <div className="text-center pt-3 space-y-1.5">
                <button
                  type="button"
                  onClick={() => setFormMode("register")}
                  className="block w-full font-sans text-xs text-emerald-400 hover:text-emerald-300 font-medium transition-colors cursor-pointer"
                >
                  Don&apos;t have a master file? Create Vault Account
                </button>
                <button
                  type="button"
                  onClick={() => setFormMode("join")}
                  className="block w-full font-sans text-xs text-sky-400 hover:text-sky-300 font-medium transition-colors cursor-pointer"
                >
                  Have a vault on another laptop? Join synced vault
                </button>
              </div>
            </motion.form>
          ) : formMode === "join" ? (
            <motion.form
              key="join-form"
              onSubmit={handleJoinSubmit}
              initial={{ opacity: 0, x: 15 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -15 }}
              className="space-y-4 text-left"
            >
              <div>
                <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 ml-1">
                  Hub Server URL
                </label>
                <input
                  type="url"
                  required
                  value={joinPeerUrl}
                  onChange={(e) => setJoinPeerUrl(e.target.value)}
                  placeholder="http://laptop-a.tailnet:3000"
                  className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 ml-1">
                  Vault Username
                </label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Username of the account on the hub"
                  className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-sans"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 ml-1">
                  Pairing Secret
                </label>
                <input
                  type="password"
                  required
                  value={joinSecret}
                  onChange={(e) => setJoinSecret(e.target.value)}
                  placeholder="Secret generated in the hub's Security Center"
                  className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-mono"
                />
              </div>

              <div className="flex items-start gap-2.5 pt-1 font-sans text-xs text-slate-400 leading-relaxed bg-[#020617]/50 p-4 rounded-2xl border border-[#1e293b]">
                <DatabaseZap className="w-4 h-4 text-sky-500 shrink-0 mt-0.5" />
                <span>
                  This imports the account and encrypted vault from your other laptop, then keeps both in sync
                  automatically. Your master password stays the same and never crosses the wire.
                </span>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full flex items-center justify-center gap-2 bento-btn-emerald text-white text-xs py-3.5 px-4 cursor-pointer disabled:opacity-50 transition-all"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : "Pair & Import Vault"}
              </button>

              <div className="text-center pt-3">
                <button
                  type="button"
                  onClick={() => setFormMode("login")}
                  className="font-sans text-xs text-emerald-400 hover:text-emerald-300 font-medium transition-colors cursor-pointer"
                >
                  Back to Unlock
                </button>
              </div>
            </motion.form>
          ) : (
            <motion.form
              key="register-form"
              onSubmit={handleRegisterSubmit}
              initial={{ opacity: 0, x: 15 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -15 }}
              className="space-y-4 text-left"
            >
              <div>
                <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 ml-1">
                  Master Vault Username
                </label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. securepass_user"
                  className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-sans"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 ml-1">
                  Create Master Password
                </label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Choose an incredibly strong phrase"
                  className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-sans"
                />

                {/* Password Strength Feedbacks */}
                {password && (
                  <div className="mt-2 text-[10px] font-mono flex items-center justify-between ml-1">
                    <span>
                      Safety rating: <span className={`${strength.color.replace('bg-', 'text-')} font-bold`}>{strength.label}</span>
                    </span>
                    <div className="w-1/3 h-1 bg-slate-950 rounded-full overflow-hidden mt-0.5">
                      <div className={`h-full ${strength.bar}`} style={{ width: strength.width }} />
                    </div>
                  </div>
                )}
              </div>

              <div>
                <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5 ml-1">
                  Confirm Master Password
                </label>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm Master Password"
                  className="w-full bento-input py-3 px-4 text-xs text-slate-100 placeholder-slate-600 transition-all font-sans"
                />
              </div>

              <div className="flex items-start gap-2.5 pt-1 font-sans text-xs text-slate-400 leading-relaxed bg-[#020617]/50 p-4 rounded-2xl border border-[#1e293b]">
                <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                <span>
                  <strong>Crucial warning:</strong> If you lose this Master Password, your E2EE passwords can never be recovered. Always store a backup physical sheet.
                </span>
              </div>

              <button
                type="submit"
                disabled={loading}
                id="btn-register-submit"
                className="w-full flex items-center justify-center gap-2 bento-btn-emerald text-white text-xs py-3.5 px-4 cursor-pointer disabled:opacity-50 transition-all"
              >
                {loading ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <>
                    <UserCheck className="w-4 h-4" />
                    Initialize Master Vault
                  </>
                )}
              </button>

              <div className="text-center pt-3">
                <button
                  type="button"
                  onClick={() => setFormMode("login")}
                  className="font-sans text-xs text-emerald-400 hover:text-emerald-300 font-medium transition-colors cursor-pointer"
                >
                  Already have standard vault? Unlock existing Account
                </button>
              </div>
            </motion.form>
          )}
        </AnimatePresence>

        <BiometricPrompt
          isOpen={bioPromptOpen}
          onClose={() => setBioPromptOpen(false)}
          username={username}
          mode="authenticate"
          prfSalt={readBioMeta()?.prfSalt || null}
          onAuthSuccess={handleBiometricSuccess}
        />
      </motion.div>
    </div>
  );
}
