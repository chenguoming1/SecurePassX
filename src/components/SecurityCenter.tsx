/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Security Center: passkey management, TOTP two-factor auth, and master
 * password change (full client-side vault re-encryption).
 */

import React, { useState, useEffect } from "react";
import QRCode from "qrcode";
import { motion, AnimatePresence } from "motion/react";
import { Fingerprint, KeyRound, ShieldCheck, Smartphone, Trash2, Loader2, Plus, X } from "lucide-react";
import {
  deriveUserKeys,
  deriveKeyFromPrfSecret,
  hashSHA256,
  generateSalt,
  encryptString,
  DEFAULT_KDF_ITERATIONS,
} from "../lib/crypto";
import { encryptCredentialPayload } from "../lib/vault";
import { DecryptedCredential, AuditLogEntry } from "../types";
import BiometricPrompt, { BiometricRegisterResult } from "./BiometricPrompt";

interface PasskeyInfo {
  id: number;
  label: string;
  createdAt: number;
}

interface SecurityCenterProps {
  isOpen: boolean;
  onClose: () => void;
  token: string;
  username: string;
  encryptionKey: CryptoKey;
  credentials: DecryptedCredential[];
  auditLogs: AuditLogEntry[];
  onBiometricChanged: (enabled: boolean) => void;
  onPasswordChanged: () => void;
  onAudit: (action: string, itemName: string) => void;
}

export default function SecurityCenter({
  isOpen,
  onClose,
  token,
  username,
  encryptionKey,
  credentials,
  auditLogs,
  onBiometricChanged,
  onPasswordChanged,
  onAudit,
}: SecurityCenterProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // Passkeys
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [masterInput, setMasterInput] = useState("");
  const [showMasterConfirm, setShowMasterConfirm] = useState(false);
  const [bioPromptOpen, setBioPromptOpen] = useState(false);

  // TOTP
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [totpSetup, setTotpSetup] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpQr, setTotpQr] = useState<string | null>(null);

  // Render the otpauth:// URI as a scannable QR code
  useEffect(() => {
    if (!totpSetup) {
      setTotpQr(null);
      return;
    }
    QRCode.toDataURL(totpSetup.otpauthUri, { width: 220, margin: 2 })
      .then(setTotpQr)
      .catch(() => setTotpQr(null));
  }, [totpSetup]);

  // Master password change
  const [pwCurrent, setPwCurrent] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");

  const authedFetch = (url: string, options: RequestInit = {}) =>
    fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        ...(options.headers || {}),
      },
    });

  const refreshState = async () => {
    try {
      const [pkRes, totpRes] = await Promise.all([
        authedFetch("/api/auth/webauthn/credentials"),
        authedFetch("/api/auth/totp/status"),
      ]);
      if (pkRes.ok) {
        const list = await pkRes.json();
        setPasskeys(list);
        onBiometricChanged(list.length > 0);
      }
      if (totpRes.ok) {
        const s = await totpRes.json();
        setTotpEnabled(!!s.enabled);
      }
    } catch {
      /* non-fatal */
    }
  };

  useEffect(() => {
    if (isOpen) {
      setError("");
      setNotice("");
      setTotpSetup(null);
      setTotpCode("");
      setPwCurrent("");
      setPwNew("");
      setPwConfirm("");
      setMasterInput("");
      setShowMasterConfirm(false);
      refreshState();
    }
  }, [isOpen]);

  // ------------------------------------------------------------------
  // Passkeys
  // ------------------------------------------------------------------
  const handleVerifyMasterForPasskey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!masterInput) return;
    setBusy(true);
    setError("");

    try {
      const saltRes = await fetch("/api/auth/salt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      if (!saltRes.ok) throw new Error("Unable to fetch KDF parameters.");
      const { salt, iterations } = await saltRes.json();

      const { authKeyHex } = await deriveUserKeys(masterInput, salt, iterations);
      const clientAuthHash = await hashSHA256(authKeyHex);

      const loginRes = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, authKeyHex: clientAuthHash }),
      });
      const loginData = await loginRes.json();
      // A totpRequired response still proves the password was correct.
      if (!loginRes.ok && !loginData.totpRequired) {
        throw new Error("Master password verification failed.");
      }

      setShowMasterConfirm(false);
      setBioPromptOpen(true);
    } catch (err: any) {
      setError(err.message || "Verification failed.");
    } finally {
      setBusy(false);
    }
  };

  const handleRegisterBiometrics = async (result: BiometricRegisterResult) => {
    setBioPromptOpen(false);
    setBusy(true);
    try {
      const metaKey = `securepassx-bio-meta-${username.toLowerCase()}`;
      if (result.prfSecret) {
        const wrapKey = await deriveKeyFromPrfSecret(result.prfSecret, result.prfSalt);
        const { cipherText: cipherMaster, iv } = await encryptString(masterInput, wrapKey);
        localStorage.setItem(metaKey, JSON.stringify({ v: 2, prfSalt: result.prfSalt, iv, cipherMaster }));
        setNotice("Passkey registered. Biometric login on this device will fully decrypt the vault.");
      } else {
        setNotice(
          "Passkey registered, but no PRF secret was provided - biometric login on this device will still require the master password."
        );
      }
      onAudit("setup_biometrics", "WebAuthn passkey registered");
      await refreshState();
    } catch (err: any) {
      setError(err.message || "Failed to finish passkey setup.");
    } finally {
      setMasterInput("");
      setBusy(false);
    }
  };

  const handleDeletePasskey = async (pk: PasskeyInfo) => {
    if (!confirm(`Remove passkey '${pk.label}'? Devices using it will no longer unlock via biometrics.`)) return;
    setBusy(true);
    setError("");
    try {
      const res = await authedFetch(`/api/auth/webauthn/credentials/${pk.id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to remove passkey.");
      setNotice(`Passkey '${pk.label}' removed.`);
      await refreshState();
    } catch (err: any) {
      setError(err.message || "Failed to remove passkey.");
    } finally {
      setBusy(false);
    }
  };

  // ------------------------------------------------------------------
  // TOTP
  // ------------------------------------------------------------------
  const handleTotpSetupStart = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await authedFetch("/api/auth/totp/setup", { method: "POST", body: "{}" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Setup failed.");
      setTotpSetup(data);
      setTotpCode("");
    } catch (err: any) {
      setError(err.message || "Two-factor setup failed.");
    } finally {
      setBusy(false);
    }
  };

  const handleTotpEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await authedFetch("/api/auth/totp/enable", {
        method: "POST",
        body: JSON.stringify({ code: totpCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not enable two-factor auth.");
      setTotpSetup(null);
      setTotpCode("");
      setTotpEnabled(true);
      setNotice("Two-factor authentication enabled. You'll be asked for a code at every password login.");
    } catch (err: any) {
      setError(err.message || "Could not enable two-factor auth.");
    } finally {
      setBusy(false);
    }
  };

  const handleTotpDisable = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await authedFetch("/api/auth/totp/disable", {
        method: "POST",
        body: JSON.stringify({ code: totpCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not disable two-factor auth.");
      setTotpCode("");
      setTotpEnabled(false);
      setNotice("Two-factor authentication disabled.");
    } catch (err: any) {
      setError(err.message || "Could not disable two-factor auth.");
    } finally {
      setBusy(false);
    }
  };

  // ------------------------------------------------------------------
  // Master password change (client-side re-encryption of the whole vault)
  // ------------------------------------------------------------------
  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (pwNew.length < 8) {
      setError("New master password must be at least 8 characters.");
      return;
    }
    if (pwNew !== pwConfirm) {
      setError("New master passwords do not match.");
      return;
    }

    if (
      !confirm(
        "Change the master password? The entire vault will be re-encrypted. " +
          "You will be logged out and must unlock with the NEW password. " +
          "Biometric containers on all devices must be re-registered afterwards."
      )
    ) {
      return;
    }

    setBusy(true);
    try {
      // 1. Current password proof
      const saltRes = await fetch("/api/auth/salt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      if (!saltRes.ok) throw new Error("Unable to fetch KDF parameters.");
      const { salt: oldSalt, iterations: oldIterations } = await saltRes.json();
      const { authKeyHex: oldAuthKeyHex } = await deriveUserKeys(pwCurrent, oldSalt, oldIterations);
      const currentAuthKeyHex = await hashSHA256(oldAuthKeyHex);

      // 2. New key material
      const newSalt = generateSalt();
      const { encryptionKey: newKey, authKeyHex: newAuthKeyHex } = await deriveUserKeys(
        pwNew,
        newSalt,
        DEFAULT_KDF_ITERATIONS
      );
      const newPasswordHash = await hashSHA256(newAuthKeyHex);

      // 3. Re-encrypt every credential under the new key
      const rotatedCredentials = [];
      for (const cred of credentials) {
        rotatedCredentials.push(
          await encryptCredentialPayload(
            {
              id: cred.id,
              title: cred.title,
              username: cred.username,
              password: cred.password,
              url: cred.url,
              notes: cred.notes,
              category: cred.category,
            },
            newKey
          )
        );
      }

      // 4. Re-encrypt the E2EE audit entries we have loaded
      const rotatedAudits = [];
      for (const log of auditLogs) {
        if (!log.e2ee) continue;
        const { cipherText, iv } = await encryptString(log.itemName, newKey);
        rotatedAudits.push({ id: log.id, itemNameEnc: cipherText, iv });
      }

      // 5. Atomic swap on the server
      const res = await authedFetch("/api/vault/rotate", {
        method: "POST",
        body: JSON.stringify({
          currentAuthKeyHex,
          newPasswordHash,
          newSalt,
          iterations: DEFAULT_KDF_ITERATIONS,
          credentials: rotatedCredentials,
          audits: rotatedAudits,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Rotation failed.");

      // 6. Stale biometric container would unwrap to the OLD password - remove it
      localStorage.removeItem(`securepassx-bio-meta-${username.toLowerCase()}`);

      alert(
        "Master password changed and vault re-encrypted. You will now be locked out - " +
          "unlock with your NEW password, then re-register biometrics on each device."
      );
      onPasswordChanged();
    } catch (err: any) {
      setError(err.message || "Master password change failed.");
      setBusy(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl p-6 text-left text-slate-100 max-h-[85vh] overflow-y-auto scrollbar"
      >
        <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-4">
          <h3 className="font-sans font-bold text-base text-white flex items-center gap-1.5 uppercase tracking-wider">
            <ShieldCheck className="w-5 h-5 text-emerald-500" />
            Security Center
          </h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white cursor-pointer">
            <X className="w-5 h-5" />
          </button>
        </div>

        <AnimatePresence>
          {notice && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="mb-4 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-300 text-xs"
            >
              {notice}
            </motion.div>
          )}
          {error && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="mb-4 p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-300 text-xs"
            >
              {error}
            </motion.div>
          )}
        </AnimatePresence>

        {/* ------------------------------------------------ Passkeys */}
        <section className="mb-6">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
            <Fingerprint className="w-4 h-4 text-blue-400" />
            Biometric Passkeys
          </h4>
          <div className="space-y-2">
            {passkeys.length === 0 && (
              <p className="text-xs text-slate-500">No passkeys registered yet.</p>
            )}
            {passkeys.map((pk) => (
              <div
                key={pk.id}
                className="flex justify-between items-center bg-[#020617] border border-slate-800 rounded-xl px-3 py-2 text-xs"
              >
                <div className="flex flex-col">
                  <span className="text-slate-200 font-semibold">{pk.label}</span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    Added {new Date(pk.createdAt).toLocaleDateString()}
                  </span>
                </div>
                <button
                  onClick={() => handleDeletePasskey(pk)}
                  disabled={busy}
                  className="p-1.5 text-slate-500 hover:text-rose-400 cursor-pointer"
                  title="Remove passkey"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>

          {!showMasterConfirm ? (
            <button
              onClick={() => setShowMasterConfirm(true)}
              disabled={busy}
              className="mt-3 w-full py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-xs font-semibold text-slate-200 flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5 text-emerald-500" />
              Register this device
            </button>
          ) : (
            <form onSubmit={handleVerifyMasterForPasskey} className="mt-3 space-y-2">
              <input
                type="password"
                required
                value={masterInput}
                onChange={(e) => setMasterInput(e.target.value)}
                placeholder="Confirm master password to continue"
                className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-600 font-sans"
              />
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowMasterConfirm(false);
                    setMasterInput("");
                  }}
                  className="flex-1 py-2 bg-slate-800 border border-slate-700 rounded-xl text-xs font-semibold text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busy}
                  className="flex-1 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-xs font-bold text-white cursor-pointer disabled:opacity-50"
                >
                  {busy ? <Loader2 className="w-4 h-4 animate-spin mx-auto" /> : "Continue"}
                </button>
              </div>
            </form>
          )}
        </section>

        {/* ------------------------------------------------ TOTP */}
        <section className="mb-6 border-t border-slate-800 pt-4">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
            <Smartphone className="w-4 h-4 text-amber-400" />
            Two-Factor Authentication (TOTP)
            <span
              className={`ml-auto text-[9px] font-bold uppercase px-2 py-0.5 rounded-full ${
                totpEnabled
                  ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                  : "bg-slate-950 border border-slate-800 text-slate-500"
              }`}
            >
              {totpEnabled ? "Active" : "Off"}
            </span>
          </h4>

          {!totpEnabled && !totpSetup && (
            <button
              onClick={handleTotpSetupStart}
              disabled={busy}
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-xs font-semibold text-slate-200 cursor-pointer"
            >
              Set up authenticator app
            </button>
          )}

          {totpSetup && (
            <form onSubmit={handleTotpEnable} className="space-y-2">
              <p className="text-xs text-slate-400">
                Scan this QR code with your authenticator app (Google Authenticator, 1Password, Aegis...):
              </p>
              {totpQr && (
                <div className="flex justify-center py-1">
                  <div className="bg-white p-2.5 rounded-2xl">
                    <img src={totpQr} alt="TOTP setup QR code" width={200} height={200} className="block" />
                  </div>
                </div>
              )}
              <p className="text-[10px] text-slate-500">Or enter the secret manually:</p>
              <div className="bg-[#020617] border border-slate-800 rounded-xl p-3 font-mono text-xs text-emerald-400 break-all select-all">
                {totpSetup.secret}
              </div>
              <a
                href={totpSetup.otpauthUri}
                className="block text-[10px] text-blue-400 hover:underline truncate"
              >
                Or open otpauth:// link on this device
              </a>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                required
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                placeholder="Enter 6-digit code to confirm"
                className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-600 font-mono tracking-widest"
              />
              <button
                type="submit"
                disabled={busy || totpCode.length !== 6}
                className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-xs font-bold text-white cursor-pointer disabled:opacity-50"
              >
                Verify & Enable
              </button>
            </form>
          )}

          {totpEnabled && (
            <form onSubmit={handleTotpDisable} className="space-y-2">
              <p className="text-xs text-slate-500">
                Enter a current code to disable two-factor authentication.
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  required
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                  placeholder="6-digit code"
                  className="flex-1 bento-input py-2 px-3.5 text-xs text-white placeholder-slate-600 font-mono tracking-widest"
                />
                <button
                  type="submit"
                  disabled={busy || totpCode.length !== 6}
                  className="px-4 py-2 bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/20 rounded-xl text-xs font-bold text-rose-300 cursor-pointer disabled:opacity-50"
                >
                  Disable
                </button>
              </div>
            </form>
          )}
        </section>

        {/* ------------------------------------------------ Master password */}
        <section className="border-t border-slate-800 pt-4">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
            <KeyRound className="w-4 h-4 text-emerald-500" />
            Change Master Password
          </h4>
          <p className="text-[11px] text-slate-500 mb-3">
            Re-encrypts the entire vault ({credentials.length} entr{credentials.length === 1 ? "y" : "ies"}) with a
            new key derived from the new password. You will be locked out and biometrics must be re-registered.
          </p>
          <form onSubmit={handlePasswordChange} className="space-y-2">
            <input
              type="password"
              required
              value={pwCurrent}
              onChange={(e) => setPwCurrent(e.target.value)}
              placeholder="Current master password"
              className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-600 font-sans"
            />
            <input
              type="password"
              required
              value={pwNew}
              onChange={(e) => setPwNew(e.target.value)}
              placeholder="New master password (min 8 chars)"
              className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-600 font-sans"
            />
            <input
              type="password"
              required
              value={pwConfirm}
              onChange={(e) => setPwConfirm(e.target.value)}
              placeholder="Confirm new master password"
              className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-600 font-sans"
            />
            <button
              type="submit"
              disabled={busy}
              className="w-full py-2.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 rounded-xl text-xs font-bold text-white cursor-pointer disabled:opacity-50 flex items-center justify-center gap-1.5"
            >
              {busy ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Re-encrypting vault...
                </>
              ) : (
                "Rotate Master Password"
              )}
            </button>
          </form>
        </section>

        <BiometricPrompt
          isOpen={bioPromptOpen}
          onClose={() => setBioPromptOpen(false)}
          username={username}
          mode="register"
          token={token}
          onRegisterSuccess={handleRegisterBiometrics}
        />
      </motion.div>
    </div>
  );
}
