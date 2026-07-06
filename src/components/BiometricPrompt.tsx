/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Fingerprint, ScanEye, X, ShieldAlert, CheckCircle2 } from "lucide-react";
import {
  isWebAuthnAvailable,
  performRegistrationCeremony,
  performAuthenticationCeremony,
} from "../lib/webauthn";

export interface BiometricRegisterResult {
  prfSalt: string;
  prfSecret: ArrayBuffer | null;
}

export interface BiometricAuthResult {
  token: string;
  userId: number;
  username: string;
  prfSecret: ArrayBuffer | null;
}

interface BiometricPromptProps {
  isOpen: boolean;
  onClose: () => void;
  username: string;
  mode: "register" | "authenticate";
  /** Session token; required for register mode. */
  token?: string;
  /** PRF salt from the local key container; used in authenticate mode. */
  prfSalt?: string | null;
  onRegisterSuccess?: (result: BiometricRegisterResult) => void;
  onAuthSuccess?: (result: BiometricAuthResult) => void;
}

export default function BiometricPrompt({
  isOpen,
  onClose,
  username,
  mode,
  token,
  prfSalt,
  onRegisterSuccess,
  onAuthSuccess,
}: BiometricPromptProps) {
  const [status, setStatus] = useState<"idle" | "scanning" | "success" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState("");
  const [bioType, setBioType] = useState<"fingerprint" | "faceid">("fingerprint");

  useEffect(() => {
    if (isOpen) {
      setStatus("idle");
      setErrorMessage("");
      setBioType(Math.random() > 0.5 ? "fingerprint" : "faceid");
    }
  }, [isOpen]);

  const fetchJson = async (url: string, body: unknown, authToken?: string) => {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || "Biometric server request failed.");
    }
    return data;
  };

  // Registration: create the credential, verify it server-side, then run one
  // authentication ceremony with the PRF extension to obtain the local
  // key-wrapping secret.
  const runRegistration = async () => {
    if (!token) throw new Error("Missing session token for biometric setup.");

    const options = await fetchJson("/api/auth/webauthn/register/options", {}, token);
    const { responseJSON, prfEnabled } = await performRegistrationCeremony(options);

    // Human-readable device label for the passkey list
    const ua = navigator.userAgent;
    const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /Firefox\//.test(ua) ? "Firefox" : "Browser";
    const platform = /Mac/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : "Device";
    const label = `${browser} on ${platform}`;

    await fetchJson("/api/auth/webauthn/register/verify", { response: responseJSON, label }, token);

    // Evaluate PRF via an immediate authentication ceremony.
    // 32 random bytes as a single valid base64 string.
    const saltBytes = new Uint8Array(32);
    window.crypto.getRandomValues(saltBytes);
    let saltBinary = "";
    saltBytes.forEach((b) => (saltBinary += String.fromCharCode(b)));
    const newPrfSalt = window.btoa(saltBinary);

    let prfSecret: ArrayBuffer | null = null;
    if (!prfEnabled) {
      console.warn("[webauthn] Authenticator reported prf.enabled !== true at creation; skipping PRF evaluation.");
    } else {
      try {
        const authOptions = await fetchJson("/api/auth/webauthn/login/options", { username });
        const authResult = await performAuthenticationCeremony(authOptions, newPrfSalt);
        await fetchJson("/api/auth/webauthn/login/verify", {
          username,
          response: authResult.responseJSON,
        });
        prfSecret = authResult.prfSecret;
        if (!prfSecret) {
          console.warn("[webauthn] PRF enabled at creation but no results returned at assertion.");
        }
      } catch (err) {
        console.warn("PRF evaluation unavailable; biometric unlock will require master password.", err);
      }
    }

    setStatus("success");
    setTimeout(() => onRegisterSuccess?.({ prfSalt: newPrfSalt, prfSecret }), 800);
  };

  // Authentication: server-verified WebAuthn assertion (challenge/signature),
  // with PRF evaluated against the stored salt for key recovery.
  const runAuthentication = async () => {
    const options = await fetchJson("/api/auth/webauthn/login/options", { username });
    const { responseJSON, prfSecret } = await performAuthenticationCeremony(options, prfSalt || null);
    const verifyData = await fetchJson("/api/auth/webauthn/login/verify", {
      username,
      response: responseJSON,
    });

    setStatus("success");
    setTimeout(
      () =>
        onAuthSuccess?.({
          token: verifyData.token,
          userId: verifyData.userId,
          username: verifyData.username,
          prfSecret,
        }),
      800
    );
  };

  const handleStartBiometric = async () => {
    setStatus("scanning");
    setErrorMessage("");

    try {
      if (!isWebAuthnAvailable()) {
        throw new Error("WebAuthn is not available in this browser/context (HTTPS or localhost required).");
      }
      if (mode === "register") {
        await runRegistration();
      } else {
        await runAuthentication();
      }
    } catch (err: any) {
      console.error("WebAuthn ceremony failed:", err);
      setErrorMessage(err?.message || "Biometric ceremony failed.");
      setStatus("error");
    }
  };

  if (!isOpen) return null;

  return (
    <div id="biometric-prompt-modal" className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 15 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 15 }}
        className="relative w-full max-w-sm bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 text-center text-slate-100"
      >
        <button
          onClick={onClose}
          id="btn-close-biometric"
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        <h3 className="font-sans font-semibold text-lg text-slate-200 mt-2">
          {mode === "register" ? "Set Up Biometric Key" : "Biometric Vault Unlock"}
        </h3>
        <p className="font-sans text-xs text-slate-400 mt-1 px-4">
          {mode === "register"
            ? `Associate Face ID or Touch ID biometric credentials with your local database for ${username}.`
            : `Log in securely using device credentials saved for ${username}.`}
        </p>

        <div className="my-8 flex flex-col items-center justify-center min-h-[160px]">
          <AnimatePresence mode="wait">
            {status === "idle" && (
              <motion.button
                key="btn-idle"
                onClick={handleStartBiometric}
                id="btn-activate-scanner"
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.9, opacity: 0 }}
                whileHover={{ scale: 1.05 }}
                className="flex flex-col items-center justify-center gap-3 p-6 bg-slate-800/50 hover:bg-slate-800 border border-slate-700/60 rounded-full cursor-pointer group transition-all"
              >
                {bioType === "fingerprint" ? (
                  <Fingerprint className="w-12 h-12 text-teal-400 group-hover:text-teal-300 transition-colors" />
                ) : (
                  <ScanEye className="w-12 h-12 text-sky-400 group-hover:text-sky-300 transition-colors" />
                )}
                <span className="font-mono text-[10px] text-slate-400 uppercase tracking-widest font-semibold group-hover:text-slate-300">
                  Tap to Scan
                </span>
              </motion.button>
            )}

            {status === "scanning" && (
              <motion.div
                key="scanning-state"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center"
              >
                <div className="relative w-24 h-24 flex items-center justify-center">
                  {/* Glowing Radar Rings */}
                  <motion.div
                    animate={{ scale: [1, 1.3, 1], opacity: [0.6, 0, 0.6] }}
                    transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
                    className={`absolute inset-0 rounded-full border ${
                      bioType === "fingerprint" ? "border-teal-500/50 bg-teal-500/5" : "border-sky-500/50 bg-sky-500/5"
                    }`}
                  />
                  <motion.div
                    animate={{ scale: [1, 1.5, 1], opacity: [0.4, 0, 0.4] }}
                    transition={{ repeat: Infinity, duration: 2.5, ease: "easeInOut", delay: 0.4 }}
                    className={`absolute inset-0 rounded-full border ${
                      bioType === "fingerprint" ? "border-teal-500/30" : "border-sky-500/30"
                    }`}
                  />

                  {/* Icon with Scanning Beam Overlay */}
                  <div className="relative p-5 bg-slate-800 border border-slate-700 rounded-full overflow-hidden">
                    {bioType === "fingerprint" ? (
                      <Fingerprint className="w-10 h-10 text-teal-500" />
                    ) : (
                      <ScanEye className="w-10 h-10 text-sky-500" />
                    )}

                    {/* Laser Scanner Beam */}
                    <motion.div
                      animate={{ y: [-15, 60, -15] }}
                      transition={{ repeat: Infinity, duration: 1.5, ease: "easeInOut" }}
                      className={`absolute left-0 right-0 h-[2px] ${
                        bioType === "fingerprint" ? "bg-teal-400 shadow-[0_0_8px_rgb(20,184,166)]" : "bg-sky-400 shadow-[0_0_8px_rgb(56,189,248)]"
                      }`}
                    />
                  </div>
                </div>

                <p className="font-mono text-xs text-slate-400 mt-4 animate-pulse">
                  Waiting for device authenticator confirmation...
                </p>
              </motion.div>
            )}

            {status === "success" && (
              <motion.div
                key="success-state"
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.9, opacity: 0 }}
                className="flex flex-col items-center justify-center text-teal-400"
              >
                <CheckCircle2 className="w-16 h-16 text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.3)] animate-bounce" />
                <h4 className="font-sans font-medium text-slate-200 mt-4 text-sm">
                  Identity Authenticated
                </h4>
                <p className="font-mono text-[10px] text-slate-500 mt-1 uppercase tracking-widest">
                  WebAuthn Signature Verified
                </p>
              </motion.div>
            )}

            {status === "error" && (
              <motion.div
                key="error-state"
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.9, opacity: 0 }}
                className="flex flex-col items-center justify-center text-rose-400"
              >
                <ShieldAlert className="w-16 h-16 text-rose-500" />
                <p className="font-sans text-xs text-rose-300 mt-3 font-medium">
                  Authentication Rejected
                </p>
                <p className="font-mono text-[10px] text-slate-500 mt-1 px-4">
                  {errorMessage || "Biometrics verification cancelled."}
                </p>
                <button
                  onClick={handleStartBiometric}
                  className="mt-4 px-3 py-1 bg-rose-500/25 hover:bg-rose-500/40 text-rose-200 text-xs rounded-lg transition-all"
                >
                  Retry Scan
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <div className="flex justify-between items-center bg-slate-800/30 border border-slate-800/80 rounded-xl px-4 py-2 mt-4 text-left">
          <div className="flex flex-col">
            <span className="font-sans text-[10px] text-slate-500 uppercase font-semibold">
              E2EE Security Scheme
            </span>
            <span className="font-mono text-[11px] text-slate-300">
              AES-GCM-256 / PBKDF2
            </span>
          </div>
          <div className="h-6 w-[1px] bg-slate-800" />
          <div className="flex flex-col text-right">
            <span className="font-sans text-[10px] text-slate-500 uppercase font-semibold">
              Authenticator
            </span>
            <span className="font-mono text-[11px] text-emerald-500 font-semibold uppercase">
              WebAuthn + PRF
            </span>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
