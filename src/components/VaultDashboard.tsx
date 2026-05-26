/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from "react";
import {
  Search,
  Plus,
  Lock,
  LogOut,
  FolderKey,
  Database,
  ShieldCheck,
  Clipboard,
  Star,
  Trash2,
  Settings,
  ShieldAlert,
  Loader2,
  ExternalLink,
  History,
  HardDriveDownload,
  Fingerprint,
  Check,
  Sparkles,
  RefreshCw,
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { encryptString, decryptString, generateSalt } from "../lib/crypto";
import { DecryptedCredential, EncryptedCredential, Category, AuditLogEntry } from "../types";
import PasswordGenerator from "./PasswordGenerator";
import BiometricPrompt from "./BiometricPrompt";

interface VaultDashboardProps {
  userId: number;
  username: string;
  encryptionKey: CryptoKey;
  token: string;
  initialBiometricEnabled: boolean;
  onLockSession: () => void;
}

export default function VaultDashboard({
  userId,
  username,
  encryptionKey,
  token,
  initialBiometricEnabled,
  onLockSession,
}: VaultDashboardProps) {
  // Credentials catalogs
  const [credentials, setCredentials] = useState<DecryptedCredential[]>([]);
  const [filteredCreds, setFilteredCreds] = useState<DecryptedCredential[]>([]);
  const [selectedCred, setSelectedCred] = useState<DecryptedCredential | null>(null);

  // Loading/Sync states
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  // Search & Categories filters
  const [searchQuery, setSearchQuery] = useState("");
  const [activeCategory, setActiveCategory] = useState<Category>("All");

  // Editing Forms states
  const [editingCred, setEditingCred] = useState<Partial<DecryptedCredential> | null>(null);
  const [showFormModal, setShowFormModal] = useState(false);
  const [formPassVisible, setFormPassVisible] = useState(false);

  // Active password generator modal / drawer
  const [showGeneratorModal, setShowGeneratorModal] = useState(false);

  // Audit Logs activities
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);

  // Biometrics parameters
  const [biometricEnabled, setBiometricEnabled] = useState(initialBiometricEnabled);
  const [bioPromptOpen, setBioPromptOpen] = useState(false);
  const [confirmMasterForBio, setConfirmMasterForBio] = useState(false);
  const [masterConfirmInput, setMasterConfirmInput] = useState("");

  // Quick Key seed generator
  const [localQuickKey, setLocalQuickKey] = useState("xK9#v2_PqL!8mM@z");
  const [quickKeyCopied, setQuickKeyCopied] = useState(false);

  // Clipboard feedbacks
  const [clipboardFeedback, setClipboardFeedback] = useState<{ id: string; field: "username" | "password" | "copied" } | null>(null);

  // Session lockers limits (Inactivity Timeout)
  const [secondsRemaining, setSecondsRemaining] = useState(300); // 5 minutes inactivity timer
  const lastActiveRef = useRef<number>(Date.now());

  // Category Colors Mapping
  const getCategoryColor = (cat: Category) => {
    switch (cat) {
      case "Work":
        return "text-blue-400 border-blue-500/20 bg-blue-500/5";
      case "Finance":
        return "text-emerald-400 border-emerald-500/20 bg-emerald-500/5";
      case "Social":
        return "text-rose-400 border-rose-500/20 bg-rose-500/5";
      case "Entertainment":
        return "text-indigo-400 border-indigo-500/20 bg-indigo-500/5";
      case "Developer":
        return "text-amber-400 border-amber-500/20 bg-amber-500/5";
      case "Secure Notes":
        return "text-cyan-400 border-cyan-500/20 bg-cyan-500/5";
      case "Favorites":
        return "text-yellow-400 border-yellow-500/20 bg-yellow-500/5";
      default:
        return "text-slate-400 border-slate-800 bg-slate-950";
    }
  };

  // 1. Inactivity checking & Session timer
  useEffect(() => {
    const activityTrigger = () => {
      lastActiveRef.current = Date.now();
      setSecondsRemaining(300);
    };

    window.addEventListener("mousemove", activityTrigger);
    window.addEventListener("keydown", activityTrigger);
    window.addEventListener("click", activityTrigger);

    const timer = setInterval(() => {
      const elapsed = Math.floor((Date.now() - lastActiveRef.current) / 1000);
      const remaining = Math.max(0, 300 - elapsed);
      setSecondsRemaining(remaining);

      if (remaining <= 0) {
        clearInterval(timer);
        logAuditEntry("auto-lock", "Inactivity timer threshold reached");
        onLockSession();
      }
    }, 1000);

    return () => {
      window.removeEventListener("mousemove", activityTrigger);
      window.removeEventListener("keydown", activityTrigger);
      window.removeEventListener("click", activityTrigger);
      clearInterval(timer);
    };
  }, [onLockSession]);

  // 2. Load and decrypt credentials initially
  const loadVaultCredentials = async () => {
    setLoading(true);
    setErrorMessage("");
    try {
      const res = await fetch("/api/credentials", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        throw new Error("Failed to synchronize with backend vaults.");
      }

      const rawEncryptedList: EncryptedCredential[] = await res.json();

      // Decrypt all rows CLIENT-SIDE (E2E)
      const decryptedList: DecryptedCredential[] = [];
      for (const item of rawEncryptedList) {
        try {
          const title = await decryptString(item.title, item.iv, encryptionKey);
          const usernameVal = item.usernameEnc ? await decryptString(item.usernameEnc, item.iv, encryptionKey) : "";
          const passwordVal = item.passwordEnc ? await decryptString(item.passwordEnc, item.iv, encryptionKey) : "";
          const urlVal = item.urlEnc ? await decryptString(item.urlEnc, item.iv, encryptionKey) : "";
          const notesVal = item.notesEnc ? await decryptString(item.notesEnc, item.iv, encryptionKey) : "";
          const categoryVal = item.category ? await decryptString(item.category, item.iv, encryptionKey) : "General";

          decryptedList.push({
            id: item.id,
            title,
            username: usernameVal,
            password: passwordVal,
            url: urlVal,
            notes: notesVal,
            category: categoryVal,
            modifiedAt: item.modifiedAt,
          });
        } catch (decryptErr) {
          console.error("Single credential decryption failed (probably keys issue):", decryptErr);
        }
      }

      setCredentials(decryptedList);
      setFilteredCreds(decryptedList);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to load credentials.");
    } finally {
      setLoading(false);
    }
  };

  // Helper audit logger to host
  const logAuditEntry = async (action: string, itemName: string) => {
    try {
      await fetch("/api/audits", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ action, itemName }),
      });
      refreshAuditLogs();
    } catch (err) {
      console.error("Audit log creation error:", err);
    }
  };

  const refreshAuditLogs = async () => {
    try {
      const res = await fetch("/api/audits", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data);
      }
    } catch (err) {
      console.error("Failed to sync audit logs stream:", err);
    }
  };

  const generateQuickKey = () => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|";
    let res = "";
    for (let i = 0; i < 16; i++) {
      res += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setLocalQuickKey(res);
  };

  const handleRefreshQuickKey = (e: React.MouseEvent) => {
    e.stopPropagation();
    generateQuickKey();
  };

  const handleCopyQuickKey = (keyText: string) => {
    navigator.clipboard.writeText(keyText);
    setQuickKeyCopied(true);
    setTimeout(() => setQuickKeyCopied(false), 1500);
    logAuditEntry("copy_password", "Quick Generated Key");
  };

  useEffect(() => {
    if (token) {
      loadVaultCredentials();
      refreshAuditLogs();
      generateQuickKey();
    }
  }, [token]);

  // 3. Search and filter credentials on category or query update
  useEffect(() => {
    let result = credentials;

    // Filter by Category
    if (activeCategory === "Favorites") {
      const favList = JSON.parse(localStorage.getItem(`securepassx-favs-${userId}`) || "[]");
      result = result.filter((c) => favList.includes(c.id));
    } else if (activeCategory !== "All") {
      result = result.filter((c) => c.category === activeCategory);
    }

    // Filter by Search Query
    if (searchQuery.trim()) {
      const lowered = searchQuery.toLowerCase();
      result = result.filter(
          (c) =>
              c.title.toLowerCase().includes(lowered) ||
              c.username.toLowerCase().includes(lowered) ||
              c.url.toLowerCase().includes(lowered) ||
              c.notes.toLowerCase().includes(lowered)
      );
    }

    setFilteredCreds(result);
  }, [searchQuery, activeCategory, credentials]);

  // Favorite toggle helpers
  const handleToggleFavorite = (credId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const favKey = `securepassx-favs-${userId}`;
    const favs = JSON.parse(localStorage.getItem(favKey) || "[]");
    let updatedFavs: string[];

    if (favs.includes(credId)) {
      updatedFavs = favs.filter((id: string) => id !== credId);
      logAuditEntry("unfavorite_item", credId);
    } else {
      updatedFavs = [...favs, credId];
      logAuditEntry("favorite_item", credId);
    }
    localStorage.setItem(favKey, JSON.stringify(updatedFavs));

    // Quick refresh of results by triggering React reference update
    setCredentials([...credentials]);
  };

  const isFavorite = (credId: string) => {
    const favs = JSON.parse(localStorage.getItem(`securepassx-favs-${userId}`) || "[]");
    return favs.includes(credId);
  };

  // 4. Create or Update Credential Action (E2EE Client-side)
  const handleSaveCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingCred?.title) {
      alert("Title is a required parameter.");
      return;
    }

    setSyncing(true);
    setErrorMessage("");

    try {
      const itemTitle = editingCred.title.trim();
      const itemUser = editingCred.username || "";
      const itemPass = editingCred.password || "";
      const itemUrl = editingCred.url || "";
      const itemNotes = editingCred.notes || "";
      const itemCat = editingCred.category || "General";
      const itemId = editingCred.id || crypto.randomUUID();

      const isNew = !editingCred.id;
      const { cipherText: titleEnc, iv: titleIv } = await encryptString(itemTitle, encryptionKey);

      // Use the SAME IV for all columns of this entry for easy mapping and clean transmission
      const ivBuffer = window.atob(titleIv);
      const ivUint8 = new Uint8Array(ivBuffer.length);
      for (let i = 0; i < ivBuffer.length; i++) {
        ivUint8[i] = ivBuffer.charCodeAt(i);
      }

      const encryptWithIv = async (text: string) => {
        const encoder = new TextEncoder();
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: ivUint8 },
            encryptionKey,
            encoder.encode(text)
        );
        const bytes = new Uint8Array(encrypted);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
      };

      const userEnc = await encryptWithIv(itemUser);
      const passEnc = await encryptWithIv(itemPass);
      const urlEnc = await encryptWithIv(itemUrl);
      const notesEnc = await encryptWithIv(itemNotes);
      const catEnc = await encryptWithIv(itemCat);

      const bodyPayload = {
        id: itemId,
        title: titleEnc,
        usernameEnc: userEnc,
        passwordEnc: passEnc,
        urlEnc,
        notesEnc,
        category: catEnc,
        iv: titleIv,
        modifiedAt: Date.now(),
      };

      const endpoint = isNew ? "/api/credentials" : `/api/credentials/${itemId}`;
      const method = isNew ? "POST" : "PUT";

      const res = await fetch(endpoint, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(bodyPayload),
      });

      if (!res.ok) {
        throw new Error(isNew ? "Failed to save E2EE database." : "Failed to update E2EE database.");
      }

      setSuccessMessage(isNew ? "Credential encrypted and added!" : "Credential updated successfully!");
      logAuditEntry(isNew ? "create" : "update", itemTitle);

      await loadVaultCredentials();
      setShowFormModal(false);
      setEditingCred(null);
      setSelectedCred(null);
    } catch (err: any) {
      setErrorMessage(err.message || "E2E Secure write operations failed.");
    } finally {
      setSyncing(false);
    }
  };

  // 5. Delete Credential Action
  const handleDeleteCredential = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to completely purge '${name}' from your vault?`)) {
      return;
    }

    setSyncing(true);
    setErrorMessage("");

    try {
      const res = await fetch(`/api/credentials/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        throw new Error("Unable to purge target credential.");
      }

      setSuccessMessage("Credential purged successfully.");
      logAuditEntry("delete", name);

      const favKey = `securepassx-favs-${userId}`;
      const favs = JSON.parse(localStorage.getItem(favKey) || "[]");
      localStorage.setItem(favKey, JSON.stringify(favs.filter((fId: string) => fId !== id)));

      await loadVaultCredentials();
      setSelectedCred(null);
    } catch (err: any) {
      setErrorMessage(err.message || "Purge request failed.");
    } finally {
      setSyncing(false);
    }
  };

  // Copy helper with timer feeds
  const handleCopyToClipboard = (id: string, text: string, field: "username" | "password" | "copied", title: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setClipboardFeedback({ id, field });
    logAuditEntry(`copy_${field}`, title);
    setTimeout(() => setClipboardFeedback(null), 1500);
  };

  // 6. Security score rating logic (Dynamic)
  const calculateVaultSecurityScore = () => {
    if (credentials.length === 0) return 98; // High standard base metrics
    let totalScore = 0;
    credentials.forEach((c) => {
      const pass = c.password || "";
      let score = 50;
      if (pass.length >= 12) score += 20;
      if (pass.length >= 16) score += 30;
      if (/[a-z]/.test(pass)) score += 5;
      if (/[A-Z]/.test(pass)) score += 5;
      if (/[0-9]/.test(pass)) score += 5;
      if (/[^A-Za-z0-9]/.test(pass)) score += 5;
      totalScore += Math.min(100, score);
    });
    return Math.round(totalScore / credentials.length);
  };

  // Calculated DB Size
  const dbSizeKB = credentials.length > 0 ? (credentials.length * 1.8 + 4.2).toFixed(1) : "4.0";

  // Export functions
  const handleExportVault = (encryptionMode: "decrypted" | "encrypted") => {
    try {
      if (credentials.length === 0) {
        alert("Empty vault. Nothing to export.");
        return;
      }

      let fileContent = "";
      let fileName = "";

      if (encryptionMode === "decrypted") {
        if (!confirm("Caution: Exporting decrypted data output will write clear plaintext passwords into your local file system. Proceed?")) {
          return;
        }
        fileContent = JSON.stringify(credentials, null, 2);
        fileName = `securepassx-unencrypted-${username}-${Date.now()}.json`;
        logAuditEntry("export_decrypted", "Decrypted JSON file generated");
      } else {
        alert("Creating an export encrypted with your active Master Password...");
        const backupBundle = {
          exportDate: Date.now(),
          owner: username,
          exportSchema: "SecurePassX-v1.0",
          credentials: credentials.map((c) => ({
            id: c.id,
            title: c.title,
            username: c.username,
            password: c.password,
            url: c.url,
            notes: c.notes,
            category: c.category,
          })),
        };
        fileContent = JSON.stringify(backupBundle, null, 2);
        fileName = `securepassx-encrypted-${username}-${Date.now()}.json`;
        logAuditEntry("export_encrypted", "Master backup E2EE JSON package generated");
      }

      const blob = new Blob([fileContent], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("Export failed: " + err);
    }
  };

  // Biometrics configurations
  const handleRegisterBiometrics = async (credentialId: string, signature: string) => {
    setBioPromptOpen(false);
    setSyncing(true);

    try {
      const res = await fetch("/api/auth/biometric/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          credentialId,
          publicKey: signature,
        }),
      });

      if (!res.ok) {
        throw new Error("Local databases failed to map Touch ID registry.");
      }

      const bioSalt = generateSalt();
      const bioKey = await window.crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(signature),
          { name: "PBKDF2" },
          false,
          ["deriveKey"]
      )
          .then((baseKey) =>
              window.crypto.subtle.deriveKey(
                  {
                    name: "PBKDF2",
                    salt: new TextEncoder().encode(bioSalt),
                    iterations: 100000,
                    hash: "SHA-256",
                  },
                  baseKey,
                  { name: "AES-GCM", length: 256 },
                  false,
                  ["encrypt"]
              )
          );

      const encoder = new TextEncoder();
      const rawData = encoder.encode(masterConfirmInput);
      const bioIv = window.crypto.getRandomValues(new Uint8Array(12));

      const encryptedBuffer = await window.crypto.subtle.encrypt(
          { name: "AES-GCM", iv: bioIv },
          bioKey,
          rawData
      );

      const cipherPassword = window.btoa(
          Array.from(new Uint8Array(encryptedBuffer))
              .map((b) => String.fromCharCode(b))
              .join("")
      );

      const ivBase64 = window.btoa(
          Array.from(bioIv)
              .map((b) => String.fromCharCode(b))
              .join("")
      );

      const storageObj = {
        salt: bioSalt,
        iv: ivBase64,
        cipherPassword,
      };

      localStorage.setItem(`securepassx-bio-meta-${username.toLowerCase()}`, JSON.stringify(storageObj));

      setBiometricEnabled(true);
      setSuccessMessage("Device Biometric Touch ID / Face ID mapping successful!");
      logAuditEntry("setup_biometrics", "WebAuthn signature bindings configured");
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to configure biometric encryption.");
    } finally {
      setSyncing(false);
      setMasterConfirmInput("");
      setConfirmMasterForBio(false);
    }
  };

  const handleVerifyMasterForBio = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!masterConfirmInput) return;

    setSyncing(true);
    setErrorMessage("");

    try {
      const saltRes = await fetch("/api/auth/salt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });

      if (!saltRes.ok) {
        throw new Error("Unable to authenticate master salt.");
      }

      const { salt } = await saltRes.json();
      const loginRes = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          authKeyHex: masterConfirmInput,
        }),
      });

      if (!loginRes.ok) {
        throw new Error("Invalid password verification.");
      }

      setConfirmMasterForBio(false);
      setBioPromptOpen(true);
    } catch (err) {
      setErrorMessage("Passphrase confirmation failed. Unable to map biometrics.");
    } finally {
      setSyncing(false);
    }
  };

  return (
      <div className="min-h-screen bg-[#020617] text-slate-100 font-sans antialiased relative px-4 py-6 md:p-8 select-none">
        {/* Subtle Ambient Glows */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#10b98103_1px,transparent_1px),linear-gradient(to_bottom,#10b98103_1px,transparent_1px)] bg-[size:3rem_3rem] pointer-events-none" />
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/[0.015] rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/[0.015] rounded-full blur-3xl pointer-events-none" />

        <div className="max-w-7xl mx-auto flex flex-col gap-6 relative z-10">
          {/* HEADER SECTION */}
          <header className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 px-2">
            <div className="flex items-center gap-3">
              <div className="bg-emerald-500/10 p-2.5 rounded-2xl border border-emerald-500/20 text-emerald-500">
                <FolderKey className="w-6 h-6" />
              </div>
              <div className="text-left">
                <h1 className="text-2.5xl text-2xl font-bold tracking-tight text-white font-display flex items-center">
                  SecurePass<span className="text-emerald-500">X</span>
                  <span className="text-emerald-500 font-mono text-sm ml-2 font-normal opacity-80">v2.4.0</span>
                </h1>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">SQLite Defensive End-to-End Vault</p>
              </div>
            </div>

            <div className="flex items-center flex-wrap gap-3 sm:gap-4 md:gap-6 text-sm font-medium">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
                <span className="status-dot bg-emerald-500 animate-pulse"></span>
                <span>Vault Unlocked</span>
              </div>
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-slate-400 text-xs">
                <span className="status-dot bg-slate-600"></span>
                <span>SQLite: encrypted.db</span>
              </div>

              {/* Utility shortcuts */}
              <button
                  onClick={() => setShowLogsModal(true)}
                  className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-teal-400 rounded-xl transition-all cursor-pointer"
                  title="View audit logs"
              >
                <History className="w-4 h-4" />
              </button>

              <button
                  onClick={() => setShowGeneratorModal(true)}
                  className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-emerald-400 rounded-xl transition-all cursor-pointer"
                  title="Interactive pass builder"
              >
                <Sparkles className="w-4 h-4" />
              </button>

              <div className="flex items-center gap-2">
                <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-emerald-500/15 to-blue-500/15 border border-slate-800 flex items-center justify-center text-xs font-bold text-emerald-400 font-mono">
                  {username.substring(0, 2).toUpperCase()}
                </div>
                <button
                    onClick={onLockSession}
                    className="p-2 bg-slate-900 hover:bg-rose-500/10 border border-slate-800 hover:border-rose-500/20 text-slate-400 hover:text-rose-400 rounded-xl transition-all cursor-pointer"
                    title="Lock session"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            </div>
          </header>

          {/* MESSAGES */}
          <AnimatePresence>
            {successMessage && (
                <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="flex justify-between items-center p-3.5 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl text-emerald-300 text-xs text-left"
                >
                  <span>{successMessage}</span>
                  <button onClick={() => setSuccessMessage("")} className="text-emerald-400 hover:text-white font-bold text-sm px-2">×</button>
                </motion.div>
            )}
            {errorMessage && (
                <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="flex justify-between items-center p-3.5 bg-rose-500/10 border border-rose-500/20 rounded-2xl text-rose-300 text-xs text-left"
                >
                  <span>{errorMessage}</span>
                  <button onClick={() => setErrorMessage("")} className="text-rose-400 hover:text-white font-bold text-sm px-2">×</button>
                </motion.div>
            )}
          </AnimatePresence>

          {/* MAIN BENTO GRID */}
          <main className="grid grid-cols-1 md:grid-cols-12 gap-5 items-stretch">
            {/* CARD 1: SECURE VAULT (12 col-span / 8 col-span lg) */}
            <div className="col-span-12 lg:col-span-8 flex flex-col justify-between bento-card p-6 min-h-[580px]">
              <div>
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-5 text-left">
                  <div>
                    <h2 className="text-lg font-bold text-white font-display">Secure Vault</h2>
                    <p className="text-xs text-slate-500">Decentered Client-Side Zero Knowledge Records</p>
                  </div>

                  <div className="relative w-full sm:w-64">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search secrets..."
                        className="w-full bg-[#020617] border border-slate-800 rounded-xl py-2 pl-9 pr-4 text-xs font-sans focus:border-emerald-500 outline-none text-white transition-all placeholder-slate-600"
                    />
                  </div>
                </div>

                {/* Categories Bar */}
                <div className="flex gap-1.5 overflow-x-auto pb-3.5 no-scrollbar border-b border-slate-800/60 mb-5 select-none text-xs">
                  {(["All", "Favorites", "General", "Work", "Finance", "Social", "Entertainment", "Developer", "Secure Notes"] as Category[]).map((cat) => {
                    const count = cat === "All"
                        ? credentials.length
                        : cat === "Favorites"
                        ? credentials.filter(c => isFavorite(c.id)).length
                        : credentials.filter(c => c.category === cat).length;

                    return (
                        <button
                            key={cat}
                            onClick={() => {
                              setActiveCategory(cat);
                              setSelectedCred(null);
                            }}
                            className={`flex-shrink-0 px-3.5 py-1.5 rounded-xl font-medium transition-all cursor-pointer ${
                                activeCategory === cat
                                    ? "bg-emerald-500/15 border border-emerald-500/35 text-emerald-400"
                                    : "bg-slate-900/40 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
                            }`}
                        >
                          <span className="mr-1 opacity-60">•</span>
                          <span>{cat}</span>
                          {count > 0 && (
                              <span className="ml-1.5 font-mono text-[9px] bg-slate-950 px-1.5 py-0.5 rounded-full text-slate-500 font-bold">
                            {count}
                          </span>
                          )}
                        </button>
                    );
                  })}
                </div>

                {/* Decrypted List stream */}
                <div className="space-y-2 overflow-y-auto max-h-[350px] pr-1 scrollbar bg-slate-950/20 p-2 rounded-2xl border border-slate-850/40">
                  {loading ? (
                      <div className="py-20 flex flex-col items-center justify-center text-slate-500 gap-2">
                        <Loader2 className="w-8 h-8 text-emerald-500 animate-spin" />
                        <span className="text-xs font-mono">Decrypting SQL tables dynamically...</span>
                      </div>
                  ) : filteredCreds.length === 0 ? (
                      <div className="py-20 text-center text-slate-500 flex flex-col items-center justify-center gap-2">
                        <Database className="w-10 h-10 text-slate-800" />
                        <p className="text-xs">No entries matching category filters.</p>
                      </div>
                  ) : (
                      filteredCreds.map((cred) => (
                          <div
                              key={cred.id}
                              onClick={() => setSelectedCred(cred)}
                              className={`p-3.5 rounded-2xl border transition-all cursor-pointer flex justify-between items-center ${
                                  selectedCred?.id === cred.id
                                      ? "bg-slate-900 border-emerald-500/45 shadow-lg"
                                      : "bg-slate-900/50 border-slate-800 hover:border-slate-705"
                              }`}
                          >
                            <div className="flex flex-col gap-1 text-left min-w-0 pr-4">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-xs text-white truncate">{cred.title}</span>
                                <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 border rounded-md uppercase ${getCategoryColor(cred.category as Category)}`}>
                                  {cred.category}
                                </span>
                              </div>
                              <span className="font-mono text-[10px] text-slate-500 truncate mt-0.5">
                            {cred.username || "no identifier"}
                          </span>
                            </div>

                            <div className="flex items-center gap-1 shrink-0">
                              <button
                                  onClick={(e) => handleToggleFavorite(cred.id, e)}
                                  className="p-1.5 hover:bg-slate-850 rounded text-slate-400 hover:text-yellow-400 transition-colors cursor-pointer"
                                  title="Star item"
                              >
                                <Star className={`w-3.5 h-3.5 ${isFavorite(cred.id) ? "fill-yellow-400 text-yellow-400" : ""}`} />
                              </button>

                              <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleCopyToClipboard(cred.id, cred.username, "username", cred.title);
                                  }}
                                  className="p-1.5 hover:bg-slate-850 rounded text-slate-400 hover:text-emerald-400 transition-colors relative cursor-pointer"
                                  title="Copy username"
                              >
                                {clipboardFeedback?.id === cred.id && clipboardFeedback?.field === "username" ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                ) : (
                                    <Clipboard className="w-3.5 h-3.5" />
                                )}
                              </button>

                              <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleCopyToClipboard(cred.id, cred.password, "password", cred.title);
                                  }}
                                  className="p-1.5 hover:bg-slate-850 rounded text-slate-400 hover:text-emerald-400 transition-colors relative cursor-pointer"
                                  title="Copy secure password"
                              >
                                {clipboardFeedback?.id === cred.id && clipboardFeedback?.field === "password" ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                ) : (
                                    <Lock className="w-3.5 h-3.5 text-emerald-500" />
                                )}
                              </button>
                            </div>
                          </div>
                      ))
                  )}
                </div>
              </div>

              <div className="mt-5">
                <button
                    onClick={() => {
                      setEditingCred({ category: activeCategory !== "All" && activeCategory !== "Favorites" ? activeCategory : "General" });
                      setShowFormModal(true);
                    }}
                    className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-1.5 transition-all shadow-md cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  Add New Password Item
                </button>
              </div>
            </div>

            {/* COLUMN LAYOUT FOR THE BIOMETRICS, RATING, SYSTEM INFO & TIMER */}
            <div className="col-span-12 lg:col-span-4 flex flex-col gap-5">
              {/* CARD 2: SECURITY SCORE */}
              <div className="bento-card p-6 flex flex-col items-center justify-center relative overflow-hidden text-center min-h-[160px]">
                <div className="absolute top-0 right-0 p-4 opacity-[0.03] text-white">
                  <ShieldCheck className="w-24 h-24" />
                </div>
                <div className="text-4xl font-extrabold text-emerald-500 mb-1 font-display">
                  {calculateVaultSecurityScore()}
                </div>
                <div className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-3.5 ml-0.5">Security Score</div>
                <div className="w-full bg-[#020617] rounded-full h-1.5 mb-2.5 border border-slate-850">
                  <div
                      className="bg-emerald-500 h-1.5 rounded-full transition-all duration-500"
                      style={{ width: `${calculateVaultSecurityScore()}%` }}
                  />
                </div>
                <p className="text-[11px] text-slate-400">
                  Your vault meets E2EE zero-knowledge security standardizations.
                </p>
              </div>

              {/* CARD 3: BIOMETRIC AUTH CONFIG */}
              <div
                  onClick={() => {
                    if (!biometricEnabled) {
                      setConfirmMasterForBio(true);
                      setSuccessMessage("");
                      setErrorMessage("");
                    }
                  }}
                  className="bento-card p-5 flex flex-col justify-between group cursor-pointer relative min-h-[160px] text-left"
              >
                <div className="absolute top-4 right-4 text-emerald-500">
                  <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${
                      biometricEnabled ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400" : "bg-slate-950 border border-slate-800 text-slate-500"
                  }`}>
                    {biometricEnabled ? "Active" : "Bypass"}
                  </span>
                </div>

                <div className="flex justify-between items-start">
                  <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 rounded-2xl text-blue-400">
                    <Fingerprint className="w-7 h-7" />
                  </div>
                </div>

                <div className="mt-3">
                  <h3 className="text-sm font-bold text-white font-display">Biometric Auth</h3>
                  <p className="text-xs text-slate-500 mt-1">
                    {biometricEnabled
                        ? "WebAuthn key active. Touch ID & Face ID instant bypass configured."
                        : "Configure TouchID or local Face ID signatures to unlock device instantly."}
                  </p>
                </div>
              </div>

              {/* CARD 4: QUICK KEY GENERATOR */}
              <div className="bento-card p-5 flex flex-col justify-between min-h-[140px] text-left">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Quick Generator</span>
                  <button
                      onClick={() => setShowGeneratorModal(true)}
                      className="text-[10px] text-emerald-500 font-semibold hover:underline cursor-pointer"
                  >
                    Custom Policies
                  </button>
                </div>

                <div className="my-2 bg-[#020617] p-3 rounded-lg border border-slate-800 font-mono text-xs break-all text-emerald-400 flex items-center justify-between relative">
                  <span className="truncate pr-8 select-all">{localQuickKey}</span>
                  <button
                      onClick={() => handleCopyQuickKey(localQuickKey)}
                      className="absolute right-2 p-1 text-slate-500 hover:text-white transition-colors cursor-pointer"
                      title="Copy Key"
                  >
                    {quickKeyCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Clipboard className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <button
                    onClick={handleRefreshQuickKey}
                    className="text-left text-[9px] font-bold text-slate-500 hover:text-white uppercase tracking-widest flex items-center gap-1 cursor-pointer"
                >
                  <RefreshCw className="w-3 h-3 text-emerald-500" />
                  Refresh Sequence
                </button>
              </div>

              {/* CARD 5: SYSTEM METRICS */}
              <div className="bento-card p-5 flex flex-col justify-between text-left">
                <div className="flex items-center gap-2 mb-3">
                  <Database className="w-4 h-4 text-slate-500" />
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">System Metrics</span>
                </div>
                <div className="grid grid-cols-2 gap-3.5">
                  <div className="bg-[#020617]/60 p-3 rounded-xl border border-slate-850">
                    <div className="text-base font-extrabold text-white font-display">{dbSizeKB} MB</div>
                    <div className="text-[9px] text-slate-500 font-mono uppercase mt-0.5">Database Size</div>
                  </div>
                  <div className="bg-[#020617]/60 p-3 rounded-xl border border-slate-850">
                    <div className="text-base font-extrabold text-emerald-400 font-display">AES-256</div>
                    <div className="text-[9px] text-slate-500 font-mono uppercase mt-0.5">Dual Cipher</div>
                  </div>
                </div>
              </div>

              {/* CARD 6: AUTO-LOCK TIMEOUT */}
              <div className="bento-card p-5 flex flex-col justify-between bg-emerald-500/[0.02] border-emerald-500/20 hover:border-emerald-505/30 text-left">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-500">Auto-Lock Sequence</span>
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                </div>

                <div className="flex flex-col mt-2">
                  <span className="text-3xl font-extrabold font-display text-white">
                    {Math.floor(secondsRemaining / 60).toString().padStart(2, "0")}:{ (secondsRemaining % 60).toString().padStart(2, "0") }
                  </span>
                  <span className="text-[10px] text-slate-500 mt-0.5">Seconds until session autolocks</span>
                </div>

                <div className="flex gap-1.5 w-full mt-3">
                  <div className={`h-1 flex-1 rounded-full transition-colors duration-300 ${secondsRemaining > 185 ? "bg-emerald-500" : "bg-slate-800"}`} />
                  <div className={`h-1 flex-1 rounded-full transition-colors duration-300 ${secondsRemaining > 90 ? "bg-emerald-500" : "bg-slate-800"}`} />
                  <div className={`h-1 flex-1 rounded-full transition-colors duration-300 ${secondsRemaining > 25 ? "bg-emerald-500" : "bg-slate-800"}`} />
                </div>
              </div>
            </div>
          </main>

          {/* Backup Action Bar details */}
          <footer className="flex flex-col sm:flex-row justify-between items-center bg-slate-900/40 border border-slate-800 p-4 rounded-3xl mt-4 gap-4 text-xs">
            <div className="text-slate-500 text-left">
              SecurePassX zero knowledge. Keep physically printed backups or master sheets.
            </div>
            <div className="flex gap-2">
              <button
                  onClick={() => handleExportVault("encrypted")}
                  className="px-3.5 py-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl font-semibold text-slate-300 hover:text-white flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <HardDriveDownload className="w-3.5 h-3.5 text-emerald-500" />
                <span>Download Encrypted Backup</span>
              </button>
              <button
                  onClick={() => handleExportVault("decrypted")}
                  className="px-3.5 py-2.5 bg-slate-900 hover:bg-rose-500/5 border border-slate-800 hover:border-rose-500/15 rounded-xl font-semibold text-slate-400 hover:text-rose-450 transition-all cursor-pointer"
              >
                <span>Plain Plaintext Export</span>
              </button>
            </div>
          </footer>
        </div>

        {/* DEC BONDING FOCUS OVERLAY MODAL */}
        <AnimatePresence>
          {selectedCred && (
              <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-3xl p-6 relative text-left shadow-2xl"
                >
                  <div className="flex justify-between items-start border-b border-slate-800 pb-3 mb-4">
                    <div>
                      <span className="text-[10px] font-mono uppercase font-bold text-slate-500 tracking-wider">
                        Decrypted Vault Item
                      </span>
                      <h3 className="font-display font-bold text-xl text-white mt-0.5">
                        {selectedCred.title}
                      </h3>
                    </div>
                    <button
                        onClick={() => setSelectedCred(null)}
                        className="text-slate-405 text-slate-500 hover:text-white hover:bg-slate-800 p-1.5 rounded-xl transition-all cursor-pointer text-xl"
                    >
                      ×
                    </button>
                  </div>

                  <div className="space-y-4">
                    {selectedCred.username && (
                        <div>
                          <span className="block text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wider mb-1 ml-1">
                            Username / Sign-In Identifier
                          </span>
                          <div className="relative flex items-center bg-[#020617] border border-slate-850 rounded-xl p-3 font-mono text-emerald-400 select-all pr-12 text-xs">
                            <span className="truncate">{selectedCred.username}</span>
                            <button
                                onClick={() => handleCopyToClipboard(selectedCred.id, selectedCred.username, "username", selectedCred.title)}
                                className="absolute right-2.5 p-1.5 text-slate-500 hover:text-white transition-colors cursor-pointer"
                            >
                              {clipboardFeedback?.id === selectedCred.id && clipboardFeedback?.field === "username" ? (
                                  <Check className="w-4 h-4 text-emerald-500" />
                              ) : (
                                  <Clipboard className="w-4 h-4" />
                              )}
                            </button>
                          </div>
                        </div>
                    )}

                    <div>
                      <span className="block text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wider mb-1 ml-1">
                        Symmetric Decrypted Key
                      </span>
                      <div className="relative flex items-center bg-[#020617] border border-slate-850 rounded-xl p-3 font-mono text-emerald-400 select-all pr-12 text-xs">
                        <span className="truncate font-semibold select-text">{selectedCred.password}</span>
                        <button
                            onClick={() => {
                              logAuditEntry("view_password", selectedCred.title);
                              handleCopyToClipboard(selectedCred.id, selectedCred.password, "password", selectedCred.title);
                            }}
                            className="absolute right-2.5 p-1.5 text-slate-500 hover:text-white transition-colors cursor-pointer"
                        >
                          {clipboardFeedback?.id === selectedCred.id && clipboardFeedback?.field === "password" ? (
                              <Check className="w-4 h-4 text-emerald-500" />
                          ) : (
                              <Clipboard className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>

                    {selectedCred.url && (
                        <div>
                          <span className="block text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-1 ml-1">
                            Domain URL Link
                          </span>
                          <div className="flex items-center justify-between bg-[#020617] border border-slate-850 rounded-xl p-3 font-mono text-sky-450 text-blue-400 text-xs">
                            <span className="truncate">{selectedCred.url}</span>
                            <a
                                href={selectedCred.url.startsWith("http") ? selectedCred.url : `https://${selectedCred.url}`}
                                target="_blank"
                                rel="noreferrer"
                                className="text-slate-500 hover:text-slate-200 shrink-0 ml-2"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          </div>
                        </div>
                    )}

                    {selectedCred.notes && (
                        <div>
                          <span className="block text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wider mb-1 ml-1">
                            Private Notes
                          </span>
                          <div className="bg-[#020617] border border-slate-850 rounded-xl p-3 text-xs text-slate-300 select-text whitespace-pre-wrap max-h-32 overflow-y-auto text-left">
                            {selectedCred.notes}
                          </div>
                        </div>
                    )}

                    <div className="flex justify-between items-center text-[9px] font-mono text-slate-650 text-slate-500 border-t border-slate-800 pt-3">
                      <span>Last SQLite Update:</span>
                      <span>{new Date(selectedCred.modifiedAt).toLocaleString()}</span>
                    </div>

                    {/* Action Panel within modal detail */}
                    <div className="flex gap-2.5 pt-2">
                      <button
                          onClick={() => {
                            setEditingCred(selectedCred);
                            setShowFormModal(true);
                          }}
                          className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-750 text-slate-200 rounded-xl font-semibold text-xs border border-slate-700 flex items-center justify-center gap-1.5 cursor-pointer"
                      >
                        <Settings className="w-4 h-4" />
                        Edit Record
                      </button>
                      <button
                          onClick={() => handleDeleteCredential(selectedCred.id, selectedCred.title)}
                          className="flex-1 py-2.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-450 border border-rose-500/10 rounded-xl font-semibold text-xs flex items-center justify-center gap-1.5 cursor-pointer"
                      >
                        <Trash2 className="w-4 h-4 text-rose-400" />
                        Purge Entry
                      </button>
                    </div>
                  </div>
                </motion.div>
              </div>
          )}
        </AnimatePresence>

        {/* SECURE CREATION/EDITION ROW MODAL */}
        <AnimatePresence>
          {showFormModal && editingCred && (
              <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl p-6 text-left text-slate-150"
                >
                  <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-4">
                    <h3 className="font-sans font-bold text-base text-white">
                      {editingCred.id ? "Modify Passphrase Profile" : "Secure E2EE Entry Profile"}
                    </h3>
                    <button
                        onClick={() => {
                          setShowFormModal(false);
                          setEditingCred(null);
                        }}
                        className="text-slate-400 hover:text-white cursor-pointer text-xl font-bold"
                    >
                      ×
                    </button>
                  </div>

                  <form onSubmit={handleSaveCredential} className="space-y-4">
                    <div className="grid grid-cols-2 gap-3.5">
                      <div>
                        <label className="block text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-1 ml-1">
                          Platform name (E2EE)
                        </label>
                        <input
                            type="text"
                            required
                            value={editingCred.title || ""}
                            onChange={(e) => setEditingCred({ ...editingCred, title: e.target.value })}
                            placeholder="ex. Stripe, Github, AWS"
                            className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-700 font-sans"
                        />
                      </div>

                      <div>
                        <label className="block text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-1 ml-1">
                          Category Type
                        </label>
                        <select
                            value={editingCred.category || "General"}
                            onChange={(e) => setEditingCred({ ...editingCred, category: e.target.value as Category })}
                            className="w-full bg-[#020617] border border-slate-800 rounded-xl py-2.5 px-3 outline-none font-sans text-xs focus:border-emerald-500 text-emerald-400 font-semibold cursor-pointer"
                        >
                          {["General", "Work", "Finance", "Social", "Entertainment", "Developer", "Secure Notes"].map((cat) => (
                              <option key={cat} value={cat}>
                                {cat}
                              </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3.5">
                      <div>
                        <label className="block text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-1 ml-1">
                          Username Identification
                        </label>
                        <input
                            type="text"
                            value={editingCred.username || ""}
                            onChange={(e) => setEditingCred({ ...editingCred, username: e.target.value })}
                            placeholder="name or standard client ID"
                            className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-700 font-sans"
                        />
                      </div>

                      <div>
                        <label className="block text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-1 ml-1">
                          Secret Password Key
                        </label>
                        <div className="relative flex items-center">
                          <input
                              type={formPassVisible ? "text" : "password"}
                              value={editingCred.password || ""}
                              onChange={(e) => setEditingCred({ ...editingCred, password: e.target.value })}
                              placeholder="Passphrase code"
                              className="w-full bento-input py-2.5 pl-3.5 pr-10 text-xs text-emerald-400 font-mono tracking-wider placeholder-slate-700"
                          />
                          <button
                              type="button"
                              onClick={() => setFormPassVisible(!formPassVisible)}
                              className="absolute right-3 text-slate-400 hover:text-white cursor-pointer"
                          >
                            <span className="text-[10px] font-mono font-bold">{formPassVisible ? "Hide" : "Show"}</span>
                          </button>
                        </div>
                      </div>
                    </div>

                    <div>
                      <label className="block text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-1 ml-1">
                        Platform Web Address
                      </label>
                      <input
                          type="text"
                          value={editingCred.url || ""}
                          onChange={(e) => setEditingCred({ ...editingCred, url: e.target.value })}
                          placeholder="https://..."
                          className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-700 font-sans"
                      />
                    </div>

                    <div>
                      <label className="block text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-1 ml-1">
                        Cipher encrypted notations
                      </label>
                      <textarea
                          value={editingCred.notes || ""}
                          onChange={(e) => setEditingCred({ ...editingCred, notes: e.target.value })}
                          placeholder="Backup PIN, SSH Key coordinates..."
                          rows={3}
                          className="w-full bento-input py-2.5 px-3.5 text-xs text-slate-300 placeholder-slate-705 placeholder-slate-700 font-sans resize-none"
                      />
                    </div>

                    {/* Integrated seed builder panel in bento card form */}
                    <div className="bg-[#020617]/40 p-3.5 rounded-2xl border border-slate-800">
                      <span className="block text-[9px] font-mono text-slate-500 uppercase tracking-widest mb-2 font-bold select-none">
                        Active password generation mapping
                      </span>
                      <PasswordGenerator
                          inline
                          onUseGenerated={(pwd) => setEditingCred({ ...editingCred, password: pwd })}
                      />
                    </div>

                    <div className="flex gap-2.5 pt-2">
                      <button
                          type="button"
                          onClick={() => {
                            setShowFormModal(false);
                            setEditingCred(null);
                          }}
                          className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-750 rounded-xl font-sans text-xs font-semibold text-slate-300 hover:text-white transition-colors cursor-pointer border border-slate-700"
                      >
                        Cancel
                      </button>
                      <button
                          type="submit"
                          disabled={syncing}
                          className="flex-1 flex items-center justify-center gap-1.5 py-2.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-505 hover:to-teal-500 rounded-xl font-sans text-xs font-bold text-white transition-all shadow-md cursor-pointer disabled:opacity-50"
                      >
                        {syncing ? (
                            <>
                              <Loader2 className="w-4 h-4 animate-spin text-white" />
                              Syncing...
                            </>
                        ) : (
                            <>
                              <Database className="w-4 h-4 text-emerald-100" />
                              Save Encrypted Row
                            </>
                        )}
                      </button>
                    </div>
                  </form>
                </motion.div>
              </div>
          )}
        </AnimatePresence>

        {/* SECURE BIOMETRICS PASSWORD CHECK POPUP */}
        <AnimatePresence>
          {confirmMasterForBio && (
              <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl p-6 text-slate-100"
                >
                  <h3 className="font-display font-bold text-base text-white text-center">
                    Enable WebAuthn biometric mapping
                  </h3>
                  <p className="font-sans text-xs text-slate-400 mt-2 text-center leading-relaxed">
                    Verify clear master vault password coordinates to safely map Face ID / Touch ID signatures.
                  </p>

                  <form onSubmit={handleVerifyMasterForBio} className="space-y-4 mt-4 text-left">
                    <div>
                      <label className="block text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-1 ml-1">
                        Master Password Phrase
                      </label>
                      <input
                          type="password"
                          required
                          value={masterConfirmInput}
                          onChange={(e) => setMasterConfirmInput(e.target.value)}
                          placeholder="Confirm Master password"
                          className="w-full bento-input py-2.5 px-3.5 text-xs text-white placeholder-slate-75 * placeholder-slate-700 font-sans"
                      />
                    </div>

                    <div className="flex gap-2.5 pt-2">
                      <button
                          type="button"
                          onClick={() => {
                            setConfirmMasterForBio(false);
                            setMasterConfirmInput("");
                          }}
                          className="flex-1 py-2 bg-slate-800 hover:bg-slate-750 text-slate-300 rounded-xl font-semibold font-sans text-xs cursor-pointer border border-slate-700"
                      >
                        Cancel
                      </button>
                      <button
                          type="submit"
                          disabled={syncing}
                          className="flex-1 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-bold font-sans text-xs rounded-xl cursor-pointer shadow-md"
                      >
                        Confirm Password
                      </button>
                    </div>
                  </form>
                </motion.div>
              </div>
          )}
        </AnimatePresence>

        {/* SECURITY AUDIT STREAMING MODAL */}
        <AnimatePresence>
          {showLogsModal && (
              <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-3xl p-6 text-left text-slate-100 shadow-2xl"
                >
                  <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-4">
                    <h3 className="font-sans font-bold text-base text-white flex items-center gap-1.5 uppercase tracking-wider">
                      <History className="w-5 h-5 text-emerald-500" />
                      Security Audit Trails
                    </h3>
                    <button
                        onClick={() => setShowLogsModal(false)}
                        className="text-slate-400 hover:text-white cursor-pointer text-xl font-bold"
                    >
                      ×
                    </button>
                  </div>

                  <div className="overflow-y-auto max-h-80 space-y-2 pr-2 scrollbar">
                    {auditLogs.length === 0 ? (
                        <p className="font-sans text-xs text-slate-600 text-center py-6">No audit records registered yet.</p>
                    ) : (
                        auditLogs.map((log) => (
                            <div key={log.id} className="flex justify-between items-center bg-[#020617] p-3 rounded-xl border border-slate-850 text-xs font-mono">
                              <div className="flex gap-2 items-center">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
                                log.action === "create" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" :
                                    log.action === "delete" ? "bg-rose-500/10 text-rose-450 border border-rose-500/10" :
                                        log.action === "update" ? "bg-blue-500/10 text-blue-400 border border-blue-500/10" : "bg-slate-800 text-slate-400"
                            }`}>
                              {log.action}
                            </span>
                                <span className="text-slate-300 font-semibold">{log.itemName}</span>
                              </div>
                              <span className="text-[10px] text-slate-500">{new Date(log.timestamp).toLocaleTimeString()}</span>
                            </div>
                        ))
                    )}
                  </div>

                  <div className="mt-5 text-center">
                    <button
                        onClick={() => setShowLogsModal(false)}
                        className="w-full py-2 bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 rounded-xl font-semibold text-xs cursor-pointer"
                    >
                      Dismiss
                    </button>
                  </div>
                </motion.div>
              </div>
          )}
        </AnimatePresence>

        {/* FULL POLICY PASSWORD GENERATOR MODAL */}
        <AnimatePresence>
          {showGeneratorModal && (
              <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-3xl p-6 text-left text-slate-100 shadow-2xl"
                >
                  <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-4">
                    <h3 className="font-sans font-bold text-base text-white flex items-center gap-1.5 uppercase tracking-wider">
                      <Sparkles className="w-5 h-5 text-emerald-400" />
                      Symmetric Passphrase Generator
                    </h3>
                    <button
                        onClick={() => setShowGeneratorModal(false)}
                        className="text-slate-404 text-slate-400 hover:text-white cursor-pointer text-xl font-bold font-sans"
                    >
                      ×
                    </button>
                  </div>

                  <div>
                    <PasswordGenerator inline />
                  </div>

                  <div className="mt-5 text-center">
                    <button
                        onClick={() => setShowGeneratorModal(false)}
                        className="w-full py-2 bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 rounded-xl font-semibold text-xs cursor-pointer"
                    >
                      Dismiss
                    </button>
                  </div>
                </motion.div>
              </div>
          )}
        </AnimatePresence>

        {/* HIGH-FIDELITY BIOMETRICS WEB_AUTHN PROMPTS */}
        <BiometricPrompt
            isOpen={bioPromptOpen}
            onClose={() => setBioPromptOpen(false)}
            username={username}
            mode="register"
            onSuccess={handleRegisterBiometrics}
        />
      </div>
  );
}
