/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect } from "react";
import { Copy, RefreshCw, Check, Info, ShieldCheck, Milestone } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

// Predefined set of readable English words for passphrase generation (Diceware style)
const DICERE_WORDS = [
  "correct", "horse", "battery", "staple", "galaxy", "pioneer", "orbital",
  "nebula", "crypt", "secure", "vector", "binary", "matrix", "beacon", "citadel",
  "canopy", "quantum", "gravity", "horizon", "vertex", "parsec", "zenith", "vortex",
  "capsule", "shuttle", "comet", "meteor", "plasma", "shield", "revolver", "copper",
  "monolith", "prism", "spectre", "entropy", "cipher", "synapse", "glitch", "proxy"
];

interface PasswordGeneratorProps {
  onUseGenerated?: (password: string) => void;
  inline?: boolean;
}

// Cryptographically secure uniform integer in [0, max) via rejection sampling
function secureRandomInt(max: number): number {
  const limit = Math.floor(0xffffffff / max) * max;
  const buf = new Uint32Array(1);
  let value: number;
  do {
    window.crypto.getRandomValues(buf);
    value = buf[0];
  } while (value >= limit);
  return value % max;
}

export default function PasswordGenerator({ onUseGenerated, inline = false }: PasswordGeneratorProps) {
  const [password, setPassword] = useState("");
  const [copied, setCopied] = useState(false);
  const [mode, setMode] = useState<"standard" | "passphrase">("standard");

  // Standard Policy configs
  const [length, setLength] = useState(16);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [numbers, setNumbers] = useState(true);
  const [specials, setSpecials] = useState(true);
  const [avoidSimilar, setAvoidSimilar] = useState(false);

  // Passphrase policy configs
  const [wordCount, setWordCount] = useState(4);
  const [separator, setSeparator] = useState("-");

  const generatePassword = () => {
    if (mode === "passphrase") {
      const selectedWords: string[] = [];
      for (let i = 0; i < wordCount; i++) {
        const randomIndex = secureRandomInt(DICERE_WORDS.length);
        selectedWords.push(DICERE_WORDS[randomIndex]);
      }
      setPassword(selectedWords.join(separator));
      return;
    }

    // Standard password generation
    let chars = "";
    let uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lowers = "abcdefghijklmnopqrstuvwxyz";
    let nums = "0123456789";
    let symbols = "!@#$%^&*()_+-=[]{}|;:',./<>?~";

    if (avoidSimilar) {
      uppers = uppers.replace(/[IO]/g, "");
      lowers = lowers.replace(/[ilo]/g, "");
      nums = nums.replace(/[01]/g, "");
      symbols = symbols.replace(/[|]/g, "");
    }

    if (uppercase) chars += uppers;
    if (lowercase) chars += lowers;
    if (numbers) chars += nums;
    if (specials) chars += symbols;

    if (!chars) {
      setPassword("");
      return;
    }

    let generated = "";
    // Guarantee at least one character of each selected pool for cryptographic safety
    const pools: string[] = [];
    if (uppercase && uppers) pools.push(uppers[secureRandomInt(uppers.length)]);
    if (lowercase && lowers) pools.push(lowers[secureRandomInt(lowers.length)]);
    if (numbers && nums) pools.push(nums[secureRandomInt(nums.length)]);
    if (specials && symbols) pools.push(symbols[secureRandomInt(symbols.length)]);

    for (let i = 0; i < length - pools.length; i++) {
      const randomIndex = secureRandomInt(chars.length);
      generated += chars[randomIndex];
    }

    // Blend and insert guaranteed characters
    const finalBuffer = (generated + pools.join("")).split("");
    for (let i = finalBuffer.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [finalBuffer[i], finalBuffer[j]] = [finalBuffer[j], finalBuffer[i]];
    }

    setPassword(finalBuffer.join(""));
  };

  useEffect(() => {
    generatePassword();
  }, [length, uppercase, lowercase, numbers, specials, avoidSimilar, mode, wordCount, separator]);

  const handleCopy = () => {
    if (!password) return;
    navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  // Entropy Calculation helper
  const calculateEntropyAndStrength = () => {
    if (!password) return { entropy: 0, label: "Empty", color: "bg-slate-700", textColor: "text-slate-400" };

    let poolSize = 0;
    if (mode === "passphrase") {
      // Pool size of passphrase dictionary
      poolSize = DICERE_WORDS.length;
      const entropy = wordCount * Math.log2(poolSize);
      if (entropy < 45) return { entropy, label: "Weak (Unsafe)", color: "bg-rose-500", textColor: "text-rose-400" };
      if (entropy < 65) return { entropy, label: "Moderate (Standard)", color: "bg-amber-500", textColor: "text-amber-400" };
      return { entropy, label: "Extremely Secure (Diceware)", color: "bg-emerald-500", textColor: "text-emerald-400" };
    } else {
      let containsUpper = /[A-Z]/.test(password);
      let containsLower = /[a-z]/.test(password);
      let containsNum = /[0-9]/.test(password);
      let containsSymbol = /[^A-Za-z0-9]/.test(password);

      if (containsUpper) poolSize += 26;
      if (containsLower) poolSize += 26;
      if (containsNum) poolSize += 10;
      if (containsSymbol) poolSize += 29;

      const entropy = password.length * Math.log2(poolSize || 1);
      if (entropy < 40) return { entropy: Math.round(entropy), label: "Weak - Easy to Crack", color: "bg-rose-500", textColor: "text-rose-400" };
      if (entropy < 70) return { entropy: Math.round(entropy), label: "Good - Medium Safety", color: "bg-amber-500", textColor: "text-amber-400" };
      if (entropy < 100) return { entropy: Math.round(entropy), label: "Strong - Fully Secured", color: "bg-emerald-500", textColor: "text-emerald-400" };
      return { entropy: Math.round(entropy), label: "Paranoid-Grade Strength", color: "bg-indigo-500", textColor: "text-indigo-400" };
    }
  };

  const strength = calculateEntropyAndStrength();

  return (
    <div className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${inline ? "" : "shadow-lg max-w-lg mx-auto"}`}>
      <div className="flex justify-between items-center mb-4">
        <h4 className="font-sans font-semibold text-sm text-slate-200 flex items-center gap-1.5">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          Password Builder
        </h4>
        <div className="flex bg-slate-850 p-1 rounded-lg border border-slate-800">
          <button
            type="button"
            onClick={() => setMode("standard")}
            className={`px-2.5 py-1 rounded-md font-mono text-[10px] uppercase font-semibold tracking-wider transition-colors ${
              mode === "standard" ? "bg-slate-705 text-slate-100 bg-slate-800" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Symmetric Key
          </button>
          <button
            type="button"
            onClick={() => setMode("passphrase")}
            className={`px-2.5 py-1 rounded-md font-mono text-[10px] uppercase font-semibold tracking-wider transition-colors ${
              mode === "passphrase" ? "bg-slate-705 text-slate-100 bg-slate-800" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Diceware Passphrase
          </button>
        </div>
      </div>

      {/* Generated Display Box */}
      <div className="relative flex items-center bg-slate-950 border border-slate-850 rounded-lg p-3.5 mb-2 font-mono text-sm break-all pr-24 tracking-wide text-slate-100 min-h-[48px]">
        {password ? (
          <span className="select-all">{password}</span>
        ) : (
          <span className="text-slate-600">Please choose at least one active pool.</span>
        )}
        <div className="absolute right-2 flex gap-1">
          <button
            type="button"
            onClick={generatePassword}
            id="btn-regen-password"
            title="Regenerate"
            className="p-1.5 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded-lg transition-colors cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={handleCopy}
            id="btn-copy-generated"
            title="Copy to Clipboard"
            className="p-1.5 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded-lg transition-colors cursor-pointer"
          >
            <AnimatePresence mode="wait">
              {copied ? (
                <motion.div
                  key="check"
                  initial={{ scale: 0.6, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  exit={{ scale: 0.6, opacity: 0 }}
                >
                  <Check className="w-4 h-4 text-emerald-400" />
                </motion.div>
              ) : (
                <motion.div
                  key="copy"
                  initial={{ scale: 0.6, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  exit={{ scale: 0.6, opacity: 0 }}
                >
                  <Copy className="w-4 h-4" />
                </motion.div>
              )}
            </AnimatePresence>
          </button>
        </div>
      </div>

      {/* Strength Indicator */}
      <div className="mb-4">
        <div className="flex justify-between items-center text-[11px] font-mono text-slate-400 mb-1">
          <span className="flex items-center gap-1">
            Strength: <span className={`${strength.textColor} font-semibold`}>{strength.label}</span>
          </span>
          <span>~{Math.round(strength.entropy)} bits of entropy</span>
        </div>
        <div className="h-1 text-[1px] w-full bg-slate-950 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${Math.min(100, (strength.entropy / 128) * 100)}%` }}
            className={`h-full ${strength.color}`}
          />
        </div>
      </div>

      {/* Policies Configurations */}
      {mode === "standard" ? (
        <div className="space-y-3 font-sans text-xs text-slate-300">
          <div className="flex items-center justify-between">
            <label className="text-slate-400 select-none">Length: <span className="font-mono text-teal-400 font-semibold">{length}</span></label>
            <input
              type="range"
              min="8"
              max="64"
              value={length}
              onChange={(e) => setLength(parseInt(e.target.value))}
              className="w-2/3 accent-teal-500 h-1 bg-slate-950 rounded-lg cursor-pointer"
            />
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2">
            <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-slate-850 border border-slate-850/50 hover:bg-slate-800 transition-colors select-none">
              <input
                type="checkbox"
                checked={uppercase}
                onChange={(e) => setUppercase(e.target.checked)}
                className="rounded accent-teal-500 cursor-pointer"
              />
              <span>Uppercase (A-Z)</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-slate-850 border border-slate-850/50 hover:bg-slate-800 transition-colors select-none">
              <input
                type="checkbox"
                checked={lowercase}
                onChange={(e) => setLowercase(e.target.checked)}
                className="rounded accent-teal-500 cursor-pointer"
              />
              <span>Lowercase (a-z)</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-slate-850 border border-slate-850/50 hover:bg-slate-800 transition-colors select-none">
              <input
                type="checkbox"
                checked={numbers}
                onChange={(e) => setNumbers(e.target.checked)}
                className="rounded accent-teal-500 cursor-pointer"
              />
              <span>Numbers (0-9)</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-slate-850 border border-slate-850/50 hover:bg-slate-800 transition-colors select-none">
              <input
                type="checkbox"
                checked={specials}
                onChange={(e) => setSpecials(e.target.checked)}
                className="rounded accent-teal-500 cursor-pointer"
              />
              <span>Symbols (!@#$)</span>
            </label>
          </div>

          <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg bg-slate-850/40 border border-slate-850/45 hover:bg-slate-800/60 transition-colors select-none">
            <input
              type="checkbox"
              checked={avoidSimilar}
              onChange={(e) => setAvoidSimilar(e.target.checked)}
              className="rounded accent-teal-500 cursor-pointer"
            />
            <span className="flex items-center gap-1">
              Avoid similar chars (ex. <code className="font-mono bg-slate-950 px-1 rounded font-semibold text-teal-400 text-[10px]">1, l, I, 0, O</code>)
            </span>
          </label>
        </div>
      ) : (
        <div className="space-y-3 font-sans text-xs text-slate-300">
          <div className="flex items-center justify-between">
            <label className="text-slate-400 select-none">Words Count: <span className="font-mono text-teal-400 font-semibold">{wordCount}</span></label>
            <input
              type="range"
              min="3"
              max="8"
              value={wordCount}
              onChange={(e) => setWordCount(parseInt(e.target.value))}
              className="w-2/3 accent-teal-500 h-1 bg-slate-950 rounded-lg cursor-pointer"
            />
          </div>

          <div className="flex justify-between items-center py-1">
            <span className="text-slate-400">Word Separator Character:</span>
            <select
              value={separator}
              onChange={(e) => setSeparator(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg py-1 px-2.5 outline-none text-teal-400 font-mono"
            >
              <option value="-">Hyphen (-)</option>
              <option value="_">Underscore (_)</option>
              <option value=".">Dot (.)</option>
              <option value="/">Slash (/)</option>
              <option value=" ">Space ( )</option>
            </select>
          </div>
        </div>
      )}

      {onUseGenerated && password && (
        <button
          type="button"
          onClick={() => onUseGenerated(password)}
          id="btn-use-generated"
          className="w-full mt-4 flex items-center justify-center gap-1 bg-teal-600 hover:bg-teal-500 active:bg-teal-700 text-white font-sans font-semibold text-xs py-2 rounded-lg transition-all shadow-md group cursor-pointer"
        >
          <Milestone className="w-4 h-4 text-teal-100 group-hover:translate-x-0.5 transition-transform" />
          Fill in Credentials Form
        </button>
      )}
    </div>
  );
}
