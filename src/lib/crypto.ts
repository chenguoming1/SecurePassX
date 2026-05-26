/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

// Helper to convert buffer to Base64
export function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper to convert Base64 to ArrayBuffer
export function base64ToBuffer(base64: string): ArrayBuffer {
  const binary = window.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to generate a cryptographically secure random salt (base64)
export function generateSalt(): string {
  const array = new Uint8Array(16);
  window.crypto.getRandomValues(array);
  return bufferToBase64(array.buffer);
}

// Helper to hash SHA-256 (useful for quick client verification)
export async function hashSHA256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Derive both Encryption and Server Verification Keys using PBKDF2-SHA256
export async function deriveUserKeys(
  password: string,
  saltBase64: string
): Promise<{ encryptionKey: CryptoKey; authKeyHex: string }> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const saltBuffer = base64ToBuffer(saltBase64);

  // Import password as raw key material
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  // Derive E2E Symmetric AES encryption key
  const encryptionKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBuffer,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  // Derive Auth Key (for server authentication)
  // Use a different salt variant so Auth Key is completely independent from Encryption Key
  const authSaltBuffer = encoder.encode(saltBase64 + "-securepassx-auth-salt-constant");
  const authBits = await window.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: authSaltBuffer,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    256
  );

  const authArray = Array.from(new Uint8Array(authBits));
  const authKeyHex = authArray.map(b => b.toString(16).padStart(2, "0")).join("");

  return { encryptionKey, authKeyHex };
}

// Encrypt string with AES-GCM 256
export async function encryptString(
  plainText: string,
  key: CryptoKey
): Promise<{ cipherText: string; iv: string }> {
  const encoder = new TextEncoder();
  const rawData = encoder.encode(plainText);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // AES-GCM standard IV size

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    rawData
  );

  return {
    cipherText: bufferToBase64(encryptedBuffer),
    iv: bufferToBase64(iv.buffer),
  };
}

// Decrypt string with AES-GCM 256
export async function decryptString(
  cipherText: string,
  ivBase64: string,
  key: CryptoKey
): Promise<string> {
  const dataBuffer = base64ToBuffer(cipherText);
  const ivBuffer = base64ToBuffer(ivBase64);
  const decoder = new TextDecoder();

  try {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(ivBuffer),
      },
      key,
      dataBuffer
    );

    return decoder.decode(decryptedBuffer);
  } catch (err) {
    console.error("Decryption failed. Invalid Master Password or Corrupted Session Data.", err);
    throw new Error("Decryption failed. Please verify your master credential.");
  }
}
