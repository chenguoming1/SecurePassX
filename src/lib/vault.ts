/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared E2EE credential payload builder. Every field gets its own random
 * AES-GCM IV (IVs must never be reused under the same key); the IV map
 * travels in the entry's iv column as JSON.
 */

import { encryptString } from "./crypto";

export interface PlainCredentialInput {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  category: string;
}

export interface EncryptedCredentialPayload {
  id: string;
  title: string;
  usernameEnc: string;
  passwordEnc: string;
  urlEnc: string;
  notesEnc: string;
  category: string;
  iv: string;
  modifiedAt: number;
}

export async function encryptCredentialPayload(
  cred: PlainCredentialInput,
  key: CryptoKey
): Promise<EncryptedCredentialPayload> {
  const [title, user, pass, url, notes, cat] = await Promise.all([
    encryptString(cred.title, key),
    encryptString(cred.username, key),
    encryptString(cred.password, key),
    encryptString(cred.url, key),
    encryptString(cred.notes, key),
    encryptString(cred.category, key),
  ]);

  return {
    id: cred.id,
    title: title.cipherText,
    usernameEnc: user.cipherText,
    passwordEnc: pass.cipherText,
    urlEnc: url.cipherText,
    notesEnc: notes.cipherText,
    category: cat.cipherText,
    iv: JSON.stringify({
      t: title.iv,
      u: user.iv,
      p: pass.iv,
      r: url.iv,
      n: notes.iv,
      c: cat.iv,
    }),
    modifiedAt: Date.now(),
  };
}
