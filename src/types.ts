/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface User {
  id: number;
  username: string;
  salt: string;
  biometricEnabled: boolean;
}

export interface EncryptedCredential {
  id: string; // client UUID
  title: string; // E2E Encrypted Base64 string
  usernameEnc: string; // E2E Encrypted Base64 string
  passwordEnc: string; // E2E Encrypted Base64 string
  urlEnc: string; // E2E Encrypted Base64 string
  notesEnc: string; // E2E Encrypted Base64 string
  category: string; // Category string (plain context or encrypted; let's keep name plain for grouping, or encrypted. Keeping name plain helps server grouping, but we should E2E encrypt the specific label if custom)
  iv: string; // Iv parameters (base64)
  modifiedAt: number; // Unix timestamp
  isFavorite?: boolean; // Front-end helper or stored as boolean/0/1
}

export interface DecryptedCredential {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  category: string;
  modifiedAt: number;
  isFavorite?: boolean;
}

export type Category = 
  | "All"
  | "General"
  | "Work"
  | "Finance"
  | "Social"
  | "Entertainment"
  | "Developer"
  | "Secure Notes"
  | "Favorites";

export interface PasswordPolicy {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  specials: boolean;
  avoidSimilar: boolean;
}

export interface AuditLogEntry {
  id: string;
  action: string; // 'create' | 'update' | 'delete' | 'view_password' | 'export'
  itemName: string;
  timestamp: number;
}
