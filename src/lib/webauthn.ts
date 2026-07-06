/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal WebAuthn ceremony helpers. Options come from @simplewebauthn/server
 * (base64url-encoded JSON); responses are serialized back into the JSON
 * format @simplewebauthn/server verification expects. The authentication
 * ceremony optionally evaluates the PRF extension so the client can derive a
 * local key-wrapping secret (used for true E2EE biometric unlock).
 */

export function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function isWebAuthnAvailable(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;
}

// ---------------------------------------------------------------------------
// Registration ceremony
// ---------------------------------------------------------------------------

export interface RegistrationResult {
  responseJSON: Record<string, unknown>;
  /** Whether the authenticator reported PRF support at creation. */
  prfEnabled: boolean;
}

export async function performRegistrationCeremony(optionsJSON: any): Promise<RegistrationResult> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: base64urlToBuffer(optionsJSON.challenge),
    rp: optionsJSON.rp,
    user: {
      id: base64urlToBuffer(optionsJSON.user.id),
      name: optionsJSON.user.name,
      displayName: optionsJSON.user.displayName || optionsJSON.user.name,
    },
    pubKeyCredParams: optionsJSON.pubKeyCredParams,
    timeout: optionsJSON.timeout,
    attestation: optionsJSON.attestation,
    authenticatorSelection: optionsJSON.authenticatorSelection,
    excludeCredentials: (optionsJSON.excludeCredentials || []).map((c: any) => ({
      id: base64urlToBuffer(c.id),
      type: "public-key" as const,
      transports: c.transports,
    })),
    extensions: { ...(optionsJSON.extensions || {}), prf: {} } as AuthenticationExtensionsClientInputs,
  };

  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error("Biometric registration was cancelled.");
  }

  const attestation = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof attestation.getTransports === "function" ? attestation.getTransports() : [];

  const createExtResults = credential.getClientExtensionResults() as any;
  const prfEnabled = createExtResults?.prf?.enabled === true;
  console.info("[webauthn] create() extension results:", JSON.stringify(createExtResults));

  return {
    prfEnabled,
    responseJSON: {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: {},
      response: {
        clientDataJSON: bufferToBase64url(attestation.clientDataJSON),
        attestationObject: bufferToBase64url(attestation.attestationObject),
        transports,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Authentication ceremony (optionally evaluating the PRF extension)
// ---------------------------------------------------------------------------

export interface AuthenticationResult {
  responseJSON: Record<string, unknown>;
  prfSecret: ArrayBuffer | null;
}

export async function performAuthenticationCeremony(
  optionsJSON: any,
  prfSaltBase64?: string | null
): Promise<AuthenticationResult> {
  const extensions: AuthenticationExtensionsClientInputs = {
    ...(optionsJSON.extensions || {}),
  };
  if (prfSaltBase64) {
    (extensions as any).prf = {
      eval: {
        first: base64urlToBuffer(prfSaltBase64.replace(/\+/g, "-").replace(/\//g, "_")),
      },
    };
  }

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: base64urlToBuffer(optionsJSON.challenge),
    timeout: optionsJSON.timeout,
    rpId: optionsJSON.rpId,
    userVerification: optionsJSON.userVerification,
    allowCredentials: (optionsJSON.allowCredentials || []).map((c: any) => ({
      id: base64urlToBuffer(c.id),
      type: "public-key" as const,
      transports: c.transports,
    })),
    extensions,
  };

  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error("Biometric authentication was cancelled.");
  }

  const assertion = credential.response as AuthenticatorAssertionResponse;
  const extensionResults = credential.getClientExtensionResults() as any;
  console.info(
    "[webauthn] get() extension results:",
    JSON.stringify(extensionResults, (_, v) => (v instanceof ArrayBuffer ? `<${v.byteLength} bytes>` : v))
  );
  const prfFirst = extensionResults?.prf?.results?.first;
  const prfSecret: ArrayBuffer | null = prfFirst
    ? prfFirst instanceof ArrayBuffer
      ? prfFirst
      : (prfFirst.buffer as ArrayBuffer)
    : null;

  return {
    responseJSON: {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: {},
      response: {
        clientDataJSON: bufferToBase64url(assertion.clientDataJSON),
        authenticatorData: bufferToBase64url(assertion.authenticatorData),
        signature: bufferToBase64url(assertion.signature),
        userHandle: assertion.userHandle ? bufferToBase64url(assertion.userHandle) : undefined,
      },
    },
    prfSecret,
  };
}
