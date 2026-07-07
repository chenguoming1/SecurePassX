/**
 * SecurePassX Autofill - popup logic.
 *
 * Zero-knowledge client: the master password is turned into the vault key
 * with PBKDF2 locally (same derivation as the web app); the server only ever
 * sees the one-way auth proof and E2EE blobs. The derived key + session
 * token live in chrome.storage.session (memory-only, cleared when the
 * browser exits) with a 10-minute auto-lock.
 */

const AUTO_LOCK_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// Helpers: base64 / crypto (mirrors src/lib/crypto.ts)
// ---------------------------------------------------------------------------

const b64ToBuf = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
const bufToB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const bufToHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sha256Hex(text) {
  return bufToHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

async function deriveKeys(password, saltB64, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const encBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: b64ToBuf(saltB64), iterations, hash: "SHA-256" }, baseKey, 256
  );
  const authBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(saltB64 + "-securepassx-auth-salt-constant"),
      iterations,
      hash: "SHA-256",
    },
    baseKey, 256
  );
  return { rawKey: encBits, authKeyHex: bufToHex(authBits) };
}

async function importVaultKey(rawKeyB64) {
  return crypto.subtle.importKey("raw", b64ToBuf(rawKeyB64), { name: "AES-GCM" }, false, ["decrypt"]);
}

async function decryptField(cipherB64, ivB64, key) {
  if (!cipherB64) return "";
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(b64ToBuf(ivB64)) }, key, b64ToBuf(cipherB64)
  );
  return new TextDecoder().decode(plain);
}

// ---------------------------------------------------------------------------
// State / storage
// ---------------------------------------------------------------------------

let serverUrl = "";
let session = null; // { token, rawKeyB64, unlockedAt }
let decrypted = []; // [{id, title, username, password, url}]

const $ = (id) => document.getElementById(id);
const show = (view) => {
  for (const v of ["settings", "login", "vault"]) {
    $(`view-${v}`).classList.toggle("active", v === view);
  }
};
const setMsg = (id, text, kind) => {
  const el = $(id);
  el.textContent = text || "";
  el.className = text ? `msg ${kind}` : "msg";
};

async function loadState() {
  const local = await chrome.storage.local.get("serverUrl");
  serverUrl = local.serverUrl || "";
  const sess = await chrome.storage.session.get("session");
  session = sess.session || null;
  if (session && Date.now() - session.unlockedAt > AUTO_LOCK_MS) {
    await lock();
  }
}

async function lock() {
  session = null;
  decrypted = [];
  await chrome.storage.session.remove("session");
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async function api(path, options = {}) {
  const res = await fetch(`${serverUrl.replace(/\/$/, "")}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(session?.token ? { Authorization: `Bearer ${session.token}` } : {}),
      ...(options.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

async function loadVault() {
  const { ok, data } = await api("/api/credentials");
  if (!ok) throw new Error(data.error || "Failed to load vault (session may have expired).");

  const key = await importVaultKey(session.rawKeyB64);
  const list = [];
  for (const item of data) {
    try {
      let ivMap = null;
      if (item.iv && item.iv.startsWith("{")) {
        try { ivMap = JSON.parse(item.iv); } catch {}
      }
      list.push({
        id: item.id,
        title: await decryptField(item.title, ivMap?.t ?? item.iv, key),
        username: await decryptField(item.usernameEnc, ivMap?.u ?? item.iv, key),
        password: await decryptField(item.passwordEnc, ivMap?.p ?? item.iv, key),
        url: await decryptField(item.urlEnc, ivMap?.r ?? item.iv, key),
      });
    } catch (e) {
      console.warn("Skipping undecryptable entry", item.id);
    }
  }
  decrypted = list;
}

// ---------------------------------------------------------------------------
// Fill (injected into the active tab on click)
// ---------------------------------------------------------------------------

function fillCredentials(username, password) {
  const setVal = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const visible = (el) => el.offsetParent !== null && !el.disabled && !el.readOnly;

  const pwField = [...document.querySelectorAll("input[type=password]")].find(visible);
  let userField = [
    ...document.querySelectorAll(
      "input[autocomplete=username], input[type=email], input[name*=user i], input[name*=email i], input[name*=login i]"
    ),
  ].find(visible);
  if (!userField && pwField && pwField.form) {
    userField = [...pwField.form.querySelectorAll("input[type=text], input[type=email]")].find(visible);
  }
  if (!userField) {
    userField = [...document.querySelectorAll("input[type=text]")].find(visible);
  }

  if (userField && username) setVal(userField, username);
  if (pwField && password) setVal(pwField, password);
  return { filledUser: !!(userField && username), filledPw: !!(pwField && password) };
}

async function fillOnActiveTab(cred) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab.");
  const [result] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: fillCredentials,
    args: [cred.username || "", cred.password || ""],
  });
  const r = result?.result || {};
  if (!r.filledPw && !r.filledUser) throw new Error("No login fields found on this page.");
  return r;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function hostnameOf(url) {
  try {
    return new URL(url.startsWith("http") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function domainMatches(entryUrl, tabHost) {
  const h = hostnameOf(entryUrl);
  if (!h || !tabHost) return false;
  return tabHost === h || tabHost.endsWith(`.${h}`) || h.endsWith(`.${tabHost}`);
}

function renderCred(cred, container) {
  const div = document.createElement("div");
  div.className = "cred";
  const meta = document.createElement("div");
  meta.className = "meta";
  const title = document.createElement("div");
  title.className = "title";
  title.textContent = cred.title;
  const user = document.createElement("div");
  user.className = "user";
  user.textContent = cred.username || "no username";
  meta.append(title, user);

  const btn = document.createElement("button");
  btn.className = "fill";
  btn.textContent = "Fill";
  btn.addEventListener("click", async () => {
    try {
      setMsg("msg-vault", "", "ok");
      const r = await fillOnActiveTab(cred);
      setMsg("msg-vault", r.filledPw ? "Filled. Submit when ready." : "Username filled (no password field found).", "ok");
    } catch (err) {
      setMsg("msg-vault", err.message, "err");
    }
  });

  div.append(meta, btn);
  container.appendChild(div);
}

async function renderVault() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let tabHost = "";
  try {
    tabHost = new URL(tab?.url || "").hostname.replace(/^www\./, "");
  } catch {}
  $("vault-domain").textContent = tabHost || "no active site";

  const matches = decrypted.filter((c) => domainMatches(c.url, tabHost));
  const matchBox = $("matches");
  matchBox.innerHTML = "";
  if (matches.length === 0) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = tabHost ? `No entries for ${tabHost}` : "Open a login page, then click an entry.";
    matchBox.appendChild(p);
  } else {
    matches.forEach((c) => renderCred(c, matchBox));
  }

  renderAll($("search").value);
}

function renderAll(filter) {
  const box = $("all-creds");
  box.innerHTML = "";
  const q = (filter || "").toLowerCase();
  const list = decrypted.filter(
    (c) => !q || c.title.toLowerCase().includes(q) || c.username.toLowerCase().includes(q) || c.url.toLowerCase().includes(q)
  );
  list.slice(0, 25).forEach((c) => renderCred(c, box));
  if (list.length === 0) {
    const p = document.createElement("div");
    p.className = "empty";
    p.textContent = "No entries.";
    box.appendChild(p);
  }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

$("btn-save-settings").addEventListener("click", async () => {
  const url = $("server-url").value.trim();
  if (!url) {
    setMsg("msg-settings", "Enter the vault server URL.", "err");
    return;
  }
  serverUrl = url;
  await chrome.storage.local.set({ serverUrl: url });
  show("login");
});

$("link-settings").addEventListener("click", () => {
  $("server-url").value = serverUrl;
  show("settings");
});

$("btn-login").addEventListener("click", async () => {
  const username = $("login-username").value.trim();
  const password = $("login-password").value;
  const totpCode = $("login-totp").value.trim();
  if (!username || !password) {
    setMsg("msg-login", "Username and master password are required.", "err");
    return;
  }

  $("btn-login").disabled = true;
  setMsg("msg-login", "Deriving keys...", "ok");
  try {
    const saltRes = await api("/api/auth/salt", { method: "POST", body: JSON.stringify({ username }) });
    if (!saltRes.ok) throw new Error(saltRes.data.error || "Server unreachable.");

    const { rawKey, authKeyHex } = await deriveKeys(password, saltRes.data.salt, saltRes.data.iterations);
    const clientAuthHash = await sha256Hex(authKeyHex);

    const loginRes = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, authKeyHex: clientAuthHash, ...(totpCode ? { totpCode } : {}) }),
    });

    if (!loginRes.ok) {
      if (loginRes.data.totpRequired) {
        $("totp-box").style.display = "block";
        setMsg("msg-login", totpCode ? "Invalid code." : "Enter your 2FA code.", "err");
        return;
      }
      throw new Error(loginRes.data.error || "Login failed.");
    }

    session = { token: loginRes.data.token, rawKeyB64: bufToB64(rawKey), unlockedAt: Date.now() };
    await chrome.storage.session.set({ session });
    $("login-password").value = "";
    $("login-totp").value = "";

    await loadVault();
    show("vault");
    await renderVault();
  } catch (err) {
    setMsg("msg-login", err.message, "err");
  } finally {
    $("btn-login").disabled = false;
  }
});

$("btn-lock").addEventListener("click", async () => {
  await lock();
  show("login");
});

$("btn-refresh").addEventListener("click", async () => {
  try {
    await loadVault();
    await renderVault();
    setMsg("msg-vault", "Vault refreshed.", "ok");
  } catch (err) {
    setMsg("msg-vault", err.message, "err");
  }
});

$("search").addEventListener("input", (e) => renderAll(e.target.value));

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

(async function init() {
  await loadState();
  if (!serverUrl) {
    show("settings");
    return;
  }
  if (!session) {
    show("login");
    return;
  }
  try {
    await loadVault();
    show("vault");
    await renderVault();
  } catch {
    await lock();
    show("login");
    setMsg("msg-login", "Session expired. Unlock again.", "err");
  }
})();
