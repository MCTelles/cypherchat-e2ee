const DATABASE = "cypherchat-session-v1";
const STORE = "sessions";
const ACTIVE_SESSION = "cypherchat.active-session";

function tokenExpiry(token) {
  try {
    const encoded = token.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
    const payload = encoded + "=".repeat((4 - (encoded.length % 4)) % 4);
    return JSON.parse(atob(payload)).exp * 1000;
  } catch {
    return 0;
  }
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE))
        request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function transaction(mode, operation) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const tx = database.transaction(STORE, mode);
      const store = tx.objectStore(STORE);
      let result;
      try {
        result = operation(store);
      } catch (error) {
        reject(error);
        return;
      }
      tx.oncomplete = () => resolve(result?.result);
      tx.onerror = () => reject(tx.error || result?.error);
      tx.onabort = () => reject(tx.error || Error("Sessão local cancelada"));
    });
  } finally {
    database.close();
  }
}

async function nonExtractableIdentity(identity) {
  const [encryptionBytes, signingBytes] = await Promise.all([
    crypto.subtle.exportKey("pkcs8", identity.encryption.privateKey),
    crypto.subtle.exportKey("pkcs8", identity.signing.privateKey),
  ]);
  try {
    const [encryptionPrivateKey, signingPrivateKey] = await Promise.all([
      crypto.subtle.importKey(
        "pkcs8",
        encryptionBytes,
        "X25519",
        false,
        ["deriveBits"],
      ),
      crypto.subtle.importKey(
        "pkcs8",
        signingBytes,
        "Ed25519",
        false,
        ["sign"],
      ),
    ]);
    return {
      ...identity,
      encryption: { privateKey: encryptionPrivateKey },
      signing: { privateKey: signingPrivateKey },
    };
  } finally {
    new Uint8Array(encryptionBytes).fill(0);
    new Uint8Array(signingBytes).fill(0);
  }
}

export async function saveSession(token, me, identity) {
  const id = sessionStorage.getItem(ACTIVE_SESSION) || crypto.randomUUID();
  const savedIdentity = identity
    ? await nonExtractableIdentity(identity)
    : null;
  await transaction("readwrite", (store) =>
    store.put({ token, expiresAt: tokenExpiry(token), me, identity: savedIdentity }, id),
  );
  sessionStorage.setItem(ACTIVE_SESSION, id);
  return savedIdentity;
}

export async function loadSession() {
  const id = sessionStorage.getItem(ACTIVE_SESSION);
  if (!id) return null;
  const session = await transaction("readonly", (store) => store.get(id));
  if (!session || !Number.isFinite(session.expiresAt) || session.expiresAt <= Date.now()) {
    await transaction("readwrite", (store) => store.delete(id));
    sessionStorage.removeItem(ACTIVE_SESSION);
    return null;
  }
  return session || null;
}

export async function clearSession() {
  const id = sessionStorage.getItem(ACTIVE_SESSION);
  sessionStorage.removeItem(ACTIVE_SESSION);
  if (id) await transaction("readwrite", (store) => store.delete(id));
}
