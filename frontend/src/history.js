import { b64, unb64 } from "./crypto.js";

const encoder = new TextEncoder();
const VERSION = 1;

async function historyKey(identity, userId) {
  const ownPublicKey = await crypto.subtle.importKey(
    "raw",
    unb64(identity.public_key),
    "X25519",
    false,
    [],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "X25519", public: ownPublicKey },
    identity.encryption.privateKey,
    256,
  );
  const material = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveKey"],
  );
  new Uint8Array(sharedSecret).fill(0);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(`cypherchat-history-v1:${userId}`),
      info: encoder.encode("local-message-history"),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function legacyHistoryKey(identity, userId) {
  const privateKey = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", identity.encryption.privateKey),
  );
  try {
    const material = await crypto.subtle.importKey(
      "raw",
      privateKey,
      "HKDF",
      false,
      ["deriveKey"],
    );
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: encoder.encode(`cypherchat-history-v1:${userId}`),
        info: encoder.encode("local-message-history"),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  } finally {
    privateKey.fill(0);
  }
}

const context = (userId) => encoder.encode(`cypherchat-history-v1:${userId}`);

export async function sealHistory(identity, userId, messages) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: context(userId) },
    await historyKey(identity, userId),
    encoder.encode(JSON.stringify({ version: VERSION, messages })),
  );
  return { version: VERSION, nonce: b64(nonce), data: b64(ciphertext) };
}

export async function openHistory(identity, userId, blob) {
  if (blob?.version !== VERSION) throw Error("Formato de histórico incompatível");
  const algorithm = {
    name: "AES-GCM",
    iv: unb64(blob.nonce),
    additionalData: context(userId),
  };
  let raw;
  let needsMigration = false;
  try {
    raw = await crypto.subtle.decrypt(
      algorithm,
      await historyKey(identity, userId),
      unb64(blob.data),
    );
  } catch (currentFormatError) {
    if (!identity.encryption.privateKey.extractable)
      throw Error("Histórico antigo: saia e entre novamente para migrá-lo com a senha.");
    try {
      raw = await crypto.subtle.decrypt(
        algorithm,
        await legacyHistoryKey(identity, userId),
        unb64(blob.data),
      );
      needsMigration = true;
    } catch {
      throw currentFormatError;
    }
  }
  const parsed = JSON.parse(new TextDecoder().decode(raw));
  if (
    parsed.version !== VERSION ||
    !parsed.messages ||
    typeof parsed.messages !== "object" ||
    Array.isArray(parsed.messages) ||
    Object.values(parsed.messages).some((items) => !Array.isArray(items))
  )
    throw Error("Histórico local inválido");
  if (needsMigration) {
    const migrated = await sealHistory(identity, userId, parsed.messages);
    localStorage.setItem(`cypherchat.history.${userId}`, JSON.stringify(migrated));
  }
  return parsed.messages;
}
