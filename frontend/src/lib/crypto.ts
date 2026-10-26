export interface EncryptedData {
  encryptedPayload: string;
  iv: string;
  keyHash: string;
  wrappedKeys: Array<{ userId: string; wrappedKey: string }>;
}

function arrayBufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function stringToArrayBuffer(str: string): Uint8Array<ArrayBuffer> {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

function arrayBufferToString(buffer: ArrayBuffer): string {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return base64ToArrayBuffer(base64);
}

function arrayBufferToPEM(buffer: ArrayBuffer, type: 'PUBLIC' | 'PRIVATE'): string {
  const base64 = arrayBufferToBase64(buffer);
  const typeLabel = type === 'PUBLIC' ? 'PUBLIC KEY' : 'PRIVATE KEY';
  return `-----BEGIN ${typeLabel}-----\n${base64.match(/.{1,64}/g)?.join('\n') || ''}\n-----END ${typeLabel}-----`;
}

export async function generateAESKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function deriveKeyFromPassword(password: string, salt: ArrayBuffer, iterations: number = 100000): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/** Derive the same 256-bit vault key as the backend's PBKDF2-HMAC-SHA256 flow. */
export async function deriveVaultKeyHex(password: string, saltHex: string, iterations: number = 10000): Promise<string> {
  const key = await deriveKeyFromPassword(password, hexToArrayBuffer(saltHex), iterations);
  const rawKey = await window.crypto.subtle.exportKey('raw', key);
  return arrayBufferToHex(rawKey);
}

export async function encryptWithAES(plaintext: string, key: CryptoKey): Promise<{ iv: string; ciphertext: string }> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const plaintextBuffer = stringToArrayBuffer(plaintext);
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    plaintextBuffer
  );
  return {
    iv: arrayBufferToHex(iv),
    ciphertext: arrayBufferToHex(ciphertext)
  };
}

export async function decryptWithAES(ciphertextHex: string, ivHex: string, key: CryptoKey): Promise<string> {
  const ciphertext = hexToArrayBuffer(ciphertextHex);
  const iv = hexToArrayBuffer(ivHex);
  const plaintext = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );
  return arrayBufferToString(plaintext);
}

export async function generateRSAKeyPair(): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  return window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 3072,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportKeyToPEM(key: CryptoKey, type: 'PUBLIC' | 'PRIVATE'): Promise<string> {
  const exported = await window.crypto.subtle.exportKey(
    type === 'PUBLIC' ? 'spki' : 'pkcs8',
    key
  );
  return arrayBufferToPEM(exported, type);
}

export async function importKeyFromPEM(pem: string, type: 'PUBLIC' | 'PRIVATE'): Promise<CryptoKey> {
  const buffer = pemToArrayBuffer(pem);
  return window.crypto.subtle.importKey(
    type === 'PUBLIC' ? 'spki' : 'pkcs8',
    buffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    type === 'PUBLIC' ? ['encrypt', 'wrapKey'] : ['decrypt', 'unwrapKey']
  );
}

export async function wrapKey(keyToWrap: CryptoKey, wrappingPublicKey: CryptoKey): Promise<string> {
  const wrapped = await window.crypto.subtle.wrapKey(
    'raw',
    keyToWrap,
    wrappingPublicKey,
    { name: 'RSA-OAEP' }
  );
  return arrayBufferToHex(wrapped);
}

export async function unwrapKey(wrappedKeyHex: string, unwrappingPrivateKey: CryptoKey): Promise<CryptoKey> {
  const wrappedKey = hexToArrayBuffer(wrappedKeyHex);
  return window.crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    unwrappingPrivateKey,
    { name: 'RSA-OAEP' },
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function hashKey(key: CryptoKey): Promise<string> {
  const exported = await window.crypto.subtle.exportKey('raw', key);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', exported);
  return arrayBufferToHex(hashBuffer);
}

export async function encryptPayloadForApprovers(plaintext: string, approverPublicKeys: Array<{ userId: string; publicKeyPEM: string }>): Promise<EncryptedData> {
  const dataEncryptionKey = await generateAESKey();
  const keyHash = await hashKey(dataEncryptionKey);
  const { iv, ciphertext } = await encryptWithAES(plaintext, dataEncryptionKey);
  const wrappedKeys: Array<{ userId: string; wrappedKey: string }> = [];

  for (const approver of approverPublicKeys) {
    const approverPublicKey = await importKeyFromPEM(approver.publicKeyPEM, 'PUBLIC');
    const wrappedKey = await wrapKey(dataEncryptionKey, approverPublicKey);
    wrappedKeys.push({
      userId: approver.userId,
      wrappedKey: wrappedKey
    });
  }

  return {
    encryptedPayload: ciphertext,
    iv: iv,
    keyHash: keyHash,
    wrappedKeys: wrappedKeys
  };
}

export async function decryptPayloadForApprover(encryptedData: EncryptedData, userPrivateKey: CryptoKey, userId: string): Promise<string> {
  const wrappedKeyEntry = encryptedData.wrappedKeys.find(k => k.userId === userId);
  if (!wrappedKeyEntry) {
    throw new Error('No wrapped key found for this user');
  }

  const dataEncryptionKey = await unwrapKey(wrappedKeyEntry.wrappedKey, userPrivateKey);
  return decryptWithAES(encryptedData.encryptedPayload, encryptedData.iv, dataEncryptionKey);
}
