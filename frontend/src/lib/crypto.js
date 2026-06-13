// Client-side Web Crypto helper for local encryption/decryption

function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuf(hexString) {
  if (!hexString) return new Uint8Array(0);
  const matches = hexString.match(/.{1,2}/g);
  if (!matches) return new Uint8Array(0);
  return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
}

export async function deriveKey(combination, salt) {
  const passwordString = combination.join('-');
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(passwordString);
  const saltBuffer = hexToBuf(salt);

  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 10000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptText(text, key) {
  if (!text) return '';
  const encoder = new TextEncoder();
  const encodedText = encoder.encode(text);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    encodedText
  );

  const ivHex = bufToHex(iv);
  const ciphertextHex = bufToHex(ciphertextBuffer);

  return `${ivHex}:${ciphertextHex}`;
}

export async function decryptText(encryptedString, key) {
  if (!encryptedString) return '';
  
  const parts = encryptedString.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted format');
  }

  const iv = hexToBuf(parts[0]);
  const ciphertext = hexToBuf(parts[1]);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}
