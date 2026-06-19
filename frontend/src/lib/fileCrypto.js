// fileCrypto.js - Client-side file encryption and decryption helpers using Web Crypto API

import { encryptText, decryptText } from './crypto';

// Helper to convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper to convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to read file as ArrayBuffer
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Encrypts a file client-side before sending to server
 * @param {File} file - The file input from user
 * @param {CryptoKey} key - The derived AES-GCM key
 * @returns {Promise<{ fileName: string, fileType: string, fileSize: number, fileData: string }>}
 */
export async function encryptFile(file, key) {
  const fileBytes = await readFileAsArrayBuffer(file);
  
  // Generate random 12-byte IV for file payload
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    fileBytes
  );

  // Convert IV and ciphertext to string formats
  const ivHex = Array.from(iv)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  const ciphertextBase64 = arrayBufferToBase64(encryptedBuffer);

  // Encrypted file data stored as "ivHex:ciphertextBase64"
  const encryptedFileData = `${ivHex}:${ciphertextBase64}`;

  // Encrypt the filename as well for complete zero-knowledge
  const encryptedName = await encryptText(file.name, key);

  return {
    fileName: encryptedName,
    fileType: file.type || 'application/octet-stream',
    fileSize: file.size,
    fileData: encryptedFileData
  };
}

/**
 * Decrypts a file retrieved from server and triggers browser download
 * @param {object} fileItem - File item object from DB containing encrypted details
 * @param {CryptoKey} key - The derived AES-GCM key
 */
export async function decryptAndDownloadFile(fileItem, key) {
  const parts = fileItem.fileData.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted file format');
  }

  // Parse IV
  const ivHex = parts[0];
  const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  
  // Parse ciphertext base64
  const ciphertextBase64 = parts[1];
  const encryptedBuffer = base64ToArrayBuffer(ciphertextBase64);

  // Decrypt file bytes
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    encryptedBuffer
  );

  // Decrypt filename
  const decryptedName = await decryptText(fileItem.fileName, key);

  // Trigger file download in browser
  const blob = new Blob([decryptedBuffer], { type: fileItem.fileType });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = decryptedName;
  document.body.appendChild(a);
  a.click();
  
  // Clean up
  setTimeout(() => {
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }, 100);
}
