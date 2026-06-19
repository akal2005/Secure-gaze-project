const { webcrypto } = require('crypto');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const db = new PrismaClient();
const { subtle } = webcrypto;

// Helper to convert array buffer to hex string
function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Helper to convert hex string to Uint8Array
function hexToBuf(hexString) {
  if (!hexString) return new Uint8Array(0);
  const matches = hexString.match(/.{1,2}/g);
  if (!matches) return new Uint8Array(0);
  return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
}

// Derive AES-GCM key from combination and salt
async function deriveKey(combination, salt) {
  const passwordString = combination.join('-');
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(passwordString);
  const saltBuffer = hexToBuf(salt);

  const baseKey = await subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  return subtle.deriveKey(
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

// Encrypt text exactly like the frontend
async function encryptText(text, key) {
  if (!text) return '';
  const encoder = new TextEncoder();
  const encodedText = encoder.encode(text);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await subtle.encrypt(
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

async function seed() {
  const username = 'admin';
  const combination = ['A', '9', '@'];
  
  // Create a random salt
  const salt = Array.from(webcrypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  console.log(`[Seed] Generating test user: "${username}" with combo: [${combination.join(', ')}]`);

  try {
    // Clean existing database records
    await db.vaultItem.deleteMany({});
    await db.secureNote.deleteMany({});
    await db.fileItem.deleteMany({});
    await db.loginAttempt.deleteMany({});
    await db.user.deleteMany({});

    // Hash the combination sequence
    const combinationStr = combination.join('-');
    const passwordHash = await bcrypt.hash(combinationStr, 10);

    // Create user
    const user = await db.user.create({
      data: {
        username,
        passwordHash,
        salt
      }
    });

    // Derive key to encrypt vault items
    const cryptoKey = await deriveKey(combination, salt);

    // Test credentials to seed (will be stored encrypted)
    const testCredentials = [
      {
        name: 'Google Workspace',
        user: 'admin@google-enterprise.com',
        pass: 'G-SuiteSecretPass!2026',
        notes: 'Corporate admin portal recovery key.'
      },
      {
        name: 'GitHub Enterprise',
        user: 'akal2005',
        pass: 'ghp_TokenAdminSecure991823',
        notes: 'Main code repository SSH deploy key.'
      },
      {
        name: 'Crypto Vault Wallet',
        user: 'security_lead',
        pass: 'seed phrase: apple banana cherry dog elephant fox giraffe horse insect jackal koala lion',
        notes: 'Cold storage wallet seed phrases.'
      }
    ];

    // Encrypt and save vault items
    for (const cred of testCredentials) {
      const encryptedUser = await encryptText(cred.user, cryptoKey);
      const encryptedPass = await encryptText(cred.pass, cryptoKey);
      const encryptedNotes = await encryptText(cred.notes, cryptoKey);

      await db.vaultItem.create({
        data: {
          userId: user.id,
          name: cred.name,
          username: encryptedUser,
          value: encryptedPass,
          notes: encryptedNotes
        }
      });
    }

    console.log(`[Seed] Stored ${testCredentials.length} encrypted vault secrets.`);

    // Seed secure notes
    const testNotes = [
      {
        title: 'Master Recovery Phrases',
        content: 'This note stores the cold wallet ledger mnemonic:\n1. abandon 2. ability 3. able 4. about 5. above 6. absent\nKeep offline if possible!'
      },
      {
        title: 'Server SSH Configurations',
        content: 'Production Server IP: 104.24.12.8\nSSH Port: 2282\nRoot access restricted. Connect via ssh-key only.'
      }
    ];

    for (const note of testNotes) {
      const encryptedTitle = await encryptText(note.title, cryptoKey);
      const encryptedContent = await encryptText(note.content, cryptoKey);
      await db.secureNote.create({
        data: {
          userId: user.id,
          title: encryptedTitle,
          content: encryptedContent
        }
      });
    }
    console.log(`[Seed] Stored ${testNotes.length} encrypted secure notes.`);

    // Seed mock encrypted file (key_backup.txt)
    const fileName = 'key_backup.txt';
    const fileType = 'text/plain';
    const fileContentStr = 'SECURE GAZE BACKUP FILE\nCreated: 2026\nSystem status: NORMAL\nEncryption key verification successful.';
    
    const encoder = new TextEncoder();
    const fileBytes = encoder.encode(fileContentStr);
    
    const fileIv = webcrypto.getRandomValues(new Uint8Array(12));
    const encryptedFileBuffer = await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: fileIv
      },
      cryptoKey,
      fileBytes
    );

    const fileIvHex = bufToHex(fileIv);
    const ciphertextBase64 = Buffer.from(encryptedFileBuffer).toString('base64');
    const encryptedFileData = `${fileIvHex}:${ciphertextBase64}`;
    const encryptedFileName = await encryptText(fileName, cryptoKey);

    await db.fileItem.create({
      data: {
        userId: user.id,
        fileName: encryptedFileName,
        fileType,
        fileSize: fileContentStr.length,
        fileData: encryptedFileData
      }
    });
    console.log(`[Seed] Stored 1 encrypted backup file.`);

    // Seed some mock login history
    const loginHistory = [
      {
        username,
        ipAddress: '192.168.1.15',
        success: true,
        details: 'Successful auth session',
        userId: user.id,
        attemptTime: new Date(Date.now() - 5 * 60000) // 5 mins ago
      },
      {
        username,
        ipAddress: '203.0.113.88',
        success: false,
        details: 'Incorrect combination sequence',
        userId: user.id,
        attemptTime: new Date(Date.now() - 15 * 60000) // 15 mins ago
      },
      {
        username,
        ipAddress: '192.168.1.15',
        success: true,
        details: 'Successful auth session',
        userId: user.id,
        attemptTime: new Date(Date.now() - 60 * 60000) // 1 hour ago
      },
      {
        username: 'intruder_hacker',
        ipAddress: '45.89.231.102',
        success: false,
        details: 'User not found',
        attemptTime: new Date(Date.now() - 120 * 60000) // 2 hours ago
      }
    ];

    for (const log of loginHistory) {
      await db.loginAttempt.create({
        data: log
      });
    }

    console.log(`[Seed] Seeded ${loginHistory.length} login attempt audit logs.`);
    console.log('[Seed] Database seeding completed successfully.');
  } catch (err) {
    console.error('Seeding error:', err);
  } finally {
    await db.$disconnect();
  }
}

seed();
