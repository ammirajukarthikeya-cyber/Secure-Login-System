const crypto = require('crypto');

/**
 * Defensive Cryptographic Utility Module
 * Provides AES-256-GCM authenticated encryption for sensitive secrets at rest (e.g. TOTP secrets).
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // Standard GCM IV length (96 bits)

let fallbackMasterKey = null;

/**
 * Derives a 32-byte key for AES-256-GCM.
 * Uses TOTP_ENCRYPTION_KEY if provided, or derives from SESSION_SECRET or an ephemeral random key.
 */
function getEncryptionKey() {
  let masterKey = process.env.TOTP_ENCRYPTION_KEY || process.env.SESSION_SECRET;
  if (!masterKey) {
    if (!fallbackMasterKey) {
      fallbackMasterKey = crypto.randomBytes(32).toString('hex');
    }
    masterKey = fallbackMasterKey;
  }
  return crypto.scryptSync(masterKey, 'salt-totp-storage-v1', 32);
}

/**
 * Encrypts plaintext string using AES-256-GCM.
 * Output format: iv:tag:ciphertext (hex-encoded)
 *
 * @param {string} text - Plaintext to encrypt
 * @returns {string} Encrypted string in format iv:tag:ciphertext
 */
function encryptSecret(text) {
  if (!text) return null;
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = getEncryptionKey();
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let ciphertext = cipher.update(text, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${tag}:${ciphertext}`;
}

/**
 * Decrypts AES-256-GCM formatted ciphertext (iv:tag:ciphertext).
 *
 * @param {string} encryptedString - String in iv:tag:ciphertext format
 * @returns {string|null} Decrypted plaintext string or null if invalid
 */
function decryptSecret(encryptedString) {
  if (!encryptedString) return null;
  const parts = encryptedString.split(':');
  if (parts.length !== 3) {
    // If not in encrypted format (e.g. legacy plaintext secret during migration), return as-is
    return encryptedString;
  }

  const [ivHex, tagHex, ciphertextHex] = parts;
  try {
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const key = getEncryptionKey();

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(ciphertextHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Failed to decrypt secret: authentication tag mismatch or corrupted ciphertext.');
    return null;
  }
}

module.exports = {
  encryptSecret,
  decryptSecret,
};
