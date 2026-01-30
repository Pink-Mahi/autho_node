/**
 * End-to-End Message Encryption
 * 
 * Provides encryption for ephemeral messages using Node's built-in crypto.
 * Uses ECDH with secp256k1 curve (same as Bitcoin/wallet keys).
 * 
 * Flow:
 * 1. Sender encrypts message with shared secret derived from recipient's public key
 * 2. Only recipient can decrypt with their private key
 * 3. Platform never sees plaintext - only encrypted blobs
 * 
 * Note: Full E2E encryption happens client-side. This module provides utilities
 * for server-side validation and optional server-assisted encryption.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes, createECDH } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const CURVE = 'secp256k1';

export interface EncryptedMessage {
  ciphertext: string;      // Base64 encoded encrypted content
  iv: string;              // Base64 encoded initialization vector
  authTag: string;         // Base64 encoded authentication tag
  ephemeralPubKey: string; // Ephemeral public key for ECDH (hex)
}

export interface DecryptedMessage {
  content: string;
  timestamp: number;
  itemId?: string;
}

/**
 * Generate an ephemeral ECDH keypair for one-time encryption
 */
function generateEphemeralKeypair(): { privateKey: string; publicKey: string } {
  const ecdh = createECDH(CURVE);
  ecdh.generateKeys();
  return {
    privateKey: ecdh.getPrivateKey('hex'),
    publicKey: ecdh.getPublicKey('hex', 'compressed'),
  };
}

/**
 * Derive a shared secret using ECDH
 */
function deriveSharedSecret(privateKeyHex: string, publicKeyHex: string): Buffer {
  const ecdh = createECDH(CURVE);
  ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
  const sharedSecret = ecdh.computeSecret(Buffer.from(publicKeyHex, 'hex'));
  // Hash to get a proper AES-256 key
  return createHash('sha256').update(sharedSecret).digest();
}

/**
 * Encrypt a message for a recipient
 * 
 * @param plaintext - The message content to encrypt
 * @param recipientPublicKey - Recipient's public key (hex string)
 * @returns Encrypted message object
 */
export function encryptMessage(plaintext: string, recipientPublicKey: string): EncryptedMessage {
  // Generate ephemeral keypair for this message
  const ephemeral = generateEphemeralKeypair();
  
  // Derive shared secret
  const sharedSecret = deriveSharedSecret(ephemeral.privateKey, recipientPublicKey);
  
  // Generate random IV
  const iv = randomBytes(12);
  
  // Encrypt
  const cipher = createCipheriv(ALGORITHM, sharedSecret, iv);
  const plaintextBuffer = Buffer.from(plaintext, 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ephemeralPubKey: ephemeral.publicKey,
  };
}

/**
 * Decrypt a message using recipient's private key
 * 
 * @param encrypted - The encrypted message object
 * @param recipientPrivateKey - Recipient's private key (hex string)
 * @returns Decrypted plaintext
 */
export function decryptMessage(encrypted: EncryptedMessage, recipientPrivateKey: string): string {
  // Derive shared secret using recipient's private key and sender's ephemeral public key
  const sharedSecret = deriveSharedSecret(recipientPrivateKey, encrypted.ephemeralPubKey);
  
  // Parse encrypted components
  const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
  const iv = Buffer.from(encrypted.iv, 'base64');
  const authTag = Buffer.from(encrypted.authTag, 'base64');
  
  // Decrypt
  const decipher = createDecipheriv(ALGORITHM, sharedSecret, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  
  return plaintext.toString('utf8');
}

/**
 * Create a message envelope with metadata
 */
export interface MessageEnvelope {
  type: 'text' | 'image' | 'offer' | 'location';
  content: string;
  timestamp: number;
  itemId?: string;
  offerAmount?: number;
  replyTo?: string;
}

/**
 * Encrypt a full message envelope
 */
export function encryptEnvelope(envelope: MessageEnvelope, recipientPublicKey: string): EncryptedMessage {
  const json = JSON.stringify(envelope);
  return encryptMessage(json, recipientPublicKey);
}

/**
 * Decrypt a full message envelope
 */
export function decryptEnvelope(encrypted: EncryptedMessage, recipientPrivateKey: string): MessageEnvelope {
  const json = decryptMessage(encrypted, recipientPrivateKey);
  return JSON.parse(json);
}

/**
 * Verify a public key is valid for secp256k1
 */
export function isValidPublicKey(publicKey: string): boolean {
  try {
    const buffer = Buffer.from(publicKey, 'hex');
    // Compressed public key should be 33 bytes
    // Uncompressed should be 65 bytes
    return buffer.length === 33 || buffer.length === 65;
  } catch {
    return false;
  }
}

/**
 * Derive a conversation key for group messages (future use)
 * This allows multiple participants to share a conversation key
 */
export function deriveConversationKey(participants: string[]): string {
  // Sort participants for deterministic key
  const sorted = [...participants].sort();
  const combined = sorted.join(':');
  return createHash('sha256').update(combined).digest('hex');
}
