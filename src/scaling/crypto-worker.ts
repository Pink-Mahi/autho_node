/**
 * Crypto Worker — runs CPU-intensive crypto operations off the main event loop
 * Used by the WorkerPool to parallelize signature verification, SHA-256 hashing, etc.
 * 
 * This worker receives messages with { id, op, args } and responds with { id, result } or { id, error }
 */
import { parentPort } from 'worker_threads';
import * as crypto from 'crypto';

// Lazy-load secp256k1 (heavy module, only load if needed)
let ecc: any = null;
function getEcc() {
  if (!ecc) {
    ecc = require('tiny-secp256k1');
  }
  return ecc;
}

function sha256(data: string | Buffer): string {
  const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function verifySignature(message: string, signature: string, publicKeyHex: string): boolean {
  try {
    const messageHash = sha256(message);
    const publicKey = Buffer.from(publicKeyHex, 'hex');
    const signatureBuffer = Buffer.from(signature, 'hex');
    return getEcc().verify(Buffer.from(messageHash, 'hex'), publicKey, signatureBuffer);
  } catch {
    return false;
  }
}

function signMessage(message: string, privateKeyHex: string): string {
  const { ECPairFactory } = require('ecpair');
  const ECPair = ECPairFactory(getEcc());
  const messageHash = sha256(message);
  const privateKey = Buffer.from(privateKeyHex, 'hex');
  const keyPair = ECPair.fromPrivateKey(privateKey);
  const sig = getEcc().sign(Buffer.from(messageHash, 'hex'), keyPair.privateKey!);
  return Buffer.from(sig).toString('hex');
}

// Handle messages from the main thread
parentPort?.on('message', (msg: { id: string; op: string; args: any[] }) => {
  try {
    let result: any;

    switch (msg.op) {
      case 'sha256':
        result = sha256(msg.args[0]);
        break;

      case 'sha256_batch': {
        // Hash multiple items at once — reduces message overhead
        const inputs = msg.args[0] as string[];
        result = inputs.map(input => sha256(input));
        break;
      }

      case 'verify_signature':
        result = verifySignature(msg.args[0], msg.args[1], msg.args[2]);
        break;

      case 'verify_signatures_batch': {
        // Verify multiple signatures at once
        const sigs = msg.args[0] as Array<{ message: string; signature: string; publicKey: string }>;
        result = sigs.map(s => verifySignature(s.message, s.signature, s.publicKey));
        break;
      }

      case 'sign_message':
        result = signMessage(msg.args[0], msg.args[1]);
        break;

      default:
        parentPort?.postMessage({ id: msg.id, error: `Unknown op: ${msg.op}` });
        return;
    }

    parentPort?.postMessage({ id: msg.id, result });
  } catch (err: any) {
    parentPort?.postMessage({ id: msg.id, error: err.message || 'Worker error' });
  }
});
