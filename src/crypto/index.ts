import * as crypto from 'crypto';
import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';
import * as bitcoin from 'bitcoinjs-lib';

const ECPair = ECPairFactory(ecc);

export function sha256(data: string | Buffer): string {
  const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function signMessage(message: string, privateKeyHex: string): string {
  const messageHash = sha256(message);
  const privateKey = Buffer.from(privateKeyHex, 'hex');
  const keyPair = ECPair.fromPrivateKey(privateKey);

  const signature = ecc.sign(Buffer.from(messageHash, 'hex'), keyPair.privateKey!);
  return Buffer.from(signature).toString('hex');
}

export function verifySignature(message: string, signature: string, publicKeyHex: string): boolean {
  try {
    const messageHash = sha256(message);
    const publicKey = Buffer.from(publicKeyHex, 'hex');
    const signatureBuffer = Buffer.from(signature, 'hex');

    return ecc.verify(Buffer.from(messageHash, 'hex'), publicKey, signatureBuffer);
  } catch {
    return false;
  }
}

export function generateKeyPair(): { privateKey: string; publicKey: string; address: string } {
  const keyPair = ECPair.makeRandom();
  const { address } = bitcoin.payments.p2pkh({
    pubkey: keyPair.publicKey,
    network: bitcoin.networks.bitcoin,
  });

  return {
    privateKey: keyPair.privateKey!.toString('hex'),
    publicKey: keyPair.publicKey.toString('hex'),
    address: address!,
  };
}

export function publicKeyToAddress(publicKeyHex: string): string {
  const publicKey = Buffer.from(publicKeyHex, 'hex');
  const { address } = bitcoin.payments.p2pkh({
    pubkey: publicKey,
    network: bitcoin.networks.bitcoin,
  });
  return address!;
}

export function generateNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function generateId(): string {
  return crypto.randomBytes(16).toString('hex');
}

// Re-export Merkle tree functions and types
export {
  buildMerkleTree,
  generateMerkleProof,
  verifyMerkleProof,
  compactifyProof,
  expandProof,
  verifyCompactProof,
  generateMultipleProofs,
  calculateTreeHeight,
  verifyProofConsistency,
  formatForOpReturn,
  parseOpReturn,
  MerkleProof,
  CompactMerkleProof,
  MerkleTreeResult,
  BitcoinAnchorableProof,
} from './merkle-tree';
