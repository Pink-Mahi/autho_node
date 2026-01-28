/**
 * Merkle Tree Implementation
 * 
 * Provides Bitcoin-style Merkle trees with proof generation and verification.
 * This enables lightweight clients to verify event inclusion without the full chain.
 * 
 * Like Bitcoin's SPV (Simplified Payment Verification), clients can verify
 * that an event is included in a checkpoint using only:
 * - The event hash
 * - The Merkle proof (sibling hashes along the path)
 * - The Merkle root (from the checkpoint)
 * 
 * This is O(log n) verification instead of O(n).
 */

import { sha256 } from './index';

/**
 * Merkle proof for a single leaf
 * Contains the sibling hashes needed to reconstruct the root
 */
export interface MerkleProof {
  leafHash: string;           // The hash being proven
  leafIndex: number;          // Position in the tree (0-indexed)
  siblings: string[];         // Sibling hashes from leaf to root
  directions: ('left' | 'right')[]; // Which side each sibling is on
  root: string;               // The Merkle root
}

/**
 * Compact proof format for external transmission
 * Minimizes data size for network/storage
 */
export interface CompactMerkleProof {
  leaf: string;
  idx: number;
  path: string[];  // Sibling hashes
  dirs: number;    // Bit flags: 0=left, 1=right
  root: string;
}

/**
 * Result of building a Merkle tree
 */
export interface MerkleTreeResult {
  root: string;
  leafCount: number;
  treeHeight: number;
  levels: string[][];  // All levels of the tree for proof generation
}

/**
 * Build a complete Merkle tree from leaf hashes
 * Stores all levels for efficient proof generation
 */
export function buildMerkleTree(leafHashes: string[]): MerkleTreeResult {
  if (leafHashes.length === 0) {
    return {
      root: '',
      leafCount: 0,
      treeHeight: 0,
      levels: [],
    };
  }

  if (leafHashes.length === 1) {
    return {
      root: leafHashes[0],
      leafCount: 1,
      treeHeight: 1,
      levels: [leafHashes],
    };
  }

  const levels: string[][] = [leafHashes];
  let currentLevel = leafHashes;

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];

    for (let i = 0; i < currentLevel.length; i += 2) {
      if (i + 1 < currentLevel.length) {
        // Hash pair together (left + right)
        const combined = currentLevel[i] + currentLevel[i + 1];
        nextLevel.push(sha256(combined));
      } else {
        // Odd node: duplicate it (Bitcoin style)
        const combined = currentLevel[i] + currentLevel[i];
        nextLevel.push(sha256(combined));
      }
    }

    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return {
    root: currentLevel[0],
    leafCount: leafHashes.length,
    treeHeight: levels.length,
    levels,
  };
}

/**
 * Generate a Merkle proof for a specific leaf
 * This proof can be used to verify the leaf is in the tree
 */
export function generateMerkleProof(
  tree: MerkleTreeResult,
  leafIndex: number
): MerkleProof | null {
  if (leafIndex < 0 || leafIndex >= tree.leafCount) {
    return null;
  }

  if (tree.leafCount === 1) {
    return {
      leafHash: tree.levels[0][0],
      leafIndex: 0,
      siblings: [],
      directions: [],
      root: tree.root,
    };
  }

  const siblings: string[] = [];
  const directions: ('left' | 'right')[] = [];
  let currentIndex = leafIndex;

  for (let level = 0; level < tree.levels.length - 1; level++) {
    const currentLevel = tree.levels[level];
    const isLeftNode = currentIndex % 2 === 0;
    const siblingIndex = isLeftNode ? currentIndex + 1 : currentIndex - 1;

    if (siblingIndex < currentLevel.length) {
      siblings.push(currentLevel[siblingIndex]);
      directions.push(isLeftNode ? 'right' : 'left');
    } else {
      // Odd node at end - sibling is itself (Bitcoin style)
      siblings.push(currentLevel[currentIndex]);
      directions.push('right');
    }

    // Move to parent index
    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    leafHash: tree.levels[0][leafIndex],
    leafIndex,
    siblings,
    directions,
    root: tree.root,
  };
}

/**
 * Verify a Merkle proof
 * Returns true if the proof is valid and the leaf is in the tree
 */
export function verifyMerkleProof(proof: MerkleProof): boolean {
  if (proof.siblings.length !== proof.directions.length) {
    return false;
  }

  // Single leaf tree
  if (proof.siblings.length === 0) {
    return proof.leafHash === proof.root;
  }

  let currentHash = proof.leafHash;

  for (let i = 0; i < proof.siblings.length; i++) {
    const sibling = proof.siblings[i];
    const direction = proof.directions[i];

    if (direction === 'left') {
      // Sibling is on the left
      currentHash = sha256(sibling + currentHash);
    } else {
      // Sibling is on the right
      currentHash = sha256(currentHash + sibling);
    }
  }

  return currentHash === proof.root;
}

/**
 * Convert proof to compact format for transmission
 */
export function compactifyProof(proof: MerkleProof): CompactMerkleProof {
  // Encode directions as bit flags
  let dirs = 0;
  for (let i = 0; i < proof.directions.length; i++) {
    if (proof.directions[i] === 'right') {
      dirs |= (1 << i);
    }
  }

  return {
    leaf: proof.leafHash,
    idx: proof.leafIndex,
    path: proof.siblings,
    dirs,
    root: proof.root,
  };
}

/**
 * Expand compact proof back to full format
 */
export function expandProof(compact: CompactMerkleProof): MerkleProof {
  const directions: ('left' | 'right')[] = [];
  
  for (let i = 0; i < compact.path.length; i++) {
    directions.push((compact.dirs & (1 << i)) ? 'right' : 'left');
  }

  return {
    leafHash: compact.leaf,
    leafIndex: compact.idx,
    siblings: compact.path,
    directions,
    root: compact.root,
  };
}

/**
 * Verify a compact proof
 */
export function verifyCompactProof(compact: CompactMerkleProof): boolean {
  return verifyMerkleProof(expandProof(compact));
}

/**
 * Generate multiple proofs efficiently (batch operation)
 */
export function generateMultipleProofs(
  tree: MerkleTreeResult,
  leafIndices: number[]
): Map<number, MerkleProof> {
  const proofs = new Map<number, MerkleProof>();
  
  for (const index of leafIndices) {
    const proof = generateMerkleProof(tree, index);
    if (proof) {
      proofs.set(index, proof);
    }
  }

  return proofs;
}

/**
 * Calculate the expected tree height for a given leaf count
 */
export function calculateTreeHeight(leafCount: number): number {
  if (leafCount === 0) return 0;
  if (leafCount === 1) return 1;
  return Math.ceil(Math.log2(leafCount)) + 1;
}

/**
 * Verify that a set of proofs are consistent with each other
 * (all have the same root)
 */
export function verifyProofConsistency(proofs: MerkleProof[]): boolean {
  if (proofs.length === 0) return true;
  
  const expectedRoot = proofs[0].root;
  
  for (const proof of proofs) {
    if (proof.root !== expectedRoot) {
      return false;
    }
    if (!verifyMerkleProof(proof)) {
      return false;
    }
  }

  return true;
}

/**
 * Create a proof that can be anchored to Bitcoin
 * Includes all data needed for external verification
 */
export interface BitcoinAnchorableProof {
  eventHash: string;
  merkleProof: CompactMerkleProof;
  checkpointRoot: string;
  checkpointSequence: { from: number; to: number };
  bitcoinTxid?: string;
  blockHeight?: number;
}

/**
 * Format proof for Bitcoin OP_RETURN commitment
 * Bitcoin OP_RETURN is limited to 80 bytes
 */
export function formatForOpReturn(merkleRoot: string, checkpointId: string): Buffer {
  // Format: AUTHO + version (1 byte) + merkle root (32 bytes) + checkpoint ID (first 8 bytes)
  const prefix = Buffer.from('AUTHO', 'ascii');  // 5 bytes
  const version = Buffer.from([0x01]);            // 1 byte
  const rootBytes = Buffer.from(merkleRoot, 'hex'); // 32 bytes
  const checkpointBytes = Buffer.from(checkpointId.slice(0, 16), 'hex'); // 8 bytes
  
  // Total: 46 bytes (well under 80 byte limit)
  return Buffer.concat([prefix, version, rootBytes, checkpointBytes]);
}

/**
 * Parse OP_RETURN data back to components
 */
export function parseOpReturn(data: Buffer): { 
  valid: boolean; 
  version?: number; 
  merkleRoot?: string; 
  checkpointPrefix?: string;
} {
  if (data.length < 46) {
    return { valid: false };
  }

  const prefix = data.slice(0, 5).toString('ascii');
  if (prefix !== 'AUTHO') {
    return { valid: false };
  }

  const version = data[5];
  const merkleRoot = data.slice(6, 38).toString('hex');
  const checkpointPrefix = data.slice(38, 46).toString('hex');

  return {
    valid: true,
    version,
    merkleRoot,
    checkpointPrefix,
  };
}
