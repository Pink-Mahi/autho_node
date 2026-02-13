/**
 * Bloom Filter — space-efficient probabilistic set membership test
 * 
 * Used for O(1) event dedup in the gossip protocol.
 * At 1M events with 0.1% false positive rate: ~1.8 MB (vs ~64 MB for a Set of hash strings)
 * 
 * False positives are acceptable for gossip dedup (worst case: we skip re-gossipping an event
 * we don't actually have — the peer will get it via normal sync).
 * False negatives never occur — if the filter says "not seen", it's definitely not seen.
 */
import * as crypto from 'crypto';

export class BloomFilter {
  private bits: Uint32Array;
  private readonly numBits: number;
  private readonly numHashes: number;
  private count: number = 0;
  private readonly maxCapacity: number;

  /**
   * @param expectedItems Expected number of items to store
   * @param falsePositiveRate Desired false positive probability (default 0.001 = 0.1%)
   */
  constructor(expectedItems: number = 100000, falsePositiveRate: number = 0.001) {
    this.maxCapacity = expectedItems;

    // Optimal number of bits: m = -n * ln(p) / (ln(2))^2
    this.numBits = Math.ceil(-expectedItems * Math.log(falsePositiveRate) / (Math.LN2 * Math.LN2));
    // Round up to nearest 32 for Uint32Array alignment
    const arraySize = Math.ceil(this.numBits / 32);

    // Optimal number of hash functions: k = (m/n) * ln(2)
    this.numHashes = Math.max(1, Math.round((this.numBits / expectedItems) * Math.LN2));

    this.bits = new Uint32Array(arraySize);
  }

  /**
   * Generate k hash positions using double hashing (Kirschner & Mitzenmacher technique)
   * Uses two independent hashes from a single SHA-256 to derive k positions
   */
  private getPositions(item: string): number[] {
    const hash = crypto.createHash('sha256').update(item).digest();
    // Use first 8 bytes as two 32-bit hashes
    const h1 = hash.readUInt32LE(0);
    const h2 = hash.readUInt32LE(4);

    const positions: number[] = [];
    for (let i = 0; i < this.numHashes; i++) {
      // Double hashing: pos_i = (h1 + i * h2) mod m
      const pos = ((h1 + i * h2) >>> 0) % this.numBits;
      positions.push(pos);
    }
    return positions;
  }

  /**
   * Add an item to the filter
   */
  add(item: string): void {
    const positions = this.getPositions(item);
    for (const pos of positions) {
      const arrayIndex = pos >>> 5;  // pos / 32
      const bitIndex = pos & 31;     // pos % 32
      this.bits[arrayIndex] |= (1 << bitIndex);
    }
    this.count++;
  }

  /**
   * Test if an item might be in the filter
   * Returns true if possibly present (may be false positive)
   * Returns false if definitely not present (never false negative)
   */
  mightContain(item: string): boolean {
    const positions = this.getPositions(item);
    for (const pos of positions) {
      const arrayIndex = pos >>> 5;
      const bitIndex = pos & 31;
      if ((this.bits[arrayIndex] & (1 << bitIndex)) === 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Add item only if not already present. Returns true if the item was new.
   */
  addIfNew(item: string): boolean {
    const positions = this.getPositions(item);

    // Check first
    let allSet = true;
    for (const pos of positions) {
      const arrayIndex = pos >>> 5;
      const bitIndex = pos & 31;
      if ((this.bits[arrayIndex] & (1 << bitIndex)) === 0) {
        allSet = false;
        break;
      }
    }

    if (allSet) return false; // Probably already present

    // Add
    for (const pos of positions) {
      const arrayIndex = pos >>> 5;
      const bitIndex = pos & 31;
      this.bits[arrayIndex] |= (1 << bitIndex);
    }
    this.count++;
    return true;
  }

  /**
   * Reset the filter (clear all bits)
   */
  clear(): void {
    this.bits.fill(0);
    this.count = 0;
  }

  /**
   * Check if the filter is getting full and should be rotated
   * When count exceeds capacity, false positive rate degrades
   */
  shouldRotate(): boolean {
    return this.count >= this.maxCapacity;
  }

  getStats(): {
    numBits: number;
    numHashes: number;
    count: number;
    capacity: number;
    fillRatio: number;
    estimatedFPRate: number;
    memoryBytes: number;
  } {
    const setBits = this.countSetBits();
    const fillRatio = setBits / this.numBits;
    // Estimated false positive rate: (setBits / numBits)^numHashes
    const estimatedFPRate = Math.pow(fillRatio, this.numHashes);

    return {
      numBits: this.numBits,
      numHashes: this.numHashes,
      count: this.count,
      capacity: this.maxCapacity,
      fillRatio,
      estimatedFPRate,
      memoryBytes: this.bits.byteLength,
    };
  }

  private countSetBits(): number {
    let total = 0;
    for (let i = 0; i < this.bits.length; i++) {
      // Brian Kernighan's algorithm
      let v = this.bits[i];
      while (v) {
        v &= (v - 1);
        total++;
      }
    }
    return total;
  }
}

/**
 * Rotating Bloom Filter — maintains two generations to handle unbounded streams
 * 
 * When the active filter gets full, the old filter is discarded, the active becomes old,
 * and a fresh filter becomes active. This provides bounded memory with graceful degradation.
 * An item is considered "seen" if it's in either generation.
 */
export class RotatingBloomFilter {
  private active: BloomFilter;
  private previous: BloomFilter | null = null;
  private readonly expectedItems: number;
  private readonly falsePositiveRate: number;

  constructor(expectedItems: number = 100000, falsePositiveRate: number = 0.001) {
    this.expectedItems = expectedItems;
    this.falsePositiveRate = falsePositiveRate;
    this.active = new BloomFilter(expectedItems, falsePositiveRate);
  }

  /**
   * Add item and return true if it was new (not in either generation)
   */
  addIfNew(item: string): boolean {
    // Check previous generation first
    if (this.previous && this.previous.mightContain(item)) {
      return false; // Probably seen in previous generation
    }

    // Check and add to active
    const isNew = this.active.addIfNew(item);

    // Rotate if needed
    if (this.active.shouldRotate()) {
      this.previous = this.active;
      this.active = new BloomFilter(this.expectedItems, this.falsePositiveRate);
    }

    return isNew;
  }

  mightContain(item: string): boolean {
    return this.active.mightContain(item) ||
      (this.previous !== null && this.previous.mightContain(item));
  }

  getStats(): {
    active: ReturnType<BloomFilter['getStats']>;
    previous: ReturnType<BloomFilter['getStats']> | null;
    totalMemoryBytes: number;
  } {
    const activeStats = this.active.getStats();
    const prevStats = this.previous ? this.previous.getStats() : null;
    return {
      active: activeStats,
      previous: prevStats,
      totalMemoryBytes: activeStats.memoryBytes + (prevStats?.memoryBytes || 0),
    };
  }
}
