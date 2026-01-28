/**
 * Item Search Engine
 * 
 * Provides comprehensive search capabilities for items on the ledger:
 * - Search by manufacturer, model, serial number
 * - Full-text search on name and description
 * - Duplicate detection (same serial + manufacturer)
 * - Image hash lookup (verify image authenticity)
 * - Fuzzy matching for typo tolerance
 * 
 * This makes Autho the definitive protocol for digital title verification -
 * customers can verify items before purchase by searching the ledger.
 */

import { sha256 } from '../crypto';

export interface SearchableItem {
  itemId: string;
  manufacturerId: string;
  serialNumberHash: string;
  serialNumberDisplay?: string;
  metadataHash: string;
  currentOwner: string;
  registeredAt: number;
  metadata?: {
    name?: string;
    description?: string;
    model?: string;
    brand?: string;
    category?: string;
    year?: number;
    condition?: string;
    imageHashes?: string[];
    [key: string]: any;
  };
  authentications?: Array<{
    authenticatorId: string;
    isAuthentic?: boolean;
    confidence?: string;
  }>;
}

export interface SearchQuery {
  /** Full-text search across name, description, model */
  text?: string;
  /** Exact or partial manufacturer ID */
  manufacturer?: string;
  /** Exact or partial model name */
  model?: string;
  /** Serial number (will be hashed for comparison) */
  serialNumber?: string;
  /** Serial number hash (already hashed) */
  serialNumberHash?: string;
  /** Brand name */
  brand?: string;
  /** Category (e.g., "trading_card", "watch", "sneaker") */
  category?: string;
  /** Image hash to find items with matching images */
  imageHash?: string;
  /** Owner address */
  owner?: string;
  /** Only return authenticated items */
  authenticatedOnly?: boolean;
  /** Minimum authentication confidence */
  minConfidence?: 'low' | 'medium' | 'high';
  /** Maximum results to return */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

export interface SearchResult {
  item: SearchableItem;
  score: number;
  matchedFields: string[];
  isDuplicate?: boolean;
  duplicateOf?: string[];
}

export interface DuplicateCheckResult {
  hasDuplicates: boolean;
  existingItems: Array<{
    itemId: string;
    registeredAt: number;
    currentOwner: string;
    matchType: 'exact_serial' | 'serial_manufacturer' | 'image_hash';
  }>;
}

export class ItemSearchEngine {
  private items: Map<string, SearchableItem>;
  
  // Indexes for fast lookup
  private manufacturerIndex: Map<string, Set<string>> = new Map();
  private serialHashIndex: Map<string, Set<string>> = new Map();
  private imageHashIndex: Map<string, Set<string>> = new Map();
  private ownerIndex: Map<string, Set<string>> = new Map();
  private categoryIndex: Map<string, Set<string>> = new Map();
  
  // Full-text search index (simple inverted index)
  private textIndex: Map<string, Set<string>> = new Map();

  constructor(items: Map<string, any>) {
    this.items = items as Map<string, SearchableItem>;
    this.rebuildIndexes();
  }

  /**
   * Rebuild all search indexes from items
   */
  rebuildIndexes(): void {
    this.manufacturerIndex.clear();
    this.serialHashIndex.clear();
    this.imageHashIndex.clear();
    this.ownerIndex.clear();
    this.categoryIndex.clear();
    this.textIndex.clear();

    for (const [itemId, item] of this.items.entries()) {
      this.indexItem(itemId, item);
    }
  }

  /**
   * Index a single item
   */
  private indexItem(itemId: string, item: SearchableItem): void {
    // Manufacturer index
    if (item.manufacturerId) {
      const key = item.manufacturerId.toLowerCase();
      if (!this.manufacturerIndex.has(key)) {
        this.manufacturerIndex.set(key, new Set());
      }
      this.manufacturerIndex.get(key)!.add(itemId);
    }

    // Serial hash index
    if (item.serialNumberHash) {
      if (!this.serialHashIndex.has(item.serialNumberHash)) {
        this.serialHashIndex.set(item.serialNumberHash, new Set());
      }
      this.serialHashIndex.get(item.serialNumberHash)!.add(itemId);
    }

    // Owner index
    if (item.currentOwner) {
      if (!this.ownerIndex.has(item.currentOwner)) {
        this.ownerIndex.set(item.currentOwner, new Set());
      }
      this.ownerIndex.get(item.currentOwner)!.add(itemId);
    }

    // Category index
    const category = item.metadata?.category?.toLowerCase();
    if (category) {
      if (!this.categoryIndex.has(category)) {
        this.categoryIndex.set(category, new Set());
      }
      this.categoryIndex.get(category)!.add(itemId);
    }

    // Image hash index
    if (item.metadata?.imageHashes) {
      for (const hash of item.metadata.imageHashes) {
        if (!this.imageHashIndex.has(hash)) {
          this.imageHashIndex.set(hash, new Set());
        }
        this.imageHashIndex.get(hash)!.add(itemId);
      }
    }
    // Also index images array if present
    if (item.metadata?.images) {
      for (const img of item.metadata.images) {
        if (img.sha256Hex) {
          if (!this.imageHashIndex.has(img.sha256Hex)) {
            this.imageHashIndex.set(img.sha256Hex, new Set());
          }
          this.imageHashIndex.get(img.sha256Hex)!.add(itemId);
        }
      }
    }

    // Full-text index
    const textFields = [
      item.metadata?.name,
      item.metadata?.description,
      item.metadata?.model,
      item.metadata?.brand,
      item.serialNumberDisplay,
    ].filter(Boolean).join(' ');

    const tokens = this.tokenize(textFields);
    for (const token of tokens) {
      if (!this.textIndex.has(token)) {
        this.textIndex.set(token, new Set());
      }
      this.textIndex.get(token)!.add(itemId);
    }
  }

  /**
   * Tokenize text for full-text search
   */
  private tokenize(text: string): string[] {
    return text
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length >= 2);
  }

  /**
   * Search for items matching the query
   */
  search(query: SearchQuery): SearchResult[] {
    const limit = query.limit || 50;
    const offset = query.offset || 0;
    
    let candidateIds: Set<string> | null = null;

    // Start with most restrictive filters
    
    // Serial number hash (exact match)
    if (query.serialNumberHash) {
      const matches = this.serialHashIndex.get(query.serialNumberHash);
      candidateIds = matches ? new Set(matches) : new Set();
    }

    // Serial number (hash it first)
    if (query.serialNumber && !query.serialNumberHash) {
      const hash = sha256(query.serialNumber);
      const matches = this.serialHashIndex.get(hash);
      if (candidateIds) {
        candidateIds = this.intersect(candidateIds, matches || new Set());
      } else {
        candidateIds = matches ? new Set(matches) : new Set();
      }
    }

    // Manufacturer (prefix match)
    if (query.manufacturer) {
      const manufacturerLower = query.manufacturer.toLowerCase();
      const matches = new Set<string>();
      for (const [key, ids] of this.manufacturerIndex.entries()) {
        if (key.includes(manufacturerLower)) {
          ids.forEach(id => matches.add(id));
        }
      }
      if (candidateIds) {
        candidateIds = this.intersect(candidateIds, matches);
      } else {
        candidateIds = matches;
      }
    }

    // Owner
    if (query.owner) {
      const matches = this.ownerIndex.get(query.owner);
      if (candidateIds) {
        candidateIds = this.intersect(candidateIds, matches || new Set());
      } else {
        candidateIds = matches ? new Set(matches) : new Set();
      }
    }

    // Category
    if (query.category) {
      const matches = this.categoryIndex.get(query.category.toLowerCase());
      if (candidateIds) {
        candidateIds = this.intersect(candidateIds, matches || new Set());
      } else {
        candidateIds = matches ? new Set(matches) : new Set();
      }
    }

    // Image hash
    if (query.imageHash) {
      const matches = this.imageHashIndex.get(query.imageHash);
      if (candidateIds) {
        candidateIds = this.intersect(candidateIds, matches || new Set());
      } else {
        candidateIds = matches ? new Set(matches) : new Set();
      }
    }

    // Full-text search
    if (query.text) {
      const tokens = this.tokenize(query.text);
      let textMatches: Set<string> | null = null;
      
      for (const token of tokens) {
        const tokenMatches = new Set<string>();
        // Prefix matching for fuzzy search
        for (const [indexToken, ids] of this.textIndex.entries()) {
          if (indexToken.startsWith(token) || indexToken.includes(token)) {
            ids.forEach(id => tokenMatches.add(id));
          }
        }
        if (textMatches === null) {
          textMatches = tokenMatches;
        } else {
          // Union for OR semantics (find items matching any token)
          tokenMatches.forEach(id => textMatches!.add(id));
        }
      }
      
      if (candidateIds && textMatches) {
        candidateIds = this.intersect(candidateIds, textMatches);
      } else if (textMatches) {
        candidateIds = textMatches;
      }
    }

    // Model search (within metadata)
    if (query.model) {
      const modelLower = query.model.toLowerCase();
      const modelMatches = new Set<string>();
      for (const [itemId, item] of this.items.entries()) {
        const itemModel = item.metadata?.model?.toLowerCase() || '';
        if (itemModel.includes(modelLower)) {
          modelMatches.add(itemId);
        }
      }
      if (candidateIds) {
        candidateIds = this.intersect(candidateIds, modelMatches);
      } else {
        candidateIds = modelMatches;
      }
    }

    // Brand search
    if (query.brand) {
      const brandLower = query.brand.toLowerCase();
      const brandMatches = new Set<string>();
      for (const [itemId, item] of this.items.entries()) {
        const itemBrand = item.metadata?.brand?.toLowerCase() || '';
        if (itemBrand.includes(brandLower)) {
          brandMatches.add(itemId);
        }
      }
      if (candidateIds) {
        candidateIds = this.intersect(candidateIds, brandMatches);
      } else {
        candidateIds = brandMatches;
      }
    }

    // If no filters, return all items
    if (candidateIds === null) {
      candidateIds = new Set(this.items.keys());
    }

    // Score and filter results
    const results: SearchResult[] = [];
    
    for (const itemId of candidateIds) {
      const item = this.items.get(itemId);
      if (!item) continue;

      // Filter by authentication if requested
      if (query.authenticatedOnly) {
        const hasAuth = item.authentications?.some(a => a.isAuthentic === true);
        if (!hasAuth) continue;
      }

      if (query.minConfidence) {
        const confidenceOrder = { low: 1, medium: 2, high: 3 };
        const minLevel = confidenceOrder[query.minConfidence];
        const hasMinConfidence = item.authentications?.some(a => {
          const level = confidenceOrder[a.confidence as keyof typeof confidenceOrder] || 0;
          return a.isAuthentic === true && level >= minLevel;
        });
        if (!hasMinConfidence) continue;
      }

      const { score, matchedFields } = this.scoreResult(item, query);
      
      // Check for duplicates (same serial + manufacturer)
      const duplicates = this.findDuplicates(item);
      
      results.push({
        item,
        score,
        matchedFields,
        isDuplicate: duplicates.length > 1,
        duplicateOf: duplicates.filter(id => id !== itemId),
      });
    }

    // Sort by score descending
    results.sort((a, b) => b.score - a.score);

    // Apply pagination
    return results.slice(offset, offset + limit);
  }

  /**
   * Score a result based on how well it matches the query
   */
  private scoreResult(item: SearchableItem, query: SearchQuery): { score: number; matchedFields: string[] } {
    let score = 0;
    const matchedFields: string[] = [];

    if (query.serialNumberHash && item.serialNumberHash === query.serialNumberHash) {
      score += 100;
      matchedFields.push('serialNumberHash');
    }

    if (query.manufacturer && item.manufacturerId?.toLowerCase().includes(query.manufacturer.toLowerCase())) {
      score += 50;
      matchedFields.push('manufacturer');
    }

    if (query.model && item.metadata?.model?.toLowerCase().includes(query.model.toLowerCase())) {
      score += 40;
      matchedFields.push('model');
    }

    if (query.brand && item.metadata?.brand?.toLowerCase().includes(query.brand.toLowerCase())) {
      score += 30;
      matchedFields.push('brand');
    }

    if (query.text) {
      const textLower = query.text.toLowerCase();
      if (item.metadata?.name?.toLowerCase().includes(textLower)) {
        score += 25;
        matchedFields.push('name');
      }
      if (item.metadata?.description?.toLowerCase().includes(textLower)) {
        score += 15;
        matchedFields.push('description');
      }
    }

    if (query.imageHash) {
      const hasImage = item.metadata?.imageHashes?.includes(query.imageHash) ||
        item.metadata?.images?.some((img: any) => img.sha256Hex === query.imageHash);
      if (hasImage) {
        score += 80;
        matchedFields.push('imageHash');
      }
    }

    // Boost authenticated items
    if (item.authentications?.some(a => a.isAuthentic === true)) {
      score += 10;
      matchedFields.push('authenticated');
    }

    return { score, matchedFields };
  }

  /**
   * Find items with the same serial number and manufacturer (potential duplicates)
   */
  private findDuplicates(item: SearchableItem): string[] {
    const serialMatches = this.serialHashIndex.get(item.serialNumberHash);
    if (!serialMatches || serialMatches.size <= 1) {
      return [item.itemId];
    }

    // Filter to same manufacturer
    const duplicates: string[] = [];
    for (const candidateId of serialMatches) {
      const candidate = this.items.get(candidateId);
      if (candidate && candidate.manufacturerId === item.manufacturerId) {
        duplicates.push(candidateId);
      }
    }

    return duplicates;
  }

  /**
   * Check if an item would be a duplicate before registration
   */
  checkForDuplicates(
    manufacturerId: string,
    serialNumber: string,
    imageHashes?: string[]
  ): DuplicateCheckResult {
    const serialHash = sha256(serialNumber);
    const existingItems: DuplicateCheckResult['existingItems'] = [];

    // Check serial number + manufacturer combination
    const serialMatches = this.serialHashIndex.get(serialHash);
    if (serialMatches) {
      for (const itemId of serialMatches) {
        const item = this.items.get(itemId);
        if (item && item.manufacturerId === manufacturerId) {
          existingItems.push({
            itemId,
            registeredAt: item.registeredAt,
            currentOwner: item.currentOwner,
            matchType: 'serial_manufacturer',
          });
        }
      }
    }

    // Check image hashes
    if (imageHashes) {
      for (const hash of imageHashes) {
        const imageMatches = this.imageHashIndex.get(hash);
        if (imageMatches) {
          for (const itemId of imageMatches) {
            const item = this.items.get(itemId);
            if (item && !existingItems.some(e => e.itemId === itemId)) {
              existingItems.push({
                itemId,
                registeredAt: item.registeredAt,
                currentOwner: item.currentOwner,
                matchType: 'image_hash',
              });
            }
          }
        }
      }
    }

    return {
      hasDuplicates: existingItems.length > 0,
      existingItems,
    };
  }

  /**
   * Find items by image hash (verify image authenticity)
   */
  findByImageHash(imageHash: string): SearchableItem[] {
    const itemIds = this.imageHashIndex.get(imageHash);
    if (!itemIds) return [];

    return Array.from(itemIds)
      .map(id => this.items.get(id))
      .filter((item): item is SearchableItem => item !== undefined);
  }

  /**
   * Get all items from a specific manufacturer
   */
  getByManufacturer(manufacturerId: string): SearchableItem[] {
    const itemIds = this.manufacturerIndex.get(manufacturerId.toLowerCase());
    if (!itemIds) return [];

    return Array.from(itemIds)
      .map(id => this.items.get(id))
      .filter((item): item is SearchableItem => item !== undefined);
  }

  /**
   * Get statistics about the search index
   */
  getStats(): {
    totalItems: number;
    uniqueManufacturers: number;
    uniqueSerialHashes: number;
    uniqueImageHashes: number;
    uniqueCategories: number;
    textIndexTokens: number;
  } {
    return {
      totalItems: this.items.size,
      uniqueManufacturers: this.manufacturerIndex.size,
      uniqueSerialHashes: this.serialHashIndex.size,
      uniqueImageHashes: this.imageHashIndex.size,
      uniqueCategories: this.categoryIndex.size,
      textIndexTokens: this.textIndex.size,
    };
  }

  /**
   * Helper to intersect two sets
   */
  private intersect(a: Set<string>, b: Set<string>): Set<string> {
    const result = new Set<string>();
    for (const item of a) {
      if (b.has(item)) {
        result.add(item);
      }
    }
    return result;
  }
}

/**
 * Hash an image for ledger storage
 * The hash is stored on the ledger, not the image itself
 */
export function hashImage(imageData: Buffer | string): string {
  if (typeof imageData === 'string') {
    // Assume base64
    const buffer = Buffer.from(imageData, 'base64');
    return sha256(buffer.toString('hex'));
  }
  return sha256(imageData.toString('hex'));
}

/**
 * Verify an image matches a stored hash
 */
export function verifyImageHash(imageData: Buffer | string, expectedHash: string): boolean {
  const actualHash = hashImage(imageData);
  return actualHash === expectedHash;
}
