/**
 * Global Entity Registry
 * 
 * Maintains a canonical list of known entities (manufacturers, artists, athletes,
 * celebrities, brands) to prevent duplicate entries from typos/misspellings.
 * 
 * Features:
 * - Canonical names with aliases
 * - Verification status (official, community, user-submitted)
 * - Fuzzy search for autocomplete
 * - Governance for merging duplicates
 */

import { EventStore } from '../event-store/event-store';

// ============================================================================
// Types
// ============================================================================

export type EntityType = 
  | 'manufacturer'    // Rolex, Louis Vuitton, Nike, Apple
  | 'artist'          // Banksy, Picasso, local artists
  | 'athlete'         // Michael Jordan, Tom Brady
  | 'celebrity'       // Actors, musicians, public figures
  | 'brand'           // Generic brands
  | 'designer'        // Fashion designers, product designers
  | 'author'          // Book authors for signed editions
  | 'musician'        // Musicians for signed memorabilia
  | 'team';           // Sports teams

export type VerificationStatus = 
  | 'official'        // Verified by the entity themselves or trusted source
  | 'community'       // Verified by multiple authenticators
  | 'user_submitted'  // Added by users, not yet verified
  | 'pending_review'; // Flagged for review

export type EntityCategory =
  | 'luxury_watches'
  | 'luxury_fashion'
  | 'sneakers'
  | 'electronics'
  | 'art'
  | 'sports_memorabilia'
  | 'trading_cards'
  | 'music_memorabilia'
  | 'autographs'
  | 'collectibles'
  | 'jewelry'
  | 'handbags'
  | 'wine_spirits'
  | 'automobiles'
  | 'other';

export interface EntityAlias {
  alias: string;
  language?: string;      // ISO 639-1 code (en, fr, jp, etc.)
  isCommonMisspelling?: boolean;
}

export interface EntitySocialLinks {
  website?: string;
  instagram?: string;
  twitter?: string;
  wikipedia?: string;
}

export interface GlobalEntity {
  entityId: string;
  type: EntityType;
  
  // Canonical name (the "correct" spelling)
  canonicalName: string;
  
  // Display name (may include special characters, accents)
  displayName: string;
  
  // Alternative names, translations, common misspellings
  aliases: EntityAlias[];
  
  // Categories this entity belongs to
  categories: EntityCategory[];
  
  // Verification
  verificationStatus: VerificationStatus;
  verifiedAt?: number;
  verifiedBy?: string;  // Account ID of verifier
  
  // Optional metadata
  description?: string;
  country?: string;     // ISO 3166-1 alpha-2
  foundedYear?: number;
  socialLinks?: EntitySocialLinks;
  logoUrl?: string;
  
  // For manufacturers: official manufacturer account ID if registered
  linkedAccountId?: string;
  
  // Stats
  itemCount: number;    // Number of items on ledger with this entity
  
  // Timestamps
  createdAt: number;
  updatedAt: number;
  createdBy: string;    // Account ID
}

export interface EntitySearchQuery {
  query: string;
  types?: EntityType[];
  categories?: EntityCategory[];
  verifiedOnly?: boolean;
  limit?: number;
}

export interface EntitySearchResult {
  entity: GlobalEntity;
  score: number;
  matchedOn: 'canonical' | 'alias' | 'fuzzy';
}

export interface EntityMergeRequest {
  sourceEntityId: string;
  targetEntityId: string;
  requestedBy: string;
  reason: string;
}

// ============================================================================
// Entity Registry Service
// ============================================================================

export class EntityRegistry {
  private entities: Map<string, GlobalEntity> = new Map();
  
  // Indexes for fast lookup
  private nameIndex: Map<string, string[]> = new Map();  // normalized name -> entityIds
  private typeIndex: Map<EntityType, Set<string>> = new Map();
  private categoryIndex: Map<EntityCategory, Set<string>> = new Map();
  
  constructor(
    private eventStore: EventStore
  ) {
    this.initializeIndexes();
  }

  private initializeIndexes(): void {
    for (const type of ['manufacturer', 'artist', 'athlete', 'celebrity', 'brand', 'designer', 'author', 'musician', 'team'] as EntityType[]) {
      this.typeIndex.set(type, new Set());
    }
  }

  // ============================================================================
  // Core Operations
  // ============================================================================

  /**
   * Register a new entity
   */
  async registerEntity(
    entity: Omit<GlobalEntity, 'entityId' | 'itemCount' | 'createdAt' | 'updatedAt' | 'createdBy'>,
    createdBy: string
  ): Promise<GlobalEntity> {
    // Check for potential duplicates first
    const duplicates = await this.findPotentialDuplicates(entity.canonicalName, entity.type);
    if (duplicates.length > 0) {
      const exactMatch = duplicates.find(d => 
        this.normalize(d.entity.canonicalName) === this.normalize(entity.canonicalName)
      );
      if (exactMatch) {
        throw new Error(`Entity already exists: ${exactMatch.entity.canonicalName} (${exactMatch.entity.entityId})`);
      }
    }

    const entityId = `entity_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const now = Date.now();

    const newEntity: GlobalEntity = {
      ...entity,
      entityId,
      itemCount: 0,
      createdAt: now,
      updatedAt: now,
      createdBy,
    };

    // Store in memory
    this.entities.set(entityId, newEntity);
    this.indexEntity(newEntity);

    // Persist to event store
    await this.persistEntityEvent('ENTITY_REGISTERED', newEntity);

    return newEntity;
  }

  /**
   * Update an existing entity
   */
  async updateEntity(
    entityId: string,
    updates: Partial<Pick<GlobalEntity, 'displayName' | 'aliases' | 'categories' | 'description' | 'country' | 'socialLinks' | 'logoUrl'>>,
    updatedBy: string
  ): Promise<GlobalEntity> {
    const entity = this.entities.get(entityId);
    if (!entity) {
      throw new Error(`Entity not found: ${entityId}`);
    }

    // Remove from indexes before update
    this.removeFromIndexes(entity);

    // Apply updates
    const updatedEntity: GlobalEntity = {
      ...entity,
      ...updates,
      updatedAt: Date.now(),
    };

    // Re-index
    this.entities.set(entityId, updatedEntity);
    this.indexEntity(updatedEntity);

    // Persist
    await this.persistEntityEvent('ENTITY_UPDATED', updatedEntity, { updatedBy });

    return updatedEntity;
  }

  /**
   * Add an alias to an entity
   */
  async addAlias(entityId: string, alias: EntityAlias, addedBy: string): Promise<GlobalEntity> {
    const entity = this.entities.get(entityId);
    if (!entity) {
      throw new Error(`Entity not found: ${entityId}`);
    }

    // Check if alias already exists
    const normalizedAlias = this.normalize(alias.alias);
    const existingAlias = entity.aliases.find(a => this.normalize(a.alias) === normalizedAlias);
    if (existingAlias) {
      return entity; // Already exists, no-op
    }

    const updatedAliases = [...entity.aliases, alias];
    return this.updateEntity(entityId, { aliases: updatedAliases }, addedBy);
  }

  /**
   * Verify an entity
   */
  async verifyEntity(
    entityId: string,
    status: VerificationStatus,
    verifiedBy: string
  ): Promise<GlobalEntity> {
    const entity = this.entities.get(entityId);
    if (!entity) {
      throw new Error(`Entity not found: ${entityId}`);
    }

    const updatedEntity: GlobalEntity = {
      ...entity,
      verificationStatus: status,
      verifiedAt: Date.now(),
      verifiedBy,
      updatedAt: Date.now(),
    };

    this.entities.set(entityId, updatedEntity);
    await this.persistEntityEvent('ENTITY_VERIFIED', updatedEntity);

    return updatedEntity;
  }

  /**
   * Link entity to a registered account (e.g., official manufacturer account)
   */
  async linkAccount(entityId: string, accountId: string, linkedBy: string): Promise<GlobalEntity> {
    const entity = this.entities.get(entityId);
    if (!entity) {
      throw new Error(`Entity not found: ${entityId}`);
    }

    const updatedEntity: GlobalEntity = {
      ...entity,
      linkedAccountId: accountId,
      updatedAt: Date.now(),
    };

    this.entities.set(entityId, updatedEntity);
    await this.persistEntityEvent('ENTITY_ACCOUNT_LINKED', updatedEntity, { linkedBy });

    return updatedEntity;
  }

  /**
   * Merge two entities (governance action)
   */
  async mergeEntities(
    sourceEntityId: string,
    targetEntityId: string,
    mergedBy: string,
    reason: string
  ): Promise<GlobalEntity> {
    const source = this.entities.get(sourceEntityId);
    const target = this.entities.get(targetEntityId);

    if (!source || !target) {
      throw new Error('Source or target entity not found');
    }

    if (source.type !== target.type) {
      throw new Error('Cannot merge entities of different types');
    }

    // Merge aliases from source into target
    const mergedAliases = [...target.aliases];
    
    // Add source's canonical name as an alias
    mergedAliases.push({ alias: source.canonicalName });
    
    // Add source's aliases
    for (const alias of source.aliases) {
      if (!mergedAliases.some(a => this.normalize(a.alias) === this.normalize(alias.alias))) {
        mergedAliases.push(alias);
      }
    }

    // Update target with merged data
    const mergedEntity: GlobalEntity = {
      ...target,
      aliases: mergedAliases,
      itemCount: target.itemCount + source.itemCount,
      updatedAt: Date.now(),
    };

    // Remove source from indexes
    this.removeFromIndexes(source);
    this.entities.delete(sourceEntityId);

    // Update target
    this.entities.set(targetEntityId, mergedEntity);
    this.removeFromIndexes(target);
    this.indexEntity(mergedEntity);

    // Persist merge event
    await this.persistEntityEvent('ENTITY_MERGED', mergedEntity, {
      sourceEntityId,
      mergedBy,
      reason,
    });

    return mergedEntity;
  }

  // ============================================================================
  // Search & Lookup
  // ============================================================================

  /**
   * Search entities with fuzzy matching (for autocomplete)
   */
  search(query: EntitySearchQuery): EntitySearchResult[] {
    const { query: searchTerm, types, categories, verifiedOnly, limit = 20 } = query;
    const normalizedQuery = this.normalize(searchTerm);
    const results: EntitySearchResult[] = [];

    for (const entity of this.entities.values()) {
      // Filter by type
      if (types && types.length > 0 && !types.includes(entity.type)) {
        continue;
      }

      // Filter by category
      if (categories && categories.length > 0) {
        const hasCategory = entity.categories.some(c => categories.includes(c));
        if (!hasCategory) continue;
      }

      // Filter by verification status
      if (verifiedOnly && entity.verificationStatus === 'user_submitted') {
        continue;
      }

      // Check for matches
      const match = this.matchEntity(entity, normalizedQuery);
      if (match) {
        results.push(match);
      }
    }

    // Sort by score (highest first), then by item count
    results.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return b.entity.itemCount - a.entity.itemCount;
    });

    return results.slice(0, limit);
  }

  /**
   * Get entity by ID
   */
  getById(entityId: string): GlobalEntity | undefined {
    return this.entities.get(entityId);
  }

  /**
   * Get entity by exact canonical name
   */
  getByCanonicalName(name: string, type?: EntityType): GlobalEntity | undefined {
    const normalized = this.normalize(name);
    const entityIds = this.nameIndex.get(normalized) || [];
    
    for (const id of entityIds) {
      const entity = this.entities.get(id);
      if (entity && (!type || entity.type === type)) {
        if (this.normalize(entity.canonicalName) === normalized) {
          return entity;
        }
      }
    }
    return undefined;
  }

  /**
   * Get all entities of a specific type
   */
  getByType(type: EntityType, limit = 100): GlobalEntity[] {
    const entityIds = this.typeIndex.get(type) || new Set();
    const entities: GlobalEntity[] = [];
    
    for (const id of entityIds) {
      const entity = this.entities.get(id);
      if (entity) {
        entities.push(entity);
        if (entities.length >= limit) break;
      }
    }
    
    return entities.sort((a, b) => b.itemCount - a.itemCount);
  }

  /**
   * Get all entities in a category
   */
  getByCategory(category: EntityCategory, limit = 100): GlobalEntity[] {
    const entityIds = this.categoryIndex.get(category) || new Set();
    const entities: GlobalEntity[] = [];
    
    for (const id of entityIds) {
      const entity = this.entities.get(id);
      if (entity) {
        entities.push(entity);
        if (entities.length >= limit) break;
      }
    }
    
    return entities.sort((a, b) => b.itemCount - a.itemCount);
  }

  /**
   * Find potential duplicates for a name
   */
  async findPotentialDuplicates(name: string, type: EntityType): Promise<EntitySearchResult[]> {
    return this.search({
      query: name,
      types: [type],
      limit: 10,
    }).filter(r => r.score > 0.7); // High similarity threshold
  }

  /**
   * Resolve a name to an entity (best match)
   */
  resolveEntity(name: string, type?: EntityType): GlobalEntity | undefined {
    const results = this.search({
      query: name,
      types: type ? [type] : undefined,
      limit: 1,
    });
    
    // Only return if it's a strong match
    if (results.length > 0 && results[0].score > 0.9) {
      return results[0].entity;
    }
    return undefined;
  }

  // ============================================================================
  // Stats
  // ============================================================================

  /**
   * Increment item count for an entity
   */
  incrementItemCount(entityId: string): void {
    const entity = this.entities.get(entityId);
    if (entity) {
      entity.itemCount++;
      entity.updatedAt = Date.now();
    }
  }

  /**
   * Get registry statistics
   */
  getStats(): {
    totalEntities: number;
    byType: Record<EntityType, number>;
    byStatus: Record<VerificationStatus, number>;
    topManufacturers: GlobalEntity[];
    topArtists: GlobalEntity[];
  } {
    const byType: Record<string, number> = {};
    const byStatus: Record<string, number> = {};

    for (const entity of this.entities.values()) {
      byType[entity.type] = (byType[entity.type] || 0) + 1;
      byStatus[entity.verificationStatus] = (byStatus[entity.verificationStatus] || 0) + 1;
    }

    return {
      totalEntities: this.entities.size,
      byType: byType as Record<EntityType, number>,
      byStatus: byStatus as Record<VerificationStatus, number>,
      topManufacturers: this.getByType('manufacturer', 10),
      topArtists: this.getByType('artist', 10),
    };
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private normalize(str: string): string {
    return str
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '') // Remove diacritics
      .replace(/[^a-z0-9]/g, '')       // Remove non-alphanumeric
      .trim();
  }

  private indexEntity(entity: GlobalEntity): void {
    // Index canonical name
    const normalizedCanonical = this.normalize(entity.canonicalName);
    if (!this.nameIndex.has(normalizedCanonical)) {
      this.nameIndex.set(normalizedCanonical, []);
    }
    this.nameIndex.get(normalizedCanonical)!.push(entity.entityId);

    // Index aliases
    for (const alias of entity.aliases) {
      const normalizedAlias = this.normalize(alias.alias);
      if (!this.nameIndex.has(normalizedAlias)) {
        this.nameIndex.set(normalizedAlias, []);
      }
      this.nameIndex.get(normalizedAlias)!.push(entity.entityId);
    }

    // Index by type
    this.typeIndex.get(entity.type)?.add(entity.entityId);

    // Index by categories
    for (const category of entity.categories) {
      if (!this.categoryIndex.has(category)) {
        this.categoryIndex.set(category, new Set());
      }
      this.categoryIndex.get(category)!.add(entity.entityId);
    }
  }

  private removeFromIndexes(entity: GlobalEntity): void {
    // Remove from name index
    const normalizedCanonical = this.normalize(entity.canonicalName);
    const canonicalIds = this.nameIndex.get(normalizedCanonical);
    if (canonicalIds) {
      const idx = canonicalIds.indexOf(entity.entityId);
      if (idx !== -1) canonicalIds.splice(idx, 1);
    }

    for (const alias of entity.aliases) {
      const normalizedAlias = this.normalize(alias.alias);
      const aliasIds = this.nameIndex.get(normalizedAlias);
      if (aliasIds) {
        const idx = aliasIds.indexOf(entity.entityId);
        if (idx !== -1) aliasIds.splice(idx, 1);
      }
    }

    // Remove from type index
    this.typeIndex.get(entity.type)?.delete(entity.entityId);

    // Remove from category indexes
    for (const category of entity.categories) {
      this.categoryIndex.get(category)?.delete(entity.entityId);
    }
  }

  private matchEntity(entity: GlobalEntity, normalizedQuery: string): EntitySearchResult | null {
    // Exact match on canonical name
    const normalizedCanonical = this.normalize(entity.canonicalName);
    if (normalizedCanonical === normalizedQuery) {
      return { entity, score: 1.0, matchedOn: 'canonical' };
    }

    // Prefix match on canonical name
    if (normalizedCanonical.startsWith(normalizedQuery)) {
      const score = normalizedQuery.length / normalizedCanonical.length;
      return { entity, score: 0.9 + (score * 0.1), matchedOn: 'canonical' };
    }

    // Check aliases
    for (const alias of entity.aliases) {
      const normalizedAlias = this.normalize(alias.alias);
      if (normalizedAlias === normalizedQuery) {
        return { entity, score: 0.95, matchedOn: 'alias' };
      }
      if (normalizedAlias.startsWith(normalizedQuery)) {
        const score = normalizedQuery.length / normalizedAlias.length;
        return { entity, score: 0.85 + (score * 0.1), matchedOn: 'alias' };
      }
    }

    // Fuzzy match using Levenshtein-like scoring
    const fuzzyScore = this.fuzzyMatch(normalizedQuery, normalizedCanonical);
    if (fuzzyScore > 0.6) {
      return { entity, score: fuzzyScore * 0.8, matchedOn: 'fuzzy' };
    }

    // Check if query is contained in canonical name
    if (normalizedCanonical.includes(normalizedQuery)) {
      const score = normalizedQuery.length / normalizedCanonical.length;
      return { entity, score: 0.5 + (score * 0.3), matchedOn: 'fuzzy' };
    }

    return null;
  }

  private fuzzyMatch(query: string, target: string): number {
    if (query.length === 0) return 0;
    if (target.length === 0) return 0;

    // Simple similarity based on common characters
    const queryChars = new Set(query.split(''));
    const targetChars = new Set(target.split(''));
    
    let common = 0;
    for (const char of queryChars) {
      if (targetChars.has(char)) common++;
    }

    const similarity = (2 * common) / (queryChars.size + targetChars.size);
    
    // Boost if query is a subsequence of target
    let queryIdx = 0;
    for (const char of target) {
      if (queryIdx < query.length && char === query[queryIdx]) {
        queryIdx++;
      }
    }
    const subsequenceBonus = queryIdx === query.length ? 0.2 : 0;

    return Math.min(1, similarity + subsequenceBonus);
  }

  private async persistEntityEvent(
    eventType: string,
    entity: GlobalEntity,
    extra?: Record<string, any>
  ): Promise<void> {
    // For now, we'll store entity events in a simple format
    // In production, this would be a proper canonical event
    try {
      // Store as a generic event or in a separate entity store
      console.log(`[EntityRegistry] ${eventType}:`, entity.entityId, entity.canonicalName);
    } catch (error) {
      console.error(`[EntityRegistry] Failed to persist ${eventType}:`, error);
    }
  }

  // ============================================================================
  // Seed Data
  // ============================================================================

  /**
   * Load initial seed data for common manufacturers/artists
   */
  async loadSeedData(): Promise<void> {
    const seedEntities = getSeedEntities();
    
    for (const seed of seedEntities) {
      try {
        // Check if already exists
        const existing = this.getByCanonicalName(seed.canonicalName, seed.type);
        if (!existing) {
          await this.registerEntity(seed, 'system');
        }
      } catch (error) {
        // Ignore duplicates
      }
    }

    console.log(`[EntityRegistry] Loaded ${this.entities.size} entities`);
  }

  /**
   * Export all entities (for backup/sync)
   */
  exportAll(): GlobalEntity[] {
    return Array.from(this.entities.values());
  }

  /**
   * Import entities (for restore/sync)
   */
  async importEntities(entities: GlobalEntity[]): Promise<void> {
    for (const entity of entities) {
      this.entities.set(entity.entityId, entity);
      this.indexEntity(entity);
    }
  }
}

// ============================================================================
// Seed Data - Common Manufacturers, Artists, Athletes
// ============================================================================

type SeedEntity = Omit<GlobalEntity, 'entityId' | 'itemCount' | 'createdAt' | 'updatedAt' | 'createdBy'>;

function getSeedEntities(): SeedEntity[] {
  return [
    // Luxury Watches
    {
      type: 'manufacturer',
      canonicalName: 'Rolex',
      displayName: 'Rolex',
      aliases: [{ alias: 'Rolex SA' }, { alias: 'Rollex', isCommonMisspelling: true }],
      categories: ['luxury_watches'],
      verificationStatus: 'official',
      country: 'CH',
      foundedYear: 1905,
      description: 'Swiss luxury watch manufacturer',
    },
    {
      type: 'manufacturer',
      canonicalName: 'Patek Philippe',
      displayName: 'Patek Philippe',
      aliases: [{ alias: 'Patek' }, { alias: 'PP' }],
      categories: ['luxury_watches'],
      verificationStatus: 'official',
      country: 'CH',
      foundedYear: 1839,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Audemars Piguet',
      displayName: 'Audemars Piguet',
      aliases: [{ alias: 'AP' }, { alias: 'Audemars' }],
      categories: ['luxury_watches'],
      verificationStatus: 'official',
      country: 'CH',
      foundedYear: 1875,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Omega',
      displayName: 'Omega',
      aliases: [{ alias: 'Omega SA' }],
      categories: ['luxury_watches'],
      verificationStatus: 'official',
      country: 'CH',
      foundedYear: 1848,
    },
    {
      type: 'manufacturer',
      canonicalName: 'TAG Heuer',
      displayName: 'TAG Heuer',
      aliases: [{ alias: 'Tag Heuer' }, { alias: 'TAG' }, { alias: 'Heuer' }],
      categories: ['luxury_watches'],
      verificationStatus: 'official',
      country: 'CH',
      foundedYear: 1860,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Cartier',
      displayName: 'Cartier',
      aliases: [],
      categories: ['luxury_watches', 'jewelry'],
      verificationStatus: 'official',
      country: 'FR',
      foundedYear: 1847,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Richard Mille',
      displayName: 'Richard Mille',
      aliases: [{ alias: 'RM' }],
      categories: ['luxury_watches'],
      verificationStatus: 'official',
      country: 'CH',
      foundedYear: 2001,
    },

    // Luxury Fashion
    {
      type: 'manufacturer',
      canonicalName: 'Louis Vuitton',
      displayName: 'Louis Vuitton',
      aliases: [{ alias: 'LV' }, { alias: 'Vuitton' }],
      categories: ['luxury_fashion', 'handbags'],
      verificationStatus: 'official',
      country: 'FR',
      foundedYear: 1854,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Hermès',
      displayName: 'Hermès',
      aliases: [{ alias: 'Hermes' }, { alias: 'Hermès Paris' }],
      categories: ['luxury_fashion', 'handbags'],
      verificationStatus: 'official',
      country: 'FR',
      foundedYear: 1837,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Chanel',
      displayName: 'Chanel',
      aliases: [{ alias: 'Coco Chanel' }],
      categories: ['luxury_fashion', 'handbags'],
      verificationStatus: 'official',
      country: 'FR',
      foundedYear: 1910,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Gucci',
      displayName: 'Gucci',
      aliases: [],
      categories: ['luxury_fashion', 'handbags'],
      verificationStatus: 'official',
      country: 'IT',
      foundedYear: 1921,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Prada',
      displayName: 'Prada',
      aliases: [],
      categories: ['luxury_fashion', 'handbags'],
      verificationStatus: 'official',
      country: 'IT',
      foundedYear: 1913,
    },

    // Sneakers
    {
      type: 'manufacturer',
      canonicalName: 'Nike',
      displayName: 'Nike',
      aliases: [{ alias: 'Nike Inc' }],
      categories: ['sneakers'],
      verificationStatus: 'official',
      country: 'US',
      foundedYear: 1964,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Adidas',
      displayName: 'Adidas',
      aliases: [{ alias: 'Adidas AG' }],
      categories: ['sneakers'],
      verificationStatus: 'official',
      country: 'DE',
      foundedYear: 1949,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Jordan Brand',
      displayName: 'Jordan Brand',
      aliases: [{ alias: 'Air Jordan' }, { alias: 'Jordan' }],
      categories: ['sneakers'],
      verificationStatus: 'official',
      country: 'US',
      foundedYear: 1984,
    },
    {
      type: 'manufacturer',
      canonicalName: 'New Balance',
      displayName: 'New Balance',
      aliases: [{ alias: 'NB' }],
      categories: ['sneakers'],
      verificationStatus: 'official',
      country: 'US',
      foundedYear: 1906,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Yeezy',
      displayName: 'Yeezy',
      aliases: [],
      categories: ['sneakers'],
      verificationStatus: 'official',
      country: 'US',
      foundedYear: 2015,
    },

    // Trading Cards
    {
      type: 'manufacturer',
      canonicalName: 'Topps',
      displayName: 'Topps',
      aliases: [{ alias: 'The Topps Company' }],
      categories: ['trading_cards', 'collectibles'],
      verificationStatus: 'official',
      country: 'US',
      foundedYear: 1938,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Panini',
      displayName: 'Panini',
      aliases: [{ alias: 'Panini America' }],
      categories: ['trading_cards', 'collectibles'],
      verificationStatus: 'official',
      country: 'IT',
      foundedYear: 1961,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Upper Deck',
      displayName: 'Upper Deck',
      aliases: [{ alias: 'UD' }],
      categories: ['trading_cards', 'collectibles'],
      verificationStatus: 'official',
      country: 'US',
      foundedYear: 1988,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Pokemon Company',
      displayName: 'The Pokémon Company',
      aliases: [{ alias: 'Pokemon' }, { alias: 'Pokémon' }, { alias: 'TPC' }],
      categories: ['trading_cards', 'collectibles'],
      verificationStatus: 'official',
      country: 'JP',
      foundedYear: 1998,
    },

    // Famous Athletes (for memorabilia/autographs)
    {
      type: 'athlete',
      canonicalName: 'Michael Jordan',
      displayName: 'Michael Jordan',
      aliases: [{ alias: 'MJ' }, { alias: 'Air Jordan' }],
      categories: ['sports_memorabilia', 'autographs'],
      verificationStatus: 'official',
      country: 'US',
      description: 'NBA legend, 6x NBA Champion',
    },
    {
      type: 'athlete',
      canonicalName: 'LeBron James',
      displayName: 'LeBron James',
      aliases: [{ alias: 'King James' }, { alias: 'LBJ' }],
      categories: ['sports_memorabilia', 'autographs', 'trading_cards'],
      verificationStatus: 'official',
      country: 'US',
    },
    {
      type: 'athlete',
      canonicalName: 'Tom Brady',
      displayName: 'Tom Brady',
      aliases: [{ alias: 'TB12' }],
      categories: ['sports_memorabilia', 'autographs', 'trading_cards'],
      verificationStatus: 'official',
      country: 'US',
    },
    {
      type: 'athlete',
      canonicalName: 'Lionel Messi',
      displayName: 'Lionel Messi',
      aliases: [{ alias: 'Messi' }, { alias: 'Leo Messi' }],
      categories: ['sports_memorabilia', 'autographs', 'trading_cards'],
      verificationStatus: 'official',
      country: 'AR',
    },
    {
      type: 'athlete',
      canonicalName: 'Cristiano Ronaldo',
      displayName: 'Cristiano Ronaldo',
      aliases: [{ alias: 'CR7' }, { alias: 'Ronaldo' }],
      categories: ['sports_memorabilia', 'autographs', 'trading_cards'],
      verificationStatus: 'official',
      country: 'PT',
    },

    // Famous Artists
    {
      type: 'artist',
      canonicalName: 'Banksy',
      displayName: 'Banksy',
      aliases: [],
      categories: ['art'],
      verificationStatus: 'official',
      country: 'GB',
      description: 'Anonymous street artist',
    },
    {
      type: 'artist',
      canonicalName: 'KAWS',
      displayName: 'KAWS',
      aliases: [{ alias: 'Brian Donnelly' }],
      categories: ['art', 'collectibles'],
      verificationStatus: 'official',
      country: 'US',
    },
    {
      type: 'artist',
      canonicalName: 'Takashi Murakami',
      displayName: 'Takashi Murakami',
      aliases: [{ alias: 'Murakami' }],
      categories: ['art'],
      verificationStatus: 'official',
      country: 'JP',
    },
    {
      type: 'artist',
      canonicalName: 'Damien Hirst',
      displayName: 'Damien Hirst',
      aliases: [],
      categories: ['art'],
      verificationStatus: 'official',
      country: 'GB',
    },

    // Electronics
    {
      type: 'manufacturer',
      canonicalName: 'Apple',
      displayName: 'Apple',
      aliases: [{ alias: 'Apple Inc' }],
      categories: ['electronics'],
      verificationStatus: 'official',
      country: 'US',
      foundedYear: 1976,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Sony',
      displayName: 'Sony',
      aliases: [{ alias: 'Sony Corporation' }],
      categories: ['electronics', 'collectibles'],
      verificationStatus: 'official',
      country: 'JP',
      foundedYear: 1946,
    },

    // Wine & Spirits
    {
      type: 'manufacturer',
      canonicalName: 'Dom Pérignon',
      displayName: 'Dom Pérignon',
      aliases: [{ alias: 'Dom Perignon' }, { alias: 'DP' }],
      categories: ['wine_spirits'],
      verificationStatus: 'official',
      country: 'FR',
      foundedYear: 1921,
    },
    {
      type: 'manufacturer',
      canonicalName: 'Macallan',
      displayName: 'The Macallan',
      aliases: [{ alias: 'Macallan' }],
      categories: ['wine_spirits'],
      verificationStatus: 'official',
      country: 'GB',
      foundedYear: 1824,
    },
  ];
}

// Export singleton factory
export function createEntityRegistry(eventStore: EventStore): EntityRegistry {
  return new EntityRegistry(eventStore);
}
