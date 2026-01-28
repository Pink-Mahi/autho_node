/**
 * Item Provenance Service
 * 
 * Provides comprehensive ownership history, price history, and provenance
 * tracking for items on the ledger. This is critical for:
 * - Buyers verifying item history before purchase
 * - Detecting suspicious patterns (rapid flipping, price manipulation)
 * - Building trust through transparent ownership chains
 * - Insurance and valuation purposes
 */

import { EventStore, Event, EventType } from '../event-store';

export interface OwnershipRecord {
  owner: string;
  acquiredAt: number;
  acquiredFrom?: string;
  acquiredPrice?: number;
  acquiredMethod: 'mint' | 'purchase' | 'transfer' | 'gift';
  soldAt?: number;
  soldTo?: string;
  soldPrice?: number;
  holdDurationDays?: number;
  settlementId?: string;
  txid?: string;
}

export interface PriceRecord {
  price: number;
  timestamp: number;
  type: 'sale' | 'listing' | 'offer';
  from?: string;
  to?: string;
  settlementId?: string;
  txid?: string;
}

export interface AuthenticationRecord {
  authenticatorId: string;
  authenticatorName?: string;
  performedAt: number;
  isAuthentic: boolean;
  manufacturerVerified?: boolean;
  confidence: 'high' | 'medium' | 'low';
  notes?: string;
  attestationId?: string;
  feeTxid?: string;
}

export interface ItemProvenance {
  itemId: string;
  manufacturerName: string;
  manufacturerId?: string;
  mintedAt: number;
  mintedBy: string;
  issuerRole: 'manufacturer' | 'authenticator' | 'user';
  currentOwner: string;
  
  // Ownership chain
  ownershipHistory: OwnershipRecord[];
  totalOwners: number;
  averageHoldDays: number;
  longestHoldDays: number;
  shortestHoldDays: number;
  
  // Price history
  priceHistory: PriceRecord[];
  mintPrice?: number;
  lastSalePrice?: number;
  highestPrice?: number;
  lowestPrice?: number;
  averagePrice?: number;
  priceChange?: number; // percentage from first to last sale
  
  // Authentication history
  authenticationHistory: AuthenticationRecord[];
  totalAuthentications: number;
  lastAuthentication?: AuthenticationRecord;
  isVerified: boolean;
  manufacturerVerified: boolean;
  
  // Risk indicators
  riskIndicators: RiskIndicator[];
  riskScore: number; // 0-100, higher = more risk
  
  // Timeline
  events: ProvenanceEvent[];
}

export interface ProvenanceEvent {
  type: string;
  timestamp: number;
  description: string;
  details: any;
}

export interface RiskIndicator {
  type: 'rapid_flip' | 'price_spike' | 'price_drop' | 'no_authentication' | 'failed_authentication' | 'multiple_duplicates' | 'suspicious_pattern';
  severity: 'low' | 'medium' | 'high';
  description: string;
  detectedAt: number;
}

export interface MarketStats {
  manufacturerName: string;
  category?: string;
  totalItems: number;
  totalSales: number;
  averagePrice: number;
  medianPrice: number;
  highestPrice: number;
  lowestPrice: number;
  priceRange: { min: number; max: number };
  recentSales: PriceRecord[];
  priceHistory30Days: PriceRecord[];
  volumeLast30Days: number;
}

export class ItemProvenanceService {
  constructor(private eventStore: EventStore) {}

  /**
   * Get complete provenance for an item
   */
  async getItemProvenance(itemId: string): Promise<ItemProvenance | null> {
    const events = await this.eventStore.getEventsByItemId(itemId);
    if (events.length === 0) return null;

    // Sort events by timestamp
    events.sort((a, b) => {
      const tsA = (a.payload as any).timestamp || 0;
      const tsB = (b.payload as any).timestamp || 0;
      return tsA - tsB;
    });

    // Find registration event
    const registrationEvent = events.find(e => (e.payload as any).type === EventType.ITEM_REGISTERED);
    if (!registrationEvent) return null;

    const regPayload = registrationEvent.payload as any;
    
    // Build ownership history
    const ownershipHistory = this.buildOwnershipHistory(events, regPayload.initialOwner);
    
    // Build price history
    const priceHistory = this.buildPriceHistory(events);
    
    // Build authentication history
    const authenticationHistory = this.buildAuthenticationHistory(events);
    
    // Calculate statistics
    const ownershipStats = this.calculateOwnershipStats(ownershipHistory);
    const priceStats = this.calculatePriceStats(priceHistory);
    
    // Detect risk indicators
    const riskIndicators = this.detectRiskIndicators(ownershipHistory, priceHistory, authenticationHistory);
    const riskScore = this.calculateRiskScore(riskIndicators);
    
    // Build timeline
    const timeline = this.buildTimeline(events);
    
    // Determine current owner
    const currentOwner = ownershipHistory.length > 0 
      ? ownershipHistory[ownershipHistory.length - 1].owner 
      : regPayload.initialOwner;

    // Check verification status
    const isVerified = authenticationHistory.some(a => a.isAuthentic);
    const manufacturerVerified = authenticationHistory.some(a => a.manufacturerVerified) ||
      (regPayload.issuerRole === 'manufacturer' && !!regPayload.manufacturerId);

    return {
      itemId,
      manufacturerName: regPayload.manufacturerName || regPayload.manufacturerId || 'Unknown',
      manufacturerId: regPayload.manufacturerId,
      mintedAt: regPayload.timestamp,
      mintedBy: regPayload.issuerAccountId || regPayload.initialOwner,
      issuerRole: regPayload.issuerRole || 'user',
      currentOwner,
      
      ownershipHistory,
      ...ownershipStats,
      
      priceHistory,
      ...priceStats,
      
      authenticationHistory,
      totalAuthentications: authenticationHistory.length,
      lastAuthentication: authenticationHistory[authenticationHistory.length - 1],
      isVerified,
      manufacturerVerified,
      
      riskIndicators,
      riskScore,
      
      events: timeline,
    };
  }

  /**
   * Build ownership history from events
   */
  private buildOwnershipHistory(events: Event[], initialOwner: string): OwnershipRecord[] {
    const history: OwnershipRecord[] = [];
    let currentOwner = initialOwner;
    let acquiredAt = 0;

    // First record: minting
    const regEvent = events.find(e => (e.payload as any).type === EventType.ITEM_REGISTERED);
    if (regEvent) {
      const regPayload = regEvent.payload as any;
      acquiredAt = regPayload.timestamp;
      history.push({
        owner: initialOwner,
        acquiredAt,
        acquiredMethod: 'mint',
      });
    }

    // Process transfer and settlement events
    for (const event of events) {
      const payload = event.payload as any;
      
      if (payload.type === EventType.OWNERSHIP_TRANSFERRED) {
        // Update previous owner's record
        if (history.length > 0) {
          const lastRecord = history[history.length - 1];
          lastRecord.soldAt = payload.timestamp;
          lastRecord.soldTo = payload.toOwner;
          lastRecord.soldPrice = payload.price;
          lastRecord.holdDurationDays = Math.floor((payload.timestamp - lastRecord.acquiredAt) / (1000 * 60 * 60 * 24));
        }

        // Add new owner record
        history.push({
          owner: payload.toOwner,
          acquiredAt: payload.timestamp,
          acquiredFrom: payload.fromOwner,
          acquiredPrice: payload.price,
          acquiredMethod: payload.price ? 'purchase' : 'transfer',
          settlementId: payload.settlementId,
          txid: payload.paymentTxHash,
        });

        currentOwner = payload.toOwner;
        acquiredAt = payload.timestamp;
      }
    }

    // Calculate hold duration for current owner
    if (history.length > 0) {
      const lastRecord = history[history.length - 1];
      if (!lastRecord.soldAt) {
        lastRecord.holdDurationDays = Math.floor((Date.now() - lastRecord.acquiredAt) / (1000 * 60 * 60 * 24));
      }
    }

    return history;
  }

  /**
   * Build price history from events
   */
  private buildPriceHistory(events: Event[]): PriceRecord[] {
    const history: PriceRecord[] = [];

    for (const event of events) {
      const payload = event.payload as any;

      if (payload.type === EventType.OWNERSHIP_TRANSFERRED && payload.price) {
        history.push({
          price: payload.price,
          timestamp: payload.timestamp,
          type: 'sale',
          from: payload.fromOwner,
          to: payload.toOwner,
          settlementId: payload.settlementId,
          txid: payload.paymentTxHash,
        });
      }

      if (payload.type === EventType.SETTLEMENT_INITIATED) {
        history.push({
          price: payload.price,
          timestamp: payload.timestamp,
          type: 'listing',
          from: payload.seller,
          to: payload.buyer,
          settlementId: payload.settlementId,
        });
      }
    }

    return history.sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Build authentication history from events
   */
  private buildAuthenticationHistory(events: Event[]): AuthenticationRecord[] {
    const history: AuthenticationRecord[] = [];

    for (const event of events) {
      const payload = event.payload as any;

      if (payload.type === EventType.AUTHENTICATION_PERFORMED || 
          payload.type === EventType.AUTHENTICATION_RESULT_RECORDED ||
          payload.type === EventType.VERIFICATION_REQUEST_COMPLETED) {
        history.push({
          authenticatorId: payload.authenticatorId,
          performedAt: payload.timestamp || payload.performedAt || payload.completedAt,
          isAuthentic: payload.isAuthentic ?? true,
          manufacturerVerified: payload.manufacturerVerified,
          confidence: payload.confidence || 'medium',
          notes: payload.notes,
          attestationId: payload.attestationId,
          feeTxid: payload.paymentTxid || payload.feeTxid,
        });
      }
    }

    return history.sort((a, b) => a.performedAt - b.performedAt);
  }

  /**
   * Calculate ownership statistics
   */
  private calculateOwnershipStats(history: OwnershipRecord[]): {
    totalOwners: number;
    averageHoldDays: number;
    longestHoldDays: number;
    shortestHoldDays: number;
  } {
    const holdDays = history
      .map(r => r.holdDurationDays)
      .filter((d): d is number => d !== undefined && d > 0);

    return {
      totalOwners: history.length,
      averageHoldDays: holdDays.length > 0 ? Math.round(holdDays.reduce((a, b) => a + b, 0) / holdDays.length) : 0,
      longestHoldDays: holdDays.length > 0 ? Math.max(...holdDays) : 0,
      shortestHoldDays: holdDays.length > 0 ? Math.min(...holdDays) : 0,
    };
  }

  /**
   * Calculate price statistics
   */
  private calculatePriceStats(history: PriceRecord[]): {
    mintPrice?: number;
    lastSalePrice?: number;
    highestPrice?: number;
    lowestPrice?: number;
    averagePrice?: number;
    priceChange?: number;
  } {
    const sales = history.filter(p => p.type === 'sale');
    if (sales.length === 0) return {};

    const prices = sales.map(s => s.price);
    const firstPrice = prices[0];
    const lastPrice = prices[prices.length - 1];

    return {
      lastSalePrice: lastPrice,
      highestPrice: Math.max(...prices),
      lowestPrice: Math.min(...prices),
      averagePrice: Math.round(prices.reduce((a, b) => a + b, 0) / prices.length),
      priceChange: firstPrice > 0 ? Math.round(((lastPrice - firstPrice) / firstPrice) * 100) : undefined,
    };
  }

  /**
   * Detect risk indicators
   */
  private detectRiskIndicators(
    ownership: OwnershipRecord[],
    prices: PriceRecord[],
    authentications: AuthenticationRecord[]
  ): RiskIndicator[] {
    const indicators: RiskIndicator[] = [];
    const now = Date.now();

    // Check for rapid flipping (sold within 7 days of purchase)
    for (const record of ownership) {
      if (record.holdDurationDays !== undefined && record.holdDurationDays < 7 && record.soldPrice) {
        indicators.push({
          type: 'rapid_flip',
          severity: record.holdDurationDays < 1 ? 'high' : 'medium',
          description: `Item was sold ${record.holdDurationDays} days after purchase`,
          detectedAt: record.soldAt || now,
        });
      }
    }

    // Check for suspicious price changes
    const sales = prices.filter(p => p.type === 'sale');
    for (let i = 1; i < sales.length; i++) {
      const prevPrice = sales[i - 1].price;
      const currPrice = sales[i].price;
      const change = ((currPrice - prevPrice) / prevPrice) * 100;

      if (change > 200) {
        indicators.push({
          type: 'price_spike',
          severity: change > 500 ? 'high' : 'medium',
          description: `Price increased ${Math.round(change)}% between sales`,
          detectedAt: sales[i].timestamp,
        });
      }

      if (change < -50) {
        indicators.push({
          type: 'price_drop',
          severity: change < -80 ? 'high' : 'medium',
          description: `Price dropped ${Math.round(Math.abs(change))}% between sales`,
          detectedAt: sales[i].timestamp,
        });
      }
    }

    // Check for no authentication
    if (authentications.length === 0 && ownership.length > 1) {
      indicators.push({
        type: 'no_authentication',
        severity: 'medium',
        description: 'Item has been sold but never authenticated',
        detectedAt: now,
      });
    }

    // Check for failed authentication
    const failedAuth = authentications.find(a => a.isAuthentic === false);
    if (failedAuth) {
      indicators.push({
        type: 'failed_authentication',
        severity: 'high',
        description: 'An authenticator determined this item is NOT authentic',
        detectedAt: failedAuth.performedAt,
      });
    }

    return indicators;
  }

  /**
   * Calculate overall risk score
   */
  private calculateRiskScore(indicators: RiskIndicator[]): number {
    let score = 0;

    for (const indicator of indicators) {
      switch (indicator.severity) {
        case 'high':
          score += 30;
          break;
        case 'medium':
          score += 15;
          break;
        case 'low':
          score += 5;
          break;
      }
    }

    return Math.min(100, score);
  }

  /**
   * Build event timeline
   */
  private buildTimeline(events: Event[]): ProvenanceEvent[] {
    return events.map(event => {
      const payload = event.payload as any;
      return {
        type: payload.type,
        timestamp: payload.timestamp,
        description: this.getEventDescription(payload),
        details: payload,
      };
    }).sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Get human-readable event description
   */
  private getEventDescription(payload: any): string {
    switch (payload.type) {
      case EventType.ITEM_REGISTERED:
        return `Item registered by ${payload.issuerRole || 'user'}`;
      case EventType.OWNERSHIP_TRANSFERRED:
        return payload.price 
          ? `Sold for ${payload.price.toLocaleString()} sats`
          : 'Ownership transferred';
      case EventType.AUTHENTICATION_PERFORMED:
      case EventType.AUTHENTICATION_RESULT_RECORDED:
        return payload.isAuthentic === false
          ? '❌ Authentication FAILED - item deemed not authentic'
          : '✅ Authenticated as genuine';
      case EventType.VERIFICATION_REQUEST_CREATED:
        return 'Verification requested';
      case EventType.VERIFICATION_REQUEST_COMPLETED:
        return 'Verification completed';
      case EventType.SETTLEMENT_INITIATED:
        return `Listed for sale at ${payload.price?.toLocaleString()} sats`;
      case EventType.SETTLEMENT_COMPLETED:
        return 'Sale completed';
      default:
        return payload.type;
    }
  }

  /**
   * Get market statistics for a manufacturer/category
   */
  async getMarketStats(manufacturerName: string, category?: string): Promise<MarketStats> {
    const allEvents = await this.eventStore.getAllEvents();
    
    // Find all items from this manufacturer
    const itemIds = new Set<string>();
    const sales: PriceRecord[] = [];
    
    for (const event of allEvents) {
      const payload = event.payload as any;
      
      if (payload.type === EventType.ITEM_REGISTERED) {
        const mfgName = (payload.manufacturerName || payload.manufacturerId || '').toLowerCase();
        const itemCategory = payload.metadata?.category?.toLowerCase();
        
        if (mfgName.includes(manufacturerName.toLowerCase())) {
          if (!category || itemCategory === category.toLowerCase()) {
            itemIds.add(payload.itemId);
          }
        }
      }
      
      if (payload.type === EventType.OWNERSHIP_TRANSFERRED && payload.price) {
        if (itemIds.has(payload.itemId)) {
          sales.push({
            price: payload.price,
            timestamp: payload.timestamp,
            type: 'sale',
            from: payload.fromOwner,
            to: payload.toOwner,
          });
        }
      }
    }

    const prices = sales.map(s => s.price).sort((a, b) => a - b);
    const now = Date.now();
    const thirtyDaysAgo = now - (30 * 24 * 60 * 60 * 1000);
    const recentSales = sales.filter(s => s.timestamp > thirtyDaysAgo);

    return {
      manufacturerName,
      category,
      totalItems: itemIds.size,
      totalSales: sales.length,
      averagePrice: prices.length > 0 ? Math.round(prices.reduce((a, b) => a + b, 0) / prices.length) : 0,
      medianPrice: prices.length > 0 ? prices[Math.floor(prices.length / 2)] : 0,
      highestPrice: prices.length > 0 ? Math.max(...prices) : 0,
      lowestPrice: prices.length > 0 ? Math.min(...prices) : 0,
      priceRange: { min: prices[0] || 0, max: prices[prices.length - 1] || 0 },
      recentSales: recentSales.slice(-10),
      priceHistory30Days: recentSales,
      volumeLast30Days: recentSales.reduce((sum, s) => sum + s.price, 0),
    };
  }
}
