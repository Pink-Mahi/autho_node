/**
 * Event Validator
 * 
 * Validates events against the current state to ensure they don't conflict.
 * This is the core of the consensus mechanism - all nodes must agree on
 * which events are valid given the current state.
 */

import { MempoolEvent, ValidationResult } from './types';

export interface StateProvider {
  getAccount(accountId: string): any | undefined;
  getItem(itemId: string): any | undefined;
  getOffer(offerId: string): any | undefined;
  getOperator(operatorId: string): any | undefined;
  getOperatorCandidate(candidateId: string): any | undefined;
  getConsignment(consignmentId: string): any | undefined;
  getSettlement(settlementId: string): any | undefined;
  hasAccountWithAddress(btcAddress: string): boolean;
  hasAccountWithEmail(email: string): boolean;
  getActiveOperators(): any[];
}

export type ValidationRule = (
  event: MempoolEvent,
  state: StateProvider
) => ValidationResult;

export class EventValidator {
  private rules: Map<string, ValidationRule> = new Map();
  private stateProvider: StateProvider;

  constructor(stateProvider: StateProvider) {
    this.stateProvider = stateProvider;
    this.registerDefaultRules();
  }

  /**
   * Register a validation rule for an event type
   */
  registerRule(eventType: string, rule: ValidationRule): void {
    this.rules.set(eventType, rule);
  }

  /**
   * Validate an event against current state
   */
  validate(event: MempoolEvent): ValidationResult {
    // Check if we have a rule for this event type
    const rule = this.rules.get(event.type);
    if (!rule) {
      // No specific rule - allow by default (but log warning)
      console.warn(`[Validator] No validation rule for event type: ${event.type}`);
      return { valid: true };
    }

    try {
      return rule(event, this.stateProvider);
    } catch (error: any) {
      return {
        valid: false,
        error: `Validation error: ${error.message}`,
      };
    }
  }

  /**
   * Validate multiple events in order
   * Returns results for each event
   */
  validateBatch(events: MempoolEvent[]): Map<string, ValidationResult> {
    const results = new Map<string, ValidationResult>();
    for (const event of events) {
      results.set(event.eventId, this.validate(event));
    }
    return results;
  }

  /**
   * Register default validation rules for all event types
   */
  private registerDefaultRules(): void {
    // Account creation
    this.registerRule('ACCOUNT_CREATED', (event, state) => {
      const { accountId, btcAddress, email } = event.payload;
      
      // Check if account already exists
      if (state.getAccount(accountId)) {
        return { valid: false, error: 'Account ID already exists' };
      }
      
      // Check if BTC address already used
      if (btcAddress && state.hasAccountWithAddress(btcAddress)) {
        return { valid: false, error: 'BTC address already registered' };
      }
      
      // Check if email already used
      if (email && state.hasAccountWithEmail(email)) {
        return { valid: false, error: 'Email already registered' };
      }
      
      return { valid: true };
    });

    // Item minting
    this.registerRule('ITEM_MINTED', (event, state) => {
      const { itemId, manufacturerId } = event.payload;
      
      // Check if item already exists
      if (state.getItem(itemId)) {
        return { valid: false, error: 'Item ID already exists' };
      }
      
      // Check if manufacturer is approved
      const manufacturer = state.getAccount(manufacturerId);
      if (!manufacturer) {
        return { valid: false, error: 'Manufacturer account not found' };
      }
      if (manufacturer.role !== 'manufacturer' || manufacturer.status !== 'active') {
        return { valid: false, error: 'Account is not an approved manufacturer' };
      }
      
      return { valid: true };
    });

    // Title update (ownership transfer)
    this.registerRule('TITLE_UPDATED', (event, state) => {
      const { itemId, fromOwner, toOwner, signerId } = event.payload;
      
      const item = state.getItem(itemId);
      if (!item) {
        return { valid: false, error: 'Item not found' };
      }
      
      // Verify current owner
      if (item.currentOwner !== fromOwner) {
        return { valid: false, error: 'From owner does not match current owner' };
      }
      
      // Verify signer is the owner
      if (signerId !== fromOwner) {
        return { valid: false, error: 'Signer is not the current owner' };
      }
      
      // Verify new owner exists
      if (!state.getAccount(toOwner)) {
        return { valid: false, error: 'New owner account not found' };
      }
      
      return { valid: true };
    });

    // Offer created
    this.registerRule('OFFER_CREATED', (event, state) => {
      const { offerId, itemId, buyerId } = event.payload;
      
      // Check if offer already exists
      if (state.getOffer(offerId)) {
        return { valid: false, error: 'Offer ID already exists' };
      }
      
      // Check if item exists
      const item = state.getItem(itemId);
      if (!item) {
        return { valid: false, error: 'Item not found' };
      }
      
      // Check if buyer exists
      if (!state.getAccount(buyerId)) {
        return { valid: false, error: 'Buyer account not found' };
      }
      
      return { valid: true };
    });

    // Offer accepted
    this.registerRule('OFFER_ACCEPTED', (event, state) => {
      const { offerId, sellerId } = event.payload;
      
      const offer = state.getOffer(offerId);
      if (!offer) {
        return { valid: false, error: 'Offer not found' };
      }
      
      if (offer.status !== 'pending') {
        return { valid: false, error: 'Offer is not pending' };
      }
      
      // Verify seller owns the item
      const item = state.getItem(offer.itemId);
      if (!item) {
        return { valid: false, error: 'Item not found' };
      }
      
      if (item.currentOwner !== sellerId) {
        return { valid: false, error: 'Seller does not own the item' };
      }
      
      return { valid: true };
    });

    // Payment confirmed
    this.registerRule('PAYMENT_CONFIRMED', (event, state) => {
      const { offerId, txid, amount } = event.payload;
      
      const offer = state.getOffer(offerId);
      if (!offer) {
        return { valid: false, error: 'Offer not found' };
      }
      
      if (offer.status !== 'accepted') {
        return { valid: false, error: 'Offer has not been accepted' };
      }
      
      // Note: Bitcoin transaction verification would happen here
      // All nodes can independently verify the BTC transaction
      if (!txid) {
        return { valid: false, error: 'Missing Bitcoin transaction ID' };
      }
      
      return { valid: true };
    });

    // Consignment created
    this.registerRule('CONSIGNMENT_CREATED', (event, state) => {
      const { consignmentId, itemId, consignorId } = event.payload;
      
      if (state.getConsignment(consignmentId)) {
        return { valid: false, error: 'Consignment ID already exists' };
      }
      
      const item = state.getItem(itemId);
      if (!item) {
        return { valid: false, error: 'Item not found' };
      }
      
      if (item.currentOwner !== consignorId) {
        return { valid: false, error: 'Consignor does not own the item' };
      }
      
      return { valid: true };
    });

    // Operator candidate requested
    this.registerRule('OPERATOR_CANDIDATE_REQUESTED', (event, state) => {
      const { candidateId, sponsorId } = event.payload;
      
      // Check if candidate already exists
      if (state.getOperatorCandidate(candidateId)) {
        return { valid: false, error: 'Operator candidate already exists' };
      }
      
      // Check if already an operator
      if (state.getOperator(candidateId)) {
        return { valid: false, error: 'Already an operator' };
      }
      
      // Check sponsor exists
      if (sponsorId && !state.getAccount(sponsorId)) {
        return { valid: false, error: 'Sponsor account not found' };
      }
      
      return { valid: true };
    });

    // Operator vote cast
    this.registerRule('OPERATOR_VOTE_CAST', (event, state) => {
      const { candidateId, voterId, vote } = event.payload;
      
      // Check candidate exists
      const candidate = state.getOperatorCandidate(candidateId);
      if (!candidate) {
        return { valid: false, error: 'Operator candidate not found' };
      }
      
      // Check voter is an active operator
      const voter = state.getOperator(voterId);
      if (!voter || voter.status !== 'active') {
        return { valid: false, error: 'Voter is not an active operator' };
      }
      
      // Check vote is valid
      if (vote !== 'yes' && vote !== 'no') {
        return { valid: false, error: 'Invalid vote value' };
      }
      
      return { valid: true };
    });

    // Operator admitted
    this.registerRule('OPERATOR_ADMITTED', (event, state) => {
      const { candidateId } = event.payload;
      
      const candidate = state.getOperatorCandidate(candidateId);
      if (!candidate) {
        return { valid: false, error: 'Operator candidate not found' };
      }
      
      // Check if already an operator
      if (state.getOperator(candidateId)) {
        return { valid: false, error: 'Already an operator' };
      }
      
      // Verify 2/3 majority (this would check the vote counts)
      const activeOperators = state.getActiveOperators();
      const requiredVotes = Math.ceil((2 / 3) * activeOperators.length);
      
      // Note: Vote counting would be done by checking vote events
      // For now, we trust the event creator verified this
      
      return { valid: true };
    });

    // Settlement created
    this.registerRule('SETTLEMENT_CREATED', (event, state) => {
      const { settlementId, itemId } = event.payload;
      
      if (state.getSettlement(settlementId)) {
        return { valid: false, error: 'Settlement ID already exists' };
      }
      
      if (!state.getItem(itemId)) {
        return { valid: false, error: 'Item not found' };
      }
      
      return { valid: true };
    });

    // Settlement completed
    this.registerRule('SETTLEMENT_COMPLETED', (event, state) => {
      const { settlementId } = event.payload;
      
      const settlement = state.getSettlement(settlementId);
      if (!settlement) {
        return { valid: false, error: 'Settlement not found' };
      }
      
      if (settlement.status === 'completed') {
        return { valid: false, error: 'Settlement already completed' };
      }
      
      return { valid: true };
    });
  }

  /**
   * Update the state provider (e.g., after checkpoint finalization)
   */
  updateStateProvider(stateProvider: StateProvider): void {
    this.stateProvider = stateProvider;
  }
}
