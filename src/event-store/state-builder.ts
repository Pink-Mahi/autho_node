/**
 * State Builder
 * 
 * Builds the current registry state by replaying all events from the event store.
 * This allows any node to reconstruct the full state from the event log.
 */

import { EventStore } from './event-store';
import { Event, EventType, PlatformFeePayoutSnapshot } from './types';

export interface ItemState {
  itemId: string;
  manufacturerId: string;
  issuerRole?: 'manufacturer' | 'authenticator' | 'user';
  issuerAccountId?: string;
  serialNumberHash: string;
  serialNumberDisplay?: string;
  metadataHash: string;
  currentOwner: string;
  metadata: any;
  registeredAt: number;
  feeTxid?: string;
  feeBlockHeight?: number;
  feeCommitmentHex?: string;
  lastTransferAt?: number;
  transferCount: number;
  authentications: Array<{
    attestationId?: string;
    authenticatorId: string;
    performedAt?: number;
    recordedAt?: number;
    isAuthentic?: boolean;
    confidence?: 'high' | 'medium' | 'low';
    notes?: string;
    images?: any[];
    attestationHash?: string;
    feeTxid?: string;
    feeBlockHeight?: number;
    feeCommitmentHex?: string;
  }>;
}

export interface SettlementState {
  settlementId: string;
  itemId: string;
  seller: string;
  buyer: string;
  price: number;
  status: 'initiated' | 'completed' | 'failed';
  escrowAddress?: string;
  expiresAt?: number;
  txid?: string;
  platformFee?: number;
  operatorFees?: { [operatorId: string]: number };
  platformFeePayouts?: PlatformFeePayoutSnapshot;
  initiatedAt: number;
  acceptedAt?: number;
  completedAt?: number;
}

export interface ConsignmentState {
  consignmentId: string;
  itemId: string;
  ownerAccountId: string;
  ownerWallet: string;
  retailerAccountId: string;
  retailerWallet: string;
  buyerAccountId?: string;
  buyerWallet?: string;
  sellerMinNetSats: number;
  askingPriceSats: number;
  retailerMarkupShareBps: number;
  platformFeeSats: number;
  retailerCommissionSats: number;
  sellerPayoutSats: number;
  platformFeePayouts?: PlatformFeePayoutSnapshot;
  status: 'pending' | 'active' | 'cancelled' | 'expired' | 'completed';
  createdByAccountId: string;
  createdAt: number;
  expiresAt: number;
  ownerConfirmedAt?: number;
  retailerConfirmedAt?: number;
  checkoutLock?: { lockedByAccountId: string; lockedUntil: number };
  cancelRequested?: { requestedByAccountId: string; requestedAt: number; reason?: string };
  cancelConfirmed?: { confirmedByAccountId: string; confirmedAt: number; reason?: string };
  settlementId?: string;
  txid?: string;
  updatedAt: number;
}

export interface VerificationRequestState {
  requestId: string;
  itemId: string;
  ownerWallet: string;
  authenticatorId: string;
  authenticatorWallet: string;
  serviceFeeSats: number;
  maxServiceFeeSats?: number;
  platformFeeSats: number;
  commitmentHex: string;
  status: 'open' | 'accepted' | 'completed' | 'cancelled';
  requestedAt: number;
  acceptedAt?: number;
  completedAt?: number;
  cancelledAt?: number;
  paymentTxid?: string;
  blockHeight?: number;
  attestationId?: string;
  expiresAt?: number;
  cancelReason?: string;
}

export interface OperatorState {
  operatorId: string;
  btcAddress: string;
  publicKey: string;
  operatorUrl?: string;
  sponsorId?: string;
  status: 'candidate' | 'active' | 'removed';
  admittedAt?: number;
  lastActiveAt?: number;
  lastHeartbeatAt?: number;
  candidateRequestedAt?: number;
  eligibleVoterIds?: string[];
  eligibleVoterCount?: number;
  requiredYesVotes?: number;
  eligibleVotingAt?: number;
  votes?: Map<string, { voterId: string; vote: 'approve' | 'reject'; reason?: string; votedAt: number }>;
  voteCount?: { approve: number; reject: number };
}

export interface AccountState {
  accountId: string;
  role: string;
  username?: string;
  companyName?: string;
  displayName?: string;
  website?: string;
  phone?: string;
  address?: string;
  contactEmail?: string;
  notes?: string;
  bondAddress?: string;
  bondMinSats?: number;
  bondConfirmedSats?: number;
  bondUtxoCount?: number;
  bondMeetsMin?: boolean;
  bondLastCheckedAt?: number;
  retailerStatus?: 'unverified' | 'verified' | 'blocked';
  retailerVerifiedAt?: number;
  retailerVerificationRevokedAt?: number;
  retailerBlockedAt?: number;
  retailerUnblockedAt?: number;
  retailerBondAddress?: string;
  retailerBondMinSats?: number;
  retailerBondConfirmedSats?: number;
  retailerBondUtxoCount?: number;
  retailerBondMeetsMin?: boolean;
  retailerBondLastCheckedAt?: number;
  retailerRatingCount?: number;
  retailerRatingSum?: number;
  retailerRatingAvg?: number;
  retailerReportCount?: number;
  ratingCount?: number;
  ratingSum?: number;
  ratingAvg?: number;
  reportCount?: number;
  email?: string;
  emailHash?: string;
  walletAddress?: string;
  passwordHash?: string;
  passwordKdf?: { saltB64?: string; iterations?: number; hash?: string };
  walletVault?: any;
  pake?: { suiteId: string; recordB64: string };
  totp?: { enabled: boolean; encScheme?: string; totpSecretEncB64?: string; secretEncB64?: string };
  verifierStatus?: 'active' | 'revoked';
  verifierRevokedAt?: number;
  verifierReactivatedAt?: number;
  verifierFrozen?: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface VerifierRatingState {
  key: string;
  targetAccountId: string;
  raterAccountId: string;
  contextType: 'issuer_item' | 'authenticated_item' | 'verification_request';
  contextId: string;
  rating: number;
  feeTxid?: string;
  feePaidSats?: number;
  feeBlockHeight?: number;
  feeConfirmations?: number;
  createdAt: number;
}

export interface VerifierReportState {
  key: string;
  targetAccountId: string;
  reporterAccountId: string;
  contextType: 'issuer_item' | 'authenticated_item' | 'verification_request';
  contextId: string;
  reasonCode?: string;
  details?: string;
  createdAt: number;
}

export interface VerifierRatingFeeTxState {
  txid: string;
  usedByKey: string;
  usedAt: number;
  paidSats?: number;
  blockHeight?: number;
  confirmations?: number;
}

export interface AccountRoleApplicationState {
  applicationId: string;
  accountId: string;
  requestedRole: 'manufacturer' | 'authenticator';
  companyName?: string;
  contactEmail?: string;
  website?: string;
  notes?: string;
  submittedAt: number;
  reviewed?: { reviewerOperatorId: string; decision: 'approve' | 'reject'; reason?: string; reviewedAt: number };
  votes: Map<string, { voterOperatorId: string; vote: 'approve' | 'reject'; reason?: string; votedAt: number }>;
  finalized?: {
    finalizedByOperatorId: string;
    decision: 'approve' | 'reject';
    reason?: string;
    finalizedAt: number;
    activeOperatorCount: number;
    approveVotes: number;
    rejectVotes: number;
  };
}

export interface AccountRoleInviteState {
  inviteId: string;
  role: 'manufacturer' | 'authenticator';
  codeHashHex: string;
  expiresAt: number;
  createdAt: number;
  createdByOperatorId: string;
  redeemedAt?: number;
  redeemedByAccountId?: string;
}

export interface RetailerVerificationApplicationState {
  applicationId: string;
  accountId: string;
  companyName?: string;
  contactEmail?: string;
  website?: string;
  notes?: string;
  submittedAt: number;
  reviewed?: { reviewerOperatorId: string; decision: 'approve' | 'reject'; reason?: string; reviewedAt: number };
  votes: Map<string, { voterOperatorId: string; vote: 'approve' | 'reject'; reason?: string; votedAt: number }>;
  finalized?: {
    finalizedByOperatorId: string;
    decision: 'approve' | 'reject';
    reason?: string;
    finalizedAt: number;
    activeOperatorCount: number;
    approveVotes: number;
    rejectVotes: number;
  };
}

export interface AccountRetailerActionState {
  actionId: string;
  targetAccountId: string;
  action: 'block' | 'unblock';
  requestedByOperatorId: string;
  reason?: string;
  createdAt: number;
  votes: Map<string, { voterOperatorId: string; vote: 'approve' | 'reject'; reason?: string; votedAt: number }>;
  finalized?: {
    finalizedByOperatorId: string;
    decision: 'approve' | 'reject';
    reason?: string;
    finalizedAt: number;
    activeOperatorCount: number;
    approveVotes: number;
    rejectVotes: number;
    quorumThreshold: number;
  };
}

export interface RetailerRatingState {
  key: string;
  targetAccountId: string;
  raterAccountId: string;
  contextType: 'retailer_profile' | 'consignment';
  contextId: string;
  rating: number;
  createdAt: number;
}

export interface RetailerReportState {
  key: string;
  targetAccountId: string;
  reporterAccountId: string;
  contextType: 'retailer_profile' | 'consignment';
  contextId: string;
  reasonCode?: string;
  details?: string;
  createdAt: number;
}

export interface AccountVerifierActionState {
  actionId: string;
  targetAccountId: string;
  action: 'revoke' | 'reactivate';
  requestedByOperatorId: string;
  reason?: string;
  createdAt: number;
  votes: Map<string, { voterOperatorId: string; vote: 'approve' | 'reject'; reason?: string; votedAt: number }>;
  finalized?: {
    finalizedByOperatorId: string;
    decision: 'approve' | 'reject';
    reason?: string;
    finalizedAt: number;
    activeOperatorCount: number;
    approveVotes: number;
    rejectVotes: number;
    quorumThreshold: number;
  };
}

export interface RegistryState {
  items: Map<string, ItemState>;
  settlements: Map<string, SettlementState>;
  consignments: Map<string, ConsignmentState>;
  verificationRequests: Map<string, VerificationRequestState>;
  operators: Map<string, OperatorState>;
  accounts: Map<string, AccountState>;
  roleApplications: Map<string, AccountRoleApplicationState>;
  roleInvites: Map<string, AccountRoleInviteState>;
  verifierActions: Map<string, AccountVerifierActionState>;
  verifierRatings: Map<string, VerifierRatingState>;
  verifierReports: Map<string, VerifierReportState>;
  verifierRatingFeeTxids: Map<string, VerifierRatingFeeTxState>;
  retailerVerificationApplications: Map<string, RetailerVerificationApplicationState>;
  retailerActions: Map<string, AccountRetailerActionState>;
  retailerRatings: Map<string, RetailerRatingState>;
  retailerReports: Map<string, RetailerReportState>;
  ownership: Map<string, string>; // itemId -> owner address
  feePayoutCursor: number;
  lastEventSequence: number;
  lastEventHash: string;
}

export class StateBuilder {
  public eventStore: EventStore;

  constructor(eventStore: EventStore) {
    this.eventStore = eventStore;
  }

  /**
   * Build current state by replaying all events
   */
  async buildState(): Promise<RegistryState> {
    const state: RegistryState = {
      items: new Map(),
      settlements: new Map(),
      consignments: new Map(),
      verificationRequests: new Map(),
      operators: new Map(),
      accounts: new Map(),
      roleApplications: new Map(),
      roleInvites: new Map(),
      verifierActions: new Map(),
      verifierRatings: new Map(),
      verifierReports: new Map(),
      verifierRatingFeeTxids: new Map(),
      retailerVerificationApplications: new Map(),
      retailerActions: new Map(),
      retailerRatings: new Map(),
      retailerReports: new Map(),
      ownership: new Map(),
      feePayoutCursor: 0,
      lastEventSequence: 0,
      lastEventHash: '',
    };

    const events = await this.eventStore.getAllEvents();

    for (const event of events) {
      this.applyEvent(state, event);
    }

    return state;
  }

  /**
   * Apply a single event to the state
   */
  private applyEvent(state: RegistryState, event: Event): void {
    const { payload } = event;

    switch (payload.type) {
      case EventType.ITEM_REGISTERED:
        this.applyItemRegistered(state, event);
        break;

      case EventType.OWNERSHIP_TRANSFERRED:
        this.applyOwnershipTransferred(state, event);
        break;

      case EventType.AUTHENTICATION_PERFORMED:
        this.applyAuthenticationPerformed(state, event);
        break;

      case EventType.AUTHENTICATION_RESULT_RECORDED:
        this.applyAuthenticationResultRecorded(state, event);
        break;

      case EventType.VERIFICATION_REQUEST_CREATED:
        this.applyVerificationRequestCreated(state, event);
        break;

      case EventType.VERIFICATION_REQUEST_ACCEPTED:
        this.applyVerificationRequestAccepted(state, event);
        break;

      case EventType.VERIFICATION_REQUEST_COMPLETED:
        this.applyVerificationRequestCompleted(state, event);
        break;

      case EventType.VERIFICATION_REQUEST_CANCELLED:
        this.applyVerificationRequestCancelled(state, event);
        break;

      case EventType.SETTLEMENT_INITIATED:
        this.applySettlementInitiated(state, event);
        break;

      case EventType.SETTLEMENT_CLAIMED:
        this.applySettlementClaimed(state, event);
        break;

      case EventType.SETTLEMENT_ACCEPTED:
        this.applySettlementAccepted(state, event);
        break;

      case EventType.SETTLEMENT_PAYMENT_SUBMITTED:
        this.applySettlementPaymentSubmitted(state, event);
        break;

      case EventType.SETTLEMENT_COMPLETED:
        this.applySettlementCompleted(state, event);
        break;

      case EventType.SETTLEMENT_FAILED:
        this.applySettlementFailed(state, event);
        break;

      case EventType.CONSIGNMENT_CREATED:
        this.applyConsignmentCreated(state, event);
        break;

      case EventType.CONSIGNMENT_OWNER_CONFIRMED:
        this.applyConsignmentOwnerConfirmed(state, event);
        break;

      case EventType.CONSIGNMENT_RETAILER_CONFIRMED:
        this.applyConsignmentRetailerConfirmed(state, event);
        break;

      case EventType.CONSIGNMENT_PRICE_UPDATED:
        this.applyConsignmentPriceUpdated(state, event);
        break;

      case EventType.CONSIGNMENT_CHECKOUT_LOCKED:
        this.applyConsignmentCheckoutLocked(state, event);
        break;

      case EventType.CONSIGNMENT_PAYMENT_SUBMITTED:
        this.applyConsignmentPaymentSubmitted(state, event);
        break;

      case EventType.CONSIGNMENT_CANCEL_REQUESTED:
        this.applyConsignmentCancelRequested(state, event);
        break;

      case EventType.CONSIGNMENT_CANCEL_CONFIRMED:
        this.applyConsignmentCancelConfirmed(state, event);
        break;

      case EventType.CONSIGNMENT_EXPIRED:
        this.applyConsignmentExpired(state, event);
        break;

      case EventType.CONSIGNMENT_COMPLETED:
        this.applyConsignmentCompleted(state, event);
        break;

      case EventType.OPERATOR_CANDIDATE_REQUESTED:
        this.applyOperatorCandidateRequested(state, event);
        break;

      case EventType.OPERATOR_CANDIDATE_VOTE:
        this.applyOperatorCandidateVote(state, event);
        break;

      case EventType.OPERATOR_ADMITTED:
        this.applyOperatorAdmitted(state, event);
        break;

      case EventType.OPERATOR_REJECTED:
        this.applyOperatorRejected(state, event);
        break;

      case EventType.OPERATOR_REMOVED:
        this.applyOperatorRemoved(state, event);
        break;

      case EventType.OPERATOR_HEARTBEAT:
        this.applyOperatorHeartbeat(state, event);
        break;

      case EventType.ACCOUNT_CREATED:
        this.applyAccountCreated(state, event);
        break;

      case EventType.ACCOUNT_ROLE_SET:
        this.applyAccountRoleSet(state, event);
        break;

      case EventType.ACCOUNT_EMAIL_SET:
        this.applyAccountEmailSet(state, event);
        break;

      case EventType.ACCOUNT_ROLE_APPLICATION_SUBMITTED:
        this.applyAccountRoleApplicationSubmitted(state, event);
        break;

      case EventType.ACCOUNT_ROLE_APPLICATION_REVIEWED:
        this.applyAccountRoleApplicationReviewed(state, event);
        break;

      case EventType.ACCOUNT_ROLE_APPLICATION_VOTED:
        this.applyAccountRoleApplicationVoted(state, event);
        break;

      case EventType.ACCOUNT_ROLE_APPLICATION_FINALIZED:
        this.applyAccountRoleApplicationFinalized(state, event);
        break;

      case EventType.ACCOUNT_ROLE_INVITE_CREATED:
        this.applyAccountRoleInviteCreated(state, event);
        break;

      case EventType.ACCOUNT_ROLE_INVITE_REDEEMED:
        this.applyAccountRoleInviteRedeemed(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_ACTION_CREATED:
        this.applyAccountVerifierActionCreated(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_ACTION_VOTED:
        this.applyAccountVerifierActionVoted(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_ACTION_FINALIZED:
        this.applyAccountVerifierActionFinalized(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_PROFILE_UPDATED:
        this.applyAccountVerifierProfileUpdated(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_BOND_PROOF_RECORDED:
        this.applyAccountVerifierBondProofRecorded(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_RATED:
        this.applyAccountVerifierRated(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_REPORTED:
        this.applyAccountVerifierReported(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_REVOKED:
        this.applyAccountVerifierRevoked(state, event);
        break;

      case EventType.ACCOUNT_VERIFIER_REACTIVATED:
        this.applyAccountVerifierReactivated(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_ACTION_CREATED:
        this.applyAccountRetailerActionCreated(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_ACTION_VOTED:
        this.applyAccountRetailerActionVoted(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_ACTION_FINALIZED:
        this.applyAccountRetailerActionFinalized(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_BLOCKED:
        this.applyAccountRetailerBlocked(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_UNBLOCKED:
        this.applyAccountRetailerUnblocked(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_PROFILE_UPDATED:
        this.applyAccountRetailerProfileUpdated(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_BOND_PROOF_RECORDED:
        this.applyAccountRetailerBondProofRecorded(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_RATED:
        this.applyAccountRetailerRated(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_REPORTED:
        this.applyAccountRetailerReported(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_SUBMITTED:
        this.applyAccountRetailerVerificationApplicationSubmitted(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_REVIEWED:
        this.applyAccountRetailerVerificationApplicationReviewed(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_VOTED:
        this.applyAccountRetailerVerificationApplicationVoted(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_FINALIZED:
        this.applyAccountRetailerVerificationApplicationFinalized(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_VERIFIED:
        this.applyAccountRetailerVerified(state, event);
        break;

      case EventType.ACCOUNT_RETAILER_VERIFICATION_REVOKED:
        this.applyAccountRetailerVerificationRevoked(state, event);
        break;

      case EventType.ACCOUNT_PAKE_RECORD_SET:
        this.applyAccountPakeRecordSet(state, event);
        break;

      case EventType.ACCOUNT_PASSWORD_SET:
        this.applyAccountPasswordSet(state, event);
        break;

      case EventType.ACCOUNT_TOTP_ENABLED:
        this.applyAccountTotpEnabled(state, event);
        break;

      case EventType.ACCOUNT_TOTP_DISABLED:
        this.applyAccountTotpDisabled(state, event);
        break;

      case EventType.ACCOUNT_RECOVERY_TOTP_RESET:
        this.applyAccountRecoveryTotpReset(state, event);
        break;
    }

    const eventTs = Number((payload as any)?.timestamp || (event as any)?.createdAt || 0);
    const sigs = Array.isArray((event as any)?.signatures) ? ((event as any).signatures as any[]) : [];
    for (const sig of sigs) {
      const signerId = String(sig?.operatorId || '').trim();
      if (!signerId) continue;
      const op = state.operators.get(signerId);
      if (!op) continue;
      const prev = Number((op as any).lastActiveAt || 0);
      if (eventTs > prev) {
        (op as any).lastActiveAt = eventTs;
      }
    }

    // Update last event tracking
    state.lastEventSequence = event.sequenceNumber;
    state.lastEventHash = event.eventHash;
  }

  private applyItemRegistered(state: RegistryState, event: Event): void {
    const payload = event.payload as any;

    const item: ItemState = {
      itemId: payload.itemId,
      manufacturerId: payload.manufacturerId,
      issuerRole: payload.issuerRole,
      issuerAccountId: payload.issuerAccountId,
      serialNumberHash: payload.serialNumberHash,
      serialNumberDisplay: payload.serialNumberDisplay,
      metadataHash: payload.metadataHash,
      currentOwner: payload.initialOwner,
      metadata: payload.metadata,
      registeredAt: payload.timestamp,
      feeTxid: payload.feeTxid,
      feeBlockHeight: payload.feeBlockHeight,
      feeCommitmentHex: payload.feeCommitmentHex,
      transferCount: 0,
      authentications: [],
    };

    state.items.set(item.itemId, item);
    state.ownership.set(item.itemId, item.currentOwner);
  }

  private applyOwnershipTransferred(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const item = state.items.get(payload.itemId);

    if (item) {
      item.currentOwner = payload.toOwner;
      item.lastTransferAt = payload.timestamp;
      item.transferCount++;

      state.ownership.set(payload.itemId, payload.toOwner);
    }
  }

  private applyConsignmentCreated(state: RegistryState, event: Event): void {
    const payload = event.payload as any;

    const consignment: ConsignmentState = {
      consignmentId: String(payload.consignmentId),
      itemId: String(payload.itemId),
      ownerAccountId: String(payload.ownerAccountId),
      ownerWallet: String(payload.ownerWallet),
      retailerAccountId: String(payload.retailerAccountId),
      retailerWallet: String(payload.retailerWallet),
      sellerMinNetSats: Number(payload.sellerMinNetSats || 0),
      askingPriceSats: Number(payload.askingPriceSats || 0),
      retailerMarkupShareBps: Number(payload.retailerMarkupShareBps || 0),
      platformFeeSats: Number(payload.platformFeeSats || 0),
      retailerCommissionSats: Number(payload.retailerCommissionSats || 0),
      sellerPayoutSats: Number(payload.sellerPayoutSats || 0),
      status: 'pending',
      createdByAccountId: String(payload.createdByAccountId || ''),
      createdAt: Number(payload.timestamp || 0),
      expiresAt: Number(payload.expiresAt || 0),
      updatedAt: Number(payload.timestamp || 0),
    };

    state.consignments.set(consignment.consignmentId, consignment);
  }

  private applyConsignmentOwnerConfirmed(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.ownerConfirmedAt = Number(payload.timestamp || 0);
    c.updatedAt = Number(payload.timestamp || 0);
    if (c.ownerConfirmedAt && c.retailerConfirmedAt) {
      c.status = 'active';
    }
  }

  private applyConsignmentRetailerConfirmed(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.retailerConfirmedAt = Number(payload.timestamp || 0);
    c.updatedAt = Number(payload.timestamp || 0);
    if (c.ownerConfirmedAt && c.retailerConfirmedAt) {
      c.status = 'active';
    }
  }

  private applyConsignmentPriceUpdated(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.askingPriceSats = Number(payload.askingPriceSats || 0);
    c.platformFeeSats = Number(payload.platformFeeSats || 0);
    c.retailerCommissionSats = Number(payload.retailerCommissionSats || 0);
    c.sellerPayoutSats = Number(payload.sellerPayoutSats || 0);
    c.updatedAt = Number(payload.timestamp || 0);
  }

  private applyConsignmentPaymentSubmitted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.buyerAccountId = payload.buyerAccountId ? String(payload.buyerAccountId) : undefined;
    c.buyerWallet = payload.buyerWallet ? String(payload.buyerWallet) : undefined;
    c.txid = payload.txid ? String(payload.txid) : undefined;
    c.updatedAt = Number(payload.timestamp || 0);
  }

  private applyConsignmentCheckoutLocked(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.checkoutLock = {
      lockedByAccountId: String(payload.lockedByAccountId || ''),
      lockedUntil: Number(payload.lockedUntil || 0),
    };

    if (payload.platformFeePayouts) {
      c.platformFeePayouts = payload.platformFeePayouts as PlatformFeePayoutSnapshot;
      state.feePayoutCursor = Number(state.feePayoutCursor || 0) + 1;
    }
    c.updatedAt = Number(payload.timestamp || 0);
  }

  private applyConsignmentCancelRequested(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.cancelRequested = {
      requestedByAccountId: String(payload.requestedByAccountId || ''),
      requestedAt: Number(payload.timestamp || 0),
      reason: payload.reason ? String(payload.reason) : undefined,
    };
    c.updatedAt = Number(payload.timestamp || 0);
  }

  private applyConsignmentCancelConfirmed(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.cancelConfirmed = {
      confirmedByAccountId: String(payload.confirmedByAccountId || ''),
      confirmedAt: Number(payload.timestamp || 0),
      reason: payload.reason ? String(payload.reason) : undefined,
    };
    c.status = 'cancelled';
    c.updatedAt = Number(payload.timestamp || 0);
  }

  private applyConsignmentExpired(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.status = 'expired';
    c.updatedAt = Number(payload.timestamp || 0);
  }

  private applyConsignmentCompleted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const c = state.consignments.get(String(payload.consignmentId));
    if (!c) return;

    c.status = 'completed';
    c.settlementId = payload.settlementId ? String(payload.settlementId) : c.settlementId;
    c.txid = payload.txid ? String(payload.txid) : c.txid;
    c.updatedAt = Number(payload.timestamp || 0);
  }

  private applyAuthenticationPerformed(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const item = state.items.get(payload.itemId);
    if (!item) return;

    const attestationId = String(payload.attestationId || '').trim();
    const authenticatorId = String(payload.authenticatorId || '').trim();
    if (!authenticatorId) return;

    const existing = item.authentications.find((a) => {
      if (attestationId) return String(a.attestationId || '') === attestationId;
      return String(a.authenticatorId || '') === authenticatorId;
    });

    if (existing) {
      existing.attestationId = existing.attestationId || (attestationId || undefined);
      existing.authenticatorId = authenticatorId;
      existing.performedAt = payload.timestamp;
      return;
    }

    item.authentications.push({
      attestationId: attestationId || undefined,
      authenticatorId,
      performedAt: payload.timestamp,
    });
  }

  private applyAuthenticationResultRecorded(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const item = state.items.get(payload.itemId);
    if (!item) return;

    const attestationId = String(payload.attestationId || '').trim();
    const authenticatorId = String(payload.authenticatorId || '').trim();
    if (!authenticatorId) return;

    let entry = item.authentications.find((a) => {
      if (attestationId) return String(a.attestationId || '') === attestationId;
      return String(a.authenticatorId || '') === authenticatorId;
    });

    if (!entry) {
      entry = {
        attestationId: attestationId || undefined,
        authenticatorId,
        performedAt: undefined,
        recordedAt: undefined,
        isAuthentic: undefined,
        confidence: undefined,
        notes: undefined,
        images: undefined,
        attestationHash: undefined,
        feeTxid: undefined,
        feeBlockHeight: undefined,
        feeCommitmentHex: undefined,
      };
      item.authentications.push(entry);
    }

    entry.attestationId = entry.attestationId || (attestationId || undefined);
    entry.authenticatorId = authenticatorId;
    entry.recordedAt = payload.timestamp;
    entry.isAuthentic = Boolean(payload.isAuthentic);
    entry.confidence = payload.confidence;
    entry.notes = payload.notes;
    entry.images = payload.images;
    entry.attestationHash = payload.attestationHash;
    entry.feeTxid = payload.feeTxid;
    entry.feeBlockHeight = payload.feeBlockHeight;
    entry.feeCommitmentHex = payload.feeCommitmentHex;
  }

  private applyVerificationRequestCreated(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const requestId = String(payload.requestId || '').trim();
    if (!requestId) return;

    state.verificationRequests.set(requestId, {
      requestId,
      itemId: String(payload.itemId || '').trim(),
      ownerWallet: String(payload.ownerWallet || '').trim(),
      authenticatorId: String(payload.authenticatorId || '').trim(),
      authenticatorWallet: String(payload.authenticatorWallet || '').trim(),
      serviceFeeSats: Number(payload.serviceFeeSats || 0),
      maxServiceFeeSats: payload.maxServiceFeeSats !== undefined ? Number(payload.maxServiceFeeSats) : undefined,
      platformFeeSats: Number(payload.platformFeeSats || 0),
      commitmentHex: String(payload.commitmentHex || '').trim(),
      status: 'open',
      requestedAt: Number(payload.timestamp || 0),
      expiresAt: payload.expiresAt ? Number(payload.expiresAt) : undefined,
    });
  }

  private applyVerificationRequestAccepted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const req = state.verificationRequests.get(String(payload.requestId || '').trim());
    if (!req) return;
    req.status = 'accepted';
    if (payload.serviceFeeSats !== undefined) req.serviceFeeSats = Number(payload.serviceFeeSats || 0);
    if (payload.platformFeeSats !== undefined) req.platformFeeSats = Number(payload.platformFeeSats || 0);
    req.acceptedAt = Number(payload.acceptedAt || payload.timestamp || 0) || undefined;
  }

  private applyVerificationRequestCompleted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const req = state.verificationRequests.get(String(payload.requestId || '').trim());
    if (!req) return;
    req.status = 'completed';
    req.completedAt = Number(payload.completedAt || payload.timestamp || 0) || undefined;
    req.paymentTxid = String(payload.paymentTxid || '').trim() || undefined;
    req.blockHeight = payload.blockHeight ? Number(payload.blockHeight) : undefined;
    req.attestationId = String(payload.attestationId || '').trim() || undefined;
  }

  private applyVerificationRequestCancelled(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const req = state.verificationRequests.get(String(payload.requestId || '').trim());
    if (!req) return;
    req.status = 'cancelled';
    req.cancelledAt = Number(payload.cancelledAt || payload.timestamp || 0) || undefined;
    req.cancelReason = String(payload.reason || '').trim() || undefined;
  }

  private applySettlementInitiated(state: RegistryState, event: Event): void {
    const payload = event.payload as any;

    const settlement: SettlementState = {
      settlementId: payload.settlementId,
      itemId: payload.itemId,
      seller: payload.seller,
      buyer: payload.buyer,
      price: payload.price,
      status: 'initiated',
      escrowAddress: payload.escrowAddress,
      expiresAt: payload.expiresAt,
      initiatedAt: payload.timestamp,
    };

    state.settlements.set(settlement.settlementId, settlement);
  }

  private applySettlementClaimed(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const settlement = state.settlements.get(payload.settlementId);

    if (settlement) {
      settlement.buyer = payload.buyer;
      settlement.acceptedAt = payload.acceptedAt;

      if (payload.platformFeePayouts) {
        settlement.platformFeePayouts = payload.platformFeePayouts as PlatformFeePayoutSnapshot;
        state.feePayoutCursor = Number(state.feePayoutCursor || 0) + 1;
      }
    }
  }

  private applySettlementAccepted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const settlement = state.settlements.get(payload.settlementId);

    if (settlement) {
      settlement.acceptedAt = payload.acceptedAt;

      if (payload.platformFeePayouts) {
        settlement.platformFeePayouts = payload.platformFeePayouts as PlatformFeePayoutSnapshot;
        state.feePayoutCursor = Number(state.feePayoutCursor || 0) + 1;
      }
    }
  }

  private applySettlementPaymentSubmitted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const settlement = state.settlements.get(payload.settlementId);

    if (settlement) {
      settlement.txid = payload.txid;
    }
  }

  private applySettlementCompleted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const settlement = state.settlements.get(payload.settlementId);

    if (settlement) {
      settlement.status = 'completed';
      settlement.txid = payload.txid;
      settlement.platformFee = payload.platformFee;
      settlement.operatorFees = payload.operatorFees;
      settlement.completedAt = payload.timestamp;
    }
  }

  private applySettlementFailed(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const settlement = state.settlements.get(payload.settlementId);

    if (settlement) {
      settlement.status = 'failed';
      settlement.completedAt = payload.timestamp;
    }
  }

  private applyOperatorCandidateRequested(state: RegistryState, event: Event): void {
    const payload = event.payload as any;

    const submittedAt = Number(payload.timestamp || 0);
    const eligibleVotingAt = Number(payload.eligibleVotingAt || 0) || submittedAt + 30 * 24 * 60 * 60 * 1000;
    const eligibleVoterIds = Array.isArray(payload.eligibleVoterIds)
      ? (payload.eligibleVoterIds as any[]).map((x) => String(x))
      : undefined;
    const eligibleVoterCount = Number(payload.eligibleVoterCount || 0) || (eligibleVoterIds ? eligibleVoterIds.length : 0) || undefined;
    const requiredYesVotes = Number(payload.requiredYesVotes || 0) || undefined;

    const operator: OperatorState = {
      operatorId: payload.candidateId,
      btcAddress: payload.btcAddress,
      publicKey: payload.publicKey,
      operatorUrl: payload.operatorUrl || payload.gatewayNodeId,
      sponsorId: payload.sponsorId || payload.publicKey,
      status: 'candidate',
      candidateRequestedAt: submittedAt,
      eligibleVoterIds: eligibleVoterIds && eligibleVoterIds.length > 0 ? eligibleVoterIds : undefined,
      eligibleVoterCount,
      requiredYesVotes,
      eligibleVotingAt,
      votes: new Map(),
      voteCount: { approve: 0, reject: 0 },
    };

    state.operators.set(operator.operatorId, operator);
  }

  private applyOperatorCandidateVote(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const operator = state.operators.get(payload.candidateId);

    if (!operator || operator.status !== 'candidate') return;
    if (!operator.votes) operator.votes = new Map();

    operator.votes.set(String(payload.voterId), {
      voterId: String(payload.voterId),
      vote: payload.vote,
      reason: payload.reason,
      votedAt: Number(payload.timestamp || 0),
    });

    const votes = Array.from(operator.votes.values());
    operator.voteCount = {
      approve: votes.filter((v) => v.vote === 'approve').length,
      reject: votes.filter((v) => v.vote === 'reject').length,
    };
  }

  private applyOperatorAdmitted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const operator = state.operators.get(payload.operatorId);

    if (operator) {
      operator.status = 'active';
      operator.admittedAt = payload.timestamp;
      operator.lastActiveAt = payload.timestamp;
    }
  }

  private applyOperatorHeartbeat(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const operatorId = String(payload.operatorId || '').trim();
    if (!operatorId) return;
    const operator = state.operators.get(operatorId);
    if (!operator) return;

    const ts = Number(payload.timestamp || 0);
    operator.lastHeartbeatAt = ts;
    operator.lastActiveAt = ts;
  }

  private applyOperatorRejected(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    state.operators.delete(payload.operatorId);
  }

  private applyOperatorRemoved(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const operator = state.operators.get(payload.operatorId);

    if (operator) {
      operator.status = 'removed';
    }
  }

  private applyAccountCreated(state: RegistryState, event: Event): void {
    const payload = event.payload as any;

    const account: AccountState = {
      accountId: payload.accountId,
      role: payload.role,
      username: payload.username,
      companyName: undefined,
      displayName: undefined,
      website: undefined,
      phone: undefined,
      address: undefined,
      contactEmail: undefined,
      notes: undefined,
      bondAddress: undefined,
      bondMinSats: undefined,
      bondConfirmedSats: undefined,
      bondUtxoCount: undefined,
      bondMeetsMin: undefined,
      bondLastCheckedAt: undefined,
      retailerStatus: payload.role === 'retailer' ? 'unverified' : undefined,
      retailerVerifiedAt: undefined,
      retailerBlockedAt: undefined,
      retailerUnblockedAt: undefined,
      retailerBondAddress: undefined,
      retailerBondMinSats: undefined,
      retailerBondConfirmedSats: undefined,
      retailerBondUtxoCount: undefined,
      retailerBondMeetsMin: undefined,
      retailerBondLastCheckedAt: undefined,
      retailerRatingCount: 0,
      retailerRatingSum: 0,
      retailerRatingAvg: 0,
      retailerReportCount: 0,
      ratingCount: 0,
      ratingSum: 0,
      ratingAvg: 0,
      reportCount: 0,
      email: payload.email,
      emailHash: payload.emailHash,
      walletAddress: payload.walletAddress,
      walletVault: payload.walletVault,
      verifierStatus: 'active',
      verifierRevokedAt: undefined,
      verifierReactivatedAt: undefined,
      verifierFrozen: false,
      createdAt: payload.timestamp,
      updatedAt: payload.timestamp,
      totp: { enabled: false },
    };

    state.accounts.set(account.accountId, account);
  }

  private applyAccountVerifierProfileUpdated(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;

    const applyField = (field: string) => {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) return;
      const v = payload[field];
      if (v === null || v === undefined) {
        (account as any)[field] = undefined;
        return;
      }
      (account as any)[field] = String(v);
    };

    applyField('companyName');
    applyField('displayName');
    applyField('website');
    applyField('phone');
    applyField('address');
    applyField('contactEmail');
    applyField('notes');

    account.updatedAt = payload.timestamp;
  }

  private applyAccountVerifierBondProofRecorded(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;

    account.bondAddress = payload.bondAddress ? String(payload.bondAddress) : undefined;
    account.bondMinSats = Number(payload.bondMinSats || 0);
    account.bondConfirmedSats = Number(payload.confirmedSats || 0);
    account.bondUtxoCount = Number(payload.utxoCount || 0);
    account.bondMeetsMin = Boolean(payload.meetsMin);
    account.bondLastCheckedAt = payload.timestamp;
    account.updatedAt = payload.timestamp;
  }

  private applyAccountVerifierRated(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const targetAccountId = String(payload.targetAccountId || '').trim();
    const raterAccountId = String(payload.raterAccountId || '').trim();
    const contextType = String(payload.contextType || '').trim();
    const contextId = String(payload.contextId || '').trim();
    const rating = Number(payload.rating || 0);
    if (!targetAccountId || !raterAccountId || !contextId) return;
    if (contextType !== 'issuer_item' && contextType !== 'authenticated_item' && contextType !== 'verification_request') return;
    if (!(rating >= 1 && rating <= 5)) return;

    const target = state.accounts.get(targetAccountId);
    if (!target) return;
    const role = String(target.role || '');
    if (role !== 'manufacturer' && role !== 'authenticator') return;

    const key = `${targetAccountId}\u0000${raterAccountId}\u0000${contextType}\u0000${contextId}`;
    const existing = state.verifierRatings.get(key);

    const prevRating = existing ? Number(existing.rating || 0) : 0;
    const isNew = !existing;

    const feeTxid = payload.feeTxid ? String(payload.feeTxid).trim().toLowerCase() : undefined;
    const feePaidSats = payload.feePaidSats !== undefined ? Number(payload.feePaidSats || 0) : undefined;
    const feeBlockHeight = payload.feeBlockHeight !== undefined ? Number(payload.feeBlockHeight || 0) : undefined;
    const feeConfirmations = payload.feeConfirmations !== undefined ? Number(payload.feeConfirmations || 0) : undefined;

    state.verifierRatings.set(key, {
      key,
      targetAccountId,
      raterAccountId,
      contextType,
      contextId,
      rating,
      feeTxid,
      feePaidSats,
      feeBlockHeight,
      feeConfirmations,
      createdAt: payload.timestamp,
    });

    if (feeTxid) {
      state.verifierRatingFeeTxids.set(feeTxid, {
        txid: feeTxid,
        usedByKey: key,
        usedAt: payload.timestamp,
        paidSats: feePaidSats,
        blockHeight: feeBlockHeight,
        confirmations: feeConfirmations,
      });
    }

    const sum0 = Number(target.ratingSum || 0);
    const count0 = Number(target.ratingCount || 0);
    const sum1 = sum0 - (isNew ? 0 : prevRating) + rating;
    const count1 = isNew ? (count0 + 1) : count0;
    target.ratingSum = sum1;
    target.ratingCount = count1;
    target.ratingAvg = count1 > 0 ? (sum1 / count1) : 0;
    target.updatedAt = Math.max(Number(target.updatedAt || 0), Number(payload.timestamp || 0));
  }

  private applyAccountVerifierReported(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const targetAccountId = String(payload.targetAccountId || '').trim();
    const reporterAccountId = String(payload.reporterAccountId || '').trim();
    const contextType = String(payload.contextType || '').trim();
    const contextId = String(payload.contextId || '').trim();
    if (!targetAccountId || !reporterAccountId || !contextId) return;
    if (contextType !== 'issuer_item' && contextType !== 'authenticated_item' && contextType !== 'verification_request') return;

    const target = state.accounts.get(targetAccountId);
    if (!target) return;
    const role = String(target.role || '');
    if (role !== 'manufacturer' && role !== 'authenticator') return;

    const key = `${targetAccountId}\u0000${reporterAccountId}\u0000${contextType}\u0000${contextId}`;
    const existing = state.verifierReports.get(key);
    const isNew = !existing;

    state.verifierReports.set(key, {
      key,
      targetAccountId,
      reporterAccountId,
      contextType,
      contextId,
      reasonCode: payload.reasonCode ? String(payload.reasonCode) : undefined,
      details: payload.details ? String(payload.details) : undefined,
      createdAt: payload.timestamp,
    });

    if (isNew) {
      target.reportCount = Number(target.reportCount || 0) + 1;
    }
    target.updatedAt = Math.max(Number(target.updatedAt || 0), Number(payload.timestamp || 0));
  }

  private applyAccountRoleSet(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const account = state.accounts.get(payload.accountId);
    if (!account) return;

    account.role = payload.role;
    if (String(payload.role) === 'retailer') {
      if (!account.retailerStatus) account.retailerStatus = 'unverified';
    }
    account.updatedAt = payload.timestamp;
  }

  private applyAccountEmailSet(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const account = state.accounts.get(payload.accountId);
    if (!account) return;

    account.email = payload.email;
    account.emailHash = payload.emailHash;
    account.updatedAt = payload.timestamp;
  }

  private applyAccountRetailerProfileUpdated(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;

    const applyField = (field: string) => {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) return;
      const v = payload[field];
      if (v === null || v === undefined) {
        (account as any)[field] = undefined;
        return;
      }
      (account as any)[field] = String(v);
    };

    applyField('companyName');
    applyField('displayName');
    applyField('website');
    applyField('phone');
    applyField('address');
    applyField('contactEmail');
    applyField('notes');

    account.updatedAt = payload.timestamp;
  }

  private applyAccountRetailerBondProofRecorded(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;

    account.retailerBondAddress = payload.bondAddress ? String(payload.bondAddress) : undefined;
    account.retailerBondMinSats = Number(payload.bondMinSats || 0);
    account.retailerBondConfirmedSats = Number(payload.confirmedSats || 0);
    account.retailerBondUtxoCount = Number(payload.utxoCount || 0);
    account.retailerBondMeetsMin = Boolean(payload.meetsMin);
    account.retailerBondLastCheckedAt = payload.timestamp;
    account.updatedAt = payload.timestamp;
  }

  private applyAccountRetailerRated(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const targetAccountId = String(payload.targetAccountId || '').trim();
    const raterAccountId = String(payload.raterAccountId || '').trim();
    const contextType = String(payload.contextType || '').trim();
    const contextId = String(payload.contextId || '').trim();
    const rating = Number(payload.rating || 0);
    if (!targetAccountId || !raterAccountId || !contextId) return;
    if (contextType !== 'retailer_profile' && contextType !== 'consignment') return;
    if (!(rating >= 1 && rating <= 5)) return;

    const target = state.accounts.get(targetAccountId);
    if (!target) return;
    const role = String(target.role || '');
    if (role !== 'retailer') return;

    const key = `${targetAccountId}\u0000${raterAccountId}\u0000${contextType}\u0000${contextId}`;
    const existing = state.retailerRatings.get(key);
    const prevRating = existing ? Number(existing.rating || 0) : 0;
    const isNew = !existing;

    state.retailerRatings.set(key, {
      key,
      targetAccountId,
      raterAccountId,
      contextType: contextType as any,
      contextId,
      rating,
      createdAt: payload.timestamp,
    });

    const sum0 = Number(target.retailerRatingSum || 0);
    const count0 = Number(target.retailerRatingCount || 0);
    const sum1 = sum0 - (isNew ? 0 : prevRating) + rating;
    const count1 = isNew ? (count0 + 1) : count0;
    target.retailerRatingSum = sum1;
    target.retailerRatingCount = count1;
    target.retailerRatingAvg = count1 > 0 ? (sum1 / count1) : 0;
    target.updatedAt = Math.max(Number(target.updatedAt || 0), Number(payload.timestamp || 0));
  }

  private applyAccountRetailerReported(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const targetAccountId = String(payload.targetAccountId || '').trim();
    const reporterAccountId = String(payload.reporterAccountId || '').trim();
    const contextType = String(payload.contextType || '').trim();
    const contextId = String(payload.contextId || '').trim();
    if (!targetAccountId || !reporterAccountId || !contextId) return;
    if (contextType !== 'retailer_profile' && contextType !== 'consignment') return;

    const target = state.accounts.get(targetAccountId);
    if (!target) return;
    const role = String(target.role || '');
    if (role !== 'retailer') return;

    const key = `${targetAccountId}\u0000${reporterAccountId}\u0000${contextType}\u0000${contextId}`;
    const existing = state.retailerReports.get(key);
    const isNew = !existing;

    state.retailerReports.set(key, {
      key,
      targetAccountId,
      reporterAccountId,
      contextType: contextType as any,
      contextId,
      reasonCode: payload.reasonCode ? String(payload.reasonCode) : undefined,
      details: payload.details ? String(payload.details) : undefined,
      createdAt: payload.timestamp,
    });

    if (isNew) {
      target.retailerReportCount = Number(target.retailerReportCount || 0) + 1;
    }
    target.updatedAt = Math.max(Number(target.updatedAt || 0), Number(payload.timestamp || 0));
  }

  private applyAccountRetailerVerificationApplicationSubmitted(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const app: RetailerVerificationApplicationState = {
      applicationId: payload.applicationId,
      accountId: payload.accountId,
      companyName: payload.companyName,
      contactEmail: payload.contactEmail,
      website: payload.website,
      notes: payload.notes,
      submittedAt: payload.timestamp,
      votes: new Map(),
    };
    state.retailerVerificationApplications.set(app.applicationId, app);
  }

  private applyAccountRetailerVerificationApplicationReviewed(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const app = state.retailerVerificationApplications.get(String(payload.applicationId));
    if (!app) return;
    app.reviewed = {
      reviewerOperatorId: payload.reviewerOperatorId,
      decision: payload.decision,
      reason: payload.reason,
      reviewedAt: payload.timestamp,
    };
  }

  private applyAccountRetailerVerificationApplicationVoted(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const app = state.retailerVerificationApplications.get(String(payload.applicationId));
    if (!app) return;
    app.votes.set(payload.voterOperatorId, {
      voterOperatorId: payload.voterOperatorId,
      vote: payload.vote,
      reason: payload.reason,
      votedAt: payload.timestamp,
    });
  }

  private applyAccountRetailerVerificationApplicationFinalized(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const app = state.retailerVerificationApplications.get(String(payload.applicationId));
    if (!app) return;
    app.finalized = {
      finalizedByOperatorId: payload.finalizedByOperatorId,
      decision: payload.decision,
      reason: payload.reason,
      finalizedAt: payload.timestamp,
      activeOperatorCount: payload.activeOperatorCount,
      approveVotes: payload.approveVotes,
      rejectVotes: payload.rejectVotes,
    };
  }

  private applyAccountRetailerVerified(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;
    if (String(account.role || '') !== 'retailer') return;
    account.retailerStatus = 'verified';
    account.retailerVerifiedAt = payload.timestamp;
    account.updatedAt = payload.timestamp;
  }

  private applyAccountRetailerVerificationRevoked(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;
    if (String(account.role || '') !== 'retailer') return;

    account.retailerVerifiedAt = undefined;
    account.retailerVerificationRevokedAt = payload.timestamp;
    if (String(account.retailerStatus || 'unverified') !== 'blocked') {
      account.retailerStatus = 'unverified';
    }
    account.updatedAt = payload.timestamp;
  }

  private applyAccountRetailerActionCreated(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const actionId = String(payload.actionId || '').trim();
    if (!actionId) return;

    const action: AccountRetailerActionState = {
      actionId,
      targetAccountId: String(payload.targetAccountId || '').trim(),
      action: payload.action,
      requestedByOperatorId: String(payload.requestedByOperatorId || '').trim(),
      reason: payload.reason,
      createdAt: payload.timestamp,
      votes: new Map(),
    };
    state.retailerActions.set(action.actionId, action);
  }

  private applyAccountRetailerActionVoted(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const action = state.retailerActions.get(String(payload.actionId));
    if (!action) return;
    action.votes.set(String(payload.voterOperatorId), {
      voterOperatorId: String(payload.voterOperatorId),
      vote: payload.vote,
      reason: payload.reason,
      votedAt: payload.timestamp,
    });
  }

  private applyAccountRetailerActionFinalized(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const action = state.retailerActions.get(String(payload.actionId));
    if (!action) return;
    action.finalized = {
      finalizedByOperatorId: String(payload.finalizedByOperatorId || ''),
      decision: payload.decision,
      reason: payload.reason,
      finalizedAt: payload.timestamp,
      activeOperatorCount: payload.activeOperatorCount,
      approveVotes: payload.approveVotes,
      rejectVotes: payload.rejectVotes,
      quorumThreshold: payload.quorumThreshold,
    };
  }

  private applyAccountRetailerBlocked(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;
    if (String(account.role || '') !== 'retailer') return;
    account.retailerStatus = 'blocked';
    account.retailerBlockedAt = payload.timestamp;
    account.updatedAt = payload.timestamp;
  }

  private applyAccountRetailerUnblocked(state: RegistryState, event: Event): void {
    const payload: any = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;
    if (String(account.role || '') !== 'retailer') return;
    account.retailerStatus = account.retailerVerifiedAt ? 'verified' : 'unverified';
    account.retailerUnblockedAt = payload.timestamp;
    account.updatedAt = payload.timestamp;
  }

  private applyAccountRoleApplicationSubmitted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;

    const app: AccountRoleApplicationState = {
      applicationId: payload.applicationId,
      accountId: payload.accountId,
      requestedRole: payload.requestedRole,
      companyName: payload.companyName,
      contactEmail: payload.contactEmail,
      website: payload.website,
      notes: payload.notes,
      submittedAt: payload.timestamp,
      votes: new Map(),
    };

    state.roleApplications.set(app.applicationId, app);
  }

  private applyAccountRoleApplicationReviewed(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const app = state.roleApplications.get(payload.applicationId);
    if (!app) return;

    app.reviewed = {
      reviewerOperatorId: payload.reviewerOperatorId,
      decision: payload.decision,
      reason: payload.reason,
      reviewedAt: payload.timestamp,
    };
  }

  private applyAccountRoleApplicationVoted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const app = state.roleApplications.get(payload.applicationId);
    if (!app) return;

    app.votes.set(payload.voterOperatorId, {
      voterOperatorId: payload.voterOperatorId,
      vote: payload.vote,
      reason: payload.reason,
      votedAt: payload.timestamp,
    });
  }

  private applyAccountRoleApplicationFinalized(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const app = state.roleApplications.get(payload.applicationId);
    if (!app) return;

    app.finalized = {
      finalizedByOperatorId: payload.finalizedByOperatorId,
      decision: payload.decision,
      reason: payload.reason,
      finalizedAt: payload.timestamp,
      activeOperatorCount: payload.activeOperatorCount,
      approveVotes: payload.approveVotes,
      rejectVotes: payload.rejectVotes,
    };
  }

  private applyAccountRoleInviteCreated(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const invite: AccountRoleInviteState = {
      inviteId: payload.inviteId,
      role: payload.role,
      codeHashHex: payload.codeHashHex,
      expiresAt: payload.expiresAt,
      createdAt: payload.timestamp,
      createdByOperatorId: payload.createdByOperatorId,
    };

    state.roleInvites.set(invite.inviteId, invite);
  }

  private applyAccountRoleInviteRedeemed(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const invite = state.roleInvites.get(payload.inviteId);
    if (!invite) return;

    invite.redeemedAt = payload.timestamp;
    invite.redeemedByAccountId = payload.accountId;
  }

  private applyAccountVerifierActionCreated(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const actionId = String(payload.actionId || '').trim();
    if (!actionId) return;

    const action: AccountVerifierActionState = {
      actionId,
      targetAccountId: String(payload.targetAccountId || '').trim(),
      action: payload.action,
      requestedByOperatorId: String(payload.requestedByOperatorId || '').trim(),
      reason: payload.reason,
      createdAt: payload.timestamp,
      votes: new Map(),
    };

    state.verifierActions.set(action.actionId, action);
  }

  private applyAccountVerifierActionVoted(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const action = state.verifierActions.get(String(payload.actionId));
    if (!action) return;

    action.votes.set(String(payload.voterOperatorId), {
      voterOperatorId: String(payload.voterOperatorId),
      vote: payload.vote,
      reason: payload.reason,
      votedAt: payload.timestamp,
    });
  }

  private applyAccountVerifierActionFinalized(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const action = state.verifierActions.get(String(payload.actionId));
    if (!action) return;

    action.finalized = {
      finalizedByOperatorId: String(payload.finalizedByOperatorId || ''),
      decision: payload.decision,
      reason: payload.reason,
      finalizedAt: payload.timestamp,
      activeOperatorCount: payload.activeOperatorCount,
      approveVotes: payload.approveVotes,
      rejectVotes: payload.rejectVotes,
      quorumThreshold: payload.quorumThreshold,
    };
  }

  private applyAccountVerifierRevoked(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;

    account.verifierStatus = 'revoked';
    account.verifierRevokedAt = payload.timestamp;
    account.verifierFrozen = true;
    account.updatedAt = payload.timestamp;
  }

  private applyAccountVerifierReactivated(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const accountId = String(payload.accountId || '').trim();
    const account = state.accounts.get(accountId);
    if (!account) return;

    account.verifierStatus = 'active';
    account.verifierReactivatedAt = payload.timestamp;
    account.updatedAt = payload.timestamp;
  }

  private applyAccountPakeRecordSet(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const account = state.accounts.get(payload.accountId);
    if (!account) return;

    account.pake = { suiteId: payload.suiteId, recordB64: payload.recordB64 };
    account.updatedAt = payload.timestamp;
  }

  private applyAccountTotpEnabled(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const account = state.accounts.get(payload.accountId);
    if (!account) return;

    account.totp = {
      enabled: true,
      encScheme: payload.encScheme,
      totpSecretEncB64: payload.totpSecretEncB64,
    };
    account.updatedAt = payload.timestamp;
  }

  private applyAccountTotpDisabled(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const account = state.accounts.get(payload.accountId);
    if (!account) return;

    account.totp = { enabled: false };
    account.updatedAt = payload.timestamp;
  }

  private applyAccountRecoveryTotpReset(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const account = state.accounts.get(payload.accountId);
    if (!account) return;

    account.totp = {
      enabled: true,
      encScheme: payload.encScheme,
      totpSecretEncB64: payload.totpSecretEncB64,
    };
    account.updatedAt = payload.timestamp;
  }

  private applyAccountPasswordSet(state: RegistryState, event: Event): void {
    const payload = event.payload as any;
    const account = state.accounts.get(payload.accountId);
    if (!account) return;
    account.passwordHash = payload.passwordHash;
    account.passwordKdf = payload.passwordKdf;
    account.updatedAt = payload.timestamp;
  }

  /**
   * Get item by ID from current state
   */
  async getItem(itemId: string): Promise<ItemState | null> {
    const state = await this.buildState();
    return state.items.get(itemId) || null;
  }

  /**
   * Get all items owned by an address
   */
  async getItemsByOwner(ownerAddress: string): Promise<ItemState[]> {
    const state = await this.buildState();
    const items: ItemState[] = [];

    for (const item of state.items.values()) {
      if (item.currentOwner === ownerAddress) {
        items.push(item);
      }
    }

    return items;
  }

  /**
   * Get settlement by ID
   */
  async getSettlement(settlementId: string): Promise<SettlementState | null> {
    const state = await this.buildState();
    return state.settlements.get(settlementId) || null;
  }

  /**
   * Get all active operators
   */
  async getActiveOperators(): Promise<OperatorState[]> {
    const state = await this.buildState();
    const operators: OperatorState[] = [];

    for (const operator of state.operators.values()) {
      if (operator.status === 'active') {
        operators.push(operator);
      }
    }

    return operators;
  }
}
