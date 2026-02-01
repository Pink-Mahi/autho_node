/**
 * Event Store Types
 * 
 * Defines the structure for the append-only event log that forms
 * the basis of the decentralized registry.
 */

export enum EventType {
  // Item lifecycle
  ITEM_REGISTERED = 'ITEM_REGISTERED',
  ITEM_METADATA_UPDATED = 'ITEM_METADATA_UPDATED',
  
  // Ownership
  OWNERSHIP_TRANSFERRED = 'OWNERSHIP_TRANSFERRED',
  OWNERSHIP_CLAIMED = 'OWNERSHIP_CLAIMED',
  
  // Authentication
  AUTHENTICATION_PERFORMED = 'AUTHENTICATION_PERFORMED',
  AUTHENTICATION_RESULT_RECORDED = 'AUTHENTICATION_RESULT_RECORDED',

  // Owner-requested verification jobs
  VERIFICATION_REQUEST_CREATED = 'VERIFICATION_REQUEST_CREATED',
  VERIFICATION_REQUEST_ACCEPTED = 'VERIFICATION_REQUEST_ACCEPTED',
  VERIFICATION_REQUEST_COMPLETED = 'VERIFICATION_REQUEST_COMPLETED',
  VERIFICATION_REQUEST_CANCELLED = 'VERIFICATION_REQUEST_CANCELLED',
  
  // Settlement
  SETTLEMENT_INITIATED = 'SETTLEMENT_INITIATED',
  SETTLEMENT_CLAIMED = 'SETTLEMENT_CLAIMED',
  SETTLEMENT_ACCEPTED = 'SETTLEMENT_ACCEPTED',
  SETTLEMENT_PAYMENT_SUBMITTED = 'SETTLEMENT_PAYMENT_SUBMITTED',
  SETTLEMENT_COMPLETED = 'SETTLEMENT_COMPLETED',
  SETTLEMENT_FAILED = 'SETTLEMENT_FAILED',

  // Retailer consignments
  CONSIGNMENT_CREATED = 'CONSIGNMENT_CREATED',
  CONSIGNMENT_OWNER_CONFIRMED = 'CONSIGNMENT_OWNER_CONFIRMED',
  CONSIGNMENT_RETAILER_CONFIRMED = 'CONSIGNMENT_RETAILER_CONFIRMED',
  CONSIGNMENT_PRICE_UPDATED = 'CONSIGNMENT_PRICE_UPDATED',
  CONSIGNMENT_CHECKOUT_LOCKED = 'CONSIGNMENT_CHECKOUT_LOCKED',
  CONSIGNMENT_PAYMENT_SUBMITTED = 'CONSIGNMENT_PAYMENT_SUBMITTED',
  CONSIGNMENT_CANCEL_REQUESTED = 'CONSIGNMENT_CANCEL_REQUESTED',
  CONSIGNMENT_CANCEL_CONFIRMED = 'CONSIGNMENT_CANCEL_CONFIRMED',
  CONSIGNMENT_EXPIRED = 'CONSIGNMENT_EXPIRED',
  CONSIGNMENT_COMPLETED = 'CONSIGNMENT_COMPLETED',
  
  // Operator network
  OPERATOR_CANDIDATE_REQUESTED = 'OPERATOR_CANDIDATE_REQUESTED',
  OPERATOR_CANDIDATE_VOTE = 'OPERATOR_CANDIDATE_VOTE',
  OPERATOR_ADMITTED = 'OPERATOR_ADMITTED',
  OPERATOR_REJECTED = 'OPERATOR_REJECTED',
  OPERATOR_REMOVED = 'OPERATOR_REMOVED',
  OPERATOR_HEARTBEAT = 'OPERATOR_HEARTBEAT',
  
  // Bitcoin anchoring
  ANCHOR_COMMITTED = 'ANCHOR_COMMITTED',
  CHECKPOINT_CREATED = 'CHECKPOINT_CREATED',

  // Accounts / Authentication
  ACCOUNT_CREATED = 'ACCOUNT_CREATED',
  ACCOUNT_ROLE_SET = 'ACCOUNT_ROLE_SET',
  ACCOUNT_EMAIL_SET = 'ACCOUNT_EMAIL_SET',
  ACCOUNT_PASSWORD_SET = 'ACCOUNT_PASSWORD_SET',
  ACCOUNT_PAKE_RECORD_SET = 'ACCOUNT_PAKE_RECORD_SET',
  ACCOUNT_TOTP_ENABLED = 'ACCOUNT_TOTP_ENABLED',
  ACCOUNT_TOTP_DISABLED = 'ACCOUNT_TOTP_DISABLED',
  ACCOUNT_RECOVERY_TOTP_RESET = 'ACCOUNT_RECOVERY_TOTP_RESET',
  ACCOUNT_PAY_HANDLE_SET = 'ACCOUNT_PAY_HANDLE_SET',

  // Account role applications / invites
  ACCOUNT_ROLE_APPLICATION_SUBMITTED = 'ACCOUNT_ROLE_APPLICATION_SUBMITTED',
  ACCOUNT_ROLE_APPLICATION_REVIEWED = 'ACCOUNT_ROLE_APPLICATION_REVIEWED',
  ACCOUNT_ROLE_APPLICATION_VOTED = 'ACCOUNT_ROLE_APPLICATION_VOTED',
  ACCOUNT_ROLE_APPLICATION_FINALIZED = 'ACCOUNT_ROLE_APPLICATION_FINALIZED',
  ACCOUNT_ROLE_INVITE_CREATED = 'ACCOUNT_ROLE_INVITE_CREATED',
  ACCOUNT_ROLE_INVITE_REDEEMED = 'ACCOUNT_ROLE_INVITE_REDEEMED',

  // Content moderation (image tombstoning)
  ITEM_IMAGE_TOMBSTONE_PROPOSED = 'ITEM_IMAGE_TOMBSTONE_PROPOSED',
  ITEM_IMAGE_TOMBSTONE_VOTED = 'ITEM_IMAGE_TOMBSTONE_VOTED',
  ITEM_IMAGE_TOMBSTONED = 'ITEM_IMAGE_TOMBSTONED',

  // Verifier governance (manufacturers/authenticators)
  ACCOUNT_VERIFIER_ACTION_CREATED = 'ACCOUNT_VERIFIER_ACTION_CREATED',
  ACCOUNT_VERIFIER_ACTION_VOTED = 'ACCOUNT_VERIFIER_ACTION_VOTED',
  ACCOUNT_VERIFIER_ACTION_FINALIZED = 'ACCOUNT_VERIFIER_ACTION_FINALIZED',
  ACCOUNT_VERIFIER_PROFILE_UPDATED = 'ACCOUNT_VERIFIER_PROFILE_UPDATED',
  ACCOUNT_VERIFIER_BOND_PROOF_RECORDED = 'ACCOUNT_VERIFIER_BOND_PROOF_RECORDED',
  ACCOUNT_VERIFIER_RATED = 'ACCOUNT_VERIFIER_RATED',
  ACCOUNT_VERIFIER_REPORTED = 'ACCOUNT_VERIFIER_REPORTED',
  ACCOUNT_VERIFIER_REVOKED = 'ACCOUNT_VERIFIER_REVOKED',
  ACCOUNT_VERIFIER_REACTIVATED = 'ACCOUNT_VERIFIER_REACTIVATED',

  // Retailer trust layer
  ACCOUNT_RETAILER_ACTION_CREATED = 'ACCOUNT_RETAILER_ACTION_CREATED',
  ACCOUNT_RETAILER_ACTION_VOTED = 'ACCOUNT_RETAILER_ACTION_VOTED',
  ACCOUNT_RETAILER_ACTION_FINALIZED = 'ACCOUNT_RETAILER_ACTION_FINALIZED',
  ACCOUNT_RETAILER_BLOCKED = 'ACCOUNT_RETAILER_BLOCKED',
  ACCOUNT_RETAILER_UNBLOCKED = 'ACCOUNT_RETAILER_UNBLOCKED',
  ACCOUNT_RETAILER_PROFILE_UPDATED = 'ACCOUNT_RETAILER_PROFILE_UPDATED',
  ACCOUNT_RETAILER_BOND_PROOF_RECORDED = 'ACCOUNT_RETAILER_BOND_PROOF_RECORDED',
  ACCOUNT_RETAILER_RATED = 'ACCOUNT_RETAILER_RATED',
  ACCOUNT_RETAILER_REPORTED = 'ACCOUNT_RETAILER_REPORTED',
  ACCOUNT_RETAILER_VERIFICATION_APPLICATION_SUBMITTED = 'ACCOUNT_RETAILER_VERIFICATION_APPLICATION_SUBMITTED',
  ACCOUNT_RETAILER_VERIFICATION_APPLICATION_REVIEWED = 'ACCOUNT_RETAILER_VERIFICATION_APPLICATION_REVIEWED',
  ACCOUNT_RETAILER_VERIFICATION_APPLICATION_VOTED = 'ACCOUNT_RETAILER_VERIFICATION_APPLICATION_VOTED',
  ACCOUNT_RETAILER_VERIFICATION_APPLICATION_FINALIZED = 'ACCOUNT_RETAILER_VERIFICATION_APPLICATION_FINALIZED',
  ACCOUNT_RETAILER_VERIFIED = 'ACCOUNT_RETAILER_VERIFIED',
  ACCOUNT_RETAILER_VERIFICATION_REVOKED = 'ACCOUNT_RETAILER_VERIFICATION_REVOKED',

  // Network topology (decentralized discovery)
  NETWORK_OPERATOR_ANNOUNCED = 'NETWORK_OPERATOR_ANNOUNCED',
  NETWORK_OPERATOR_DEANNOUNCED = 'NETWORK_OPERATOR_DEANNOUNCED',
  NETWORK_GATEWAY_ANNOUNCED = 'NETWORK_GATEWAY_ANNOUNCED',
  NETWORK_GATEWAY_DEANNOUNCED = 'NETWORK_GATEWAY_DEANNOUNCED',
  NETWORK_SEED_ANNOUNCED = 'NETWORK_SEED_ANNOUNCED',
}

export interface BaseEventPayload {
  type: EventType;
  timestamp: number;
  nonce: string;
}

export interface LedgerImage {
  mime: 'image/webp' | 'image/jpeg' | 'image/png';
  dataB64: string;
  sha256Hex: string;
  w: number;
  h: number;
}

/**
 * Standard item metadata schema for searchable items.
 * Image hashes are stored on the ledger (not the images themselves).
 */
export interface ItemMetadata {
  /** Display name of the item */
  name: string;
  /** Detailed description */
  description?: string;
  /** Model number/name (e.g., "Air Jordan 1 Retro High OG") */
  model?: string;
  /** Brand name (e.g., "Nike", "Rolex", "Pokemon") */
  brand?: string;
  /** Category for filtering (e.g., "sneaker", "watch", "trading_card", "collectible") */
  category?: string;
  /** Year of manufacture/release */
  year?: number;
  /** Condition (e.g., "mint", "near_mint", "excellent", "good", "fair", "poor") */
  condition?: string;
  /** Edition info (e.g., "1st Edition", "Limited Release") */
  edition?: string;
  /** Rarity level (e.g., "common", "uncommon", "rare", "ultra_rare", "legendary") */
  rarity?: string;
  /** Color/colorway */
  color?: string;
  /** Size (for apparel/shoes) */
  size?: string;
  /** Material composition */
  material?: string;
  /** Legacy image URL (deprecated - use images with hashes) */
  imageUrl?: string;
  /** Images with SHA-256 hashes stored on ledger */
  images?: LedgerImage[];
  /** Additional image hashes (for images stored externally) */
  imageHashes?: string[];
  /** Any additional custom fields */
  [key: string]: any;
}

export interface ItemRegisteredPayload extends BaseEventPayload {
  type: EventType.ITEM_REGISTERED;
  itemId: string;
  
  /**
   * The claimed manufacturer/brand name (e.g., "Rolex", "Nike", "Pokemon")
   * This is what the minter CLAIMS the item is - not necessarily verified.
   * Authentication by an authenticator validates this claim.
   */
  manufacturerName: string;
  
  /**
   * Optional: If the minter is a registered manufacturer account, this links to their account.
   * If a user mints their own Rolex, this would be empty.
   * If Rolex (the company) mints it, this would be their manufacturer account ID.
   */
  manufacturerId?: string;
  
  /**
   * Who minted this item:
   * - 'manufacturer': Official manufacturer account (manufacturerId matches a verified manufacturer)
   * - 'authenticator': An authenticator minted on behalf of someone
   * - 'user': A regular user minted their own item
   */
  issuerRole: 'manufacturer' | 'authenticator' | 'user';
  
  /** The account ID of whoever actually minted this item */
  issuerAccountId: string;
  
  serialNumberHash: string;
  serialNumberDisplay?: string;
  metadataHash: string;
  metadata?: ItemMetadata;
  initialOwner: string; // Bitcoin address

  // Per-mint fee + Bitcoin anchor
  feeTxid?: string;
  feeBlockHeight?: number;
  feeCommitmentHex?: string;
}

export interface VerificationRequestCreatedPayload extends BaseEventPayload {
  type: EventType.VERIFICATION_REQUEST_CREATED;
  requestId: string;
  itemId: string;
  ownerWallet: string;
  authenticatorId: string;
  authenticatorWallet: string;
  serviceFeeSats: number;
  maxServiceFeeSats?: number;
  platformFeeSats: number;
  commitmentHex: string;
  expiresAt?: number;
}

export interface VerificationRequestAcceptedPayload extends BaseEventPayload {
  type: EventType.VERIFICATION_REQUEST_ACCEPTED;
  requestId: string;
  itemId: string;
  authenticatorId: string;
  acceptedAt: number;
  serviceFeeSats?: number;
  platformFeeSats?: number;
}

export interface VerificationRequestCompletedPayload extends BaseEventPayload {
  type: EventType.VERIFICATION_REQUEST_COMPLETED;
  requestId: string;
  itemId: string;
  authenticatorId: string;
  completedAt: number;
  paymentTxid: string;
  blockHeight?: number;
  serviceFeeSats: number;
  platformFeeSats: number;
  commitmentHex: string;
  attestationId?: string;
}

export interface VerificationRequestCancelledPayload extends BaseEventPayload {
  type: EventType.VERIFICATION_REQUEST_CANCELLED;
  requestId: string;
  itemId: string;
  cancelledAt: number;
  reason?: string;
}

export interface OwnershipTransferredPayload extends BaseEventPayload {
  type: EventType.OWNERSHIP_TRANSFERRED;
  itemId: string;
  fromOwner: string;
  toOwner: string;
  settlementId?: string;
  price?: number; // in satoshis
  paymentTxHash?: string;
}

export interface AuthenticationPerformedPayload extends BaseEventPayload {
  type: EventType.AUTHENTICATION_PERFORMED;
  itemId: string;
  authenticatorId: string;
  attestationId?: string;
}

export interface AuthenticationResultRecordedPayload extends BaseEventPayload {
  type: EventType.AUTHENTICATION_RESULT_RECORDED;
  itemId: string;
  authenticatorId: string;
  isAuthentic: boolean;
  confidence: 'high' | 'medium' | 'low';
  notes?: string;
  images?: LedgerImage[];
  attestationHash?: string;
  attestationId?: string;

  // Per-attestation fee + Bitcoin anchor
  feeTxid?: string;
  feeBlockHeight?: number;
  feeCommitmentHex?: string;
}

export interface SettlementInitiatedPayload extends BaseEventPayload {
  type: EventType.SETTLEMENT_INITIATED;
  settlementId: string;
  itemId: string;
  seller: string;
  buyer: string;
  price: number; // in satoshis
  escrowAddress: string;
  expiresAt: number;
}

export interface PlatformFeePayoutSnapshot {
  platformFeeSats: number;
  mainNodeAddress: string;
  mainNodeFeeSats: number;
  operatorPayouts: Array<{ operatorId: string; address: string; amountSats: number }>;
}

export interface SettlementClaimedPayload extends BaseEventPayload {
  type: EventType.SETTLEMENT_CLAIMED;
  settlementId: string;
  itemId: string;
  buyer: string;
  acceptedAt: number;
  platformFeePayouts?: PlatformFeePayoutSnapshot;
}

export interface SettlementAcceptedPayload extends BaseEventPayload {
  type: EventType.SETTLEMENT_ACCEPTED;
  settlementId: string;
  itemId: string;
  acceptedAt: number;
  platformFeePayouts?: PlatformFeePayoutSnapshot;
}

export interface SettlementPaymentSubmittedPayload extends BaseEventPayload {
  type: EventType.SETTLEMENT_PAYMENT_SUBMITTED;
  settlementId: string;
  itemId: string;
  txid: string;
}

export interface SettlementCompletedPayload extends BaseEventPayload {
  type: EventType.SETTLEMENT_COMPLETED;
  settlementId: string;
  itemId: string;
  txid: string;
  blockHeight?: number;
  platformFee: number;
  operatorFees: { [operatorId: string]: number };
}

export interface ConsignmentCreatedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_CREATED;
  consignmentId: string;
  itemId: string;
  ownerAccountId: string;
  ownerWallet: string;
  retailerAccountId: string;
  retailerWallet: string;
  sellerMinNetSats: number;
  askingPriceSats: number;
  retailerMarkupShareBps: number; // default 2500 = 25%
  platformFeeSats: number;
  retailerCommissionSats: number;
  sellerPayoutSats: number;
  expiresAt: number;
  createdByAccountId: string;
}

export interface ConsignmentOwnerConfirmedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_OWNER_CONFIRMED;
  consignmentId: string;
  confirmedByAccountId: string;
}

export interface ConsignmentRetailerConfirmedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_RETAILER_CONFIRMED;
  consignmentId: string;
  confirmedByAccountId: string;
}

export interface ConsignmentPriceUpdatedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_PRICE_UPDATED;
  consignmentId: string;
  askingPriceSats: number;
  platformFeeSats: number;
  retailerCommissionSats: number;
  sellerPayoutSats: number;
  updatedByAccountId: string;
}

export interface ConsignmentCheckoutLockedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_CHECKOUT_LOCKED;
  consignmentId: string;
  lockedByAccountId: string;
  lockedUntil: number;
  platformFeePayouts?: PlatformFeePayoutSnapshot;
}

export interface ConsignmentPaymentSubmittedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_PAYMENT_SUBMITTED;
  consignmentId: string;
  buyerAccountId: string;
  buyerWallet: string;
  txid: string;
}

export interface ConsignmentCancelRequestedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_CANCEL_REQUESTED;
  consignmentId: string;
  requestedByAccountId: string;
  reason?: string;
}

export interface ConsignmentCancelConfirmedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_CANCEL_CONFIRMED;
  consignmentId: string;
  confirmedByAccountId: string;
  reason?: string;
}

export interface ConsignmentExpiredPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_EXPIRED;
  consignmentId: string;
}

export interface ConsignmentCompletedPayload extends BaseEventPayload {
  type: EventType.CONSIGNMENT_COMPLETED;
  consignmentId: string;
  settlementId?: string;
  txid?: string;
}

export interface AccountCreatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_CREATED;
  accountId: string; // canonical identity (wallet public key)
  role: 'buyer' | 'manufacturer' | 'retailer' | 'authenticator' | 'operator';
  username?: string;
  email?: string;
  emailHash?: string;
  walletAddress?: string;
  walletVault?: any;
}

export interface AccountRoleSetPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_ROLE_SET;
  accountId: string;
  role: 'buyer' | 'manufacturer' | 'retailer' | 'authenticator' | 'operator';
  reason?: string;
  applicationId?: string;
  inviteId?: string;
  decidedByOperatorId?: string;
}

export interface AccountEmailSetPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_EMAIL_SET;
  accountId: string;
  email: string;
  emailHash: string;
}

export interface AccountRoleApplicationSubmittedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_ROLE_APPLICATION_SUBMITTED;
  applicationId: string;
  accountId: string;
  requestedRole: 'manufacturer' | 'authenticator';
  companyName?: string;
  contactEmail?: string;
  website?: string;
  notes?: string;
}

export interface AccountRoleApplicationReviewedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_ROLE_APPLICATION_REVIEWED;
  applicationId: string;
  reviewerOperatorId: string;
  decision: 'approve' | 'reject';
  reason?: string;
}

export interface AccountRoleApplicationVotedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_ROLE_APPLICATION_VOTED;
  applicationId: string;
  voterOperatorId: string;
  vote: 'approve' | 'reject';
  reason?: string;
}

export interface AccountRoleApplicationFinalizedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_ROLE_APPLICATION_FINALIZED;
  applicationId: string;
  finalizedByOperatorId: string;
  decision: 'approve' | 'reject';
  reason?: string;
  activeOperatorCount: number;
  approveVotes: number;
  rejectVotes: number;
}

export interface AccountRoleInviteCreatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_ROLE_INVITE_CREATED;
  inviteId: string;
  role: 'manufacturer' | 'authenticator';
  codeHashHex: string;
  expiresAt: number;
  createdByOperatorId: string;
}

export interface AccountRoleInviteRedeemedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_ROLE_INVITE_REDEEMED;
  inviteId: string;
  accountId: string;
}

export interface AccountVerifierActionCreatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_ACTION_CREATED;
  actionId: string;
  targetAccountId: string;
  action: 'revoke' | 'reactivate';
  requestedByOperatorId: string;
  reason?: string;
}

export interface AccountVerifierActionVotedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_ACTION_VOTED;
  actionId: string;
  voterOperatorId: string;
  vote: 'approve' | 'reject';
  reason?: string;
}

export interface AccountVerifierActionFinalizedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_ACTION_FINALIZED;
  actionId: string;
  finalizedByOperatorId: string;
  decision: 'approve' | 'reject';
  reason?: string;
  activeOperatorCount: number;
  approveVotes: number;
  rejectVotes: number;
  quorumThreshold: number;
}

export interface AccountVerifierProfileUpdatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_PROFILE_UPDATED;
  accountId: string;
  updatedByAccountId?: string;
  companyName?: string;
  displayName?: string;
  website?: string;
  phone?: string;
  address?: string;
  contactEmail?: string;
  notes?: string;
}

export interface AccountVerifierBondProofRecordedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_BOND_PROOF_RECORDED;
  accountId: string;
  bondAddress: string;
  bondMinSats: number;
  confirmedSats: number;
  utxoCount: number;
  meetsMin: boolean;
  recordedByAccountId?: string;
}

export interface AccountVerifierRatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_RATED;
  targetAccountId: string;
  raterAccountId: string;
  contextType: 'issuer_item' | 'authenticated_item' | 'verification_request';
  contextId: string;
  rating: number; // 1..5
  feeTxid?: string;
  feePaidSats?: number;
  feeBlockHeight?: number;
  feeConfirmations?: number;
}

export interface AccountVerifierReportedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_REPORTED;
  targetAccountId: string;
  reporterAccountId: string;
  contextType: 'issuer_item' | 'authenticated_item' | 'verification_request';
  contextId: string;
  reasonCode?: string;
  details?: string;
}

export interface AccountVerifierRevokedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_REVOKED;
  accountId: string;
  revokedByOperatorId: string;
  reason?: string;
  actionId?: string;
}

export interface AccountVerifierReactivatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_VERIFIER_REACTIVATED;
  accountId: string;
  reactivatedByOperatorId: string;
  reason?: string;
  actionId?: string;
}

export interface AccountRetailerActionCreatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_ACTION_CREATED;
  actionId: string;
  targetAccountId: string;
  action: 'block' | 'unblock';
  requestedByOperatorId: string;
  reason?: string;
}

export interface AccountRetailerActionVotedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_ACTION_VOTED;
  actionId: string;
  voterOperatorId: string;
  vote: 'approve' | 'reject';
  reason?: string;
}

export interface AccountRetailerActionFinalizedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_ACTION_FINALIZED;
  actionId: string;
  finalizedByOperatorId: string;
  decision: 'approve' | 'reject';
  reason?: string;
  activeOperatorCount: number;
  approveVotes: number;
  rejectVotes: number;
  quorumThreshold: number;
}

export interface AccountRetailerBlockedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_BLOCKED;
  accountId: string;
  blockedByOperatorId: string;
  reason?: string;
  actionId?: string;
}

export interface AccountRetailerUnblockedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_UNBLOCKED;
  accountId: string;
  unblockedByOperatorId: string;
  reason?: string;
  actionId?: string;
}

export interface AccountRetailerProfileUpdatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_PROFILE_UPDATED;
  accountId: string;
  updatedByAccountId?: string;
  companyName?: string;
  displayName?: string;
  website?: string;
  phone?: string;
  address?: string;
  contactEmail?: string;
  notes?: string;
}

export interface AccountRetailerBondProofRecordedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_BOND_PROOF_RECORDED;
  accountId: string;
  bondAddress: string;
  bondMinSats: number;
  confirmedSats: number;
  utxoCount: number;
  meetsMin: boolean;
  recordedByAccountId?: string;
}

export interface AccountRetailerRatedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_RATED;
  targetAccountId: string;
  raterAccountId: string;
  contextType: 'retailer_profile' | 'consignment';
  contextId: string;
  rating: number; // 1..5
}

export interface AccountRetailerReportedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_REPORTED;
  targetAccountId: string;
  reporterAccountId: string;
  contextType: 'retailer_profile' | 'consignment';
  contextId: string;
  reasonCode?: string;
  details?: string;
}

export interface AccountRetailerVerificationApplicationSubmittedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_SUBMITTED;
  applicationId: string;
  accountId: string;
  companyName?: string;
  contactEmail?: string;
  website?: string;
  notes?: string;
}

export interface AccountRetailerVerificationApplicationReviewedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_REVIEWED;
  applicationId: string;
  reviewerOperatorId: string;
  decision: 'approve' | 'reject';
  reason?: string;
}

export interface AccountRetailerVerificationApplicationVotedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_VOTED;
  applicationId: string;
  voterOperatorId: string;
  vote: 'approve' | 'reject';
  reason?: string;
}

export interface AccountRetailerVerificationApplicationFinalizedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_FINALIZED;
  applicationId: string;
  finalizedByOperatorId: string;
  decision: 'approve' | 'reject';
  reason?: string;
  activeOperatorCount: number;
  approveVotes: number;
  rejectVotes: number;
}

export interface AccountRetailerVerifiedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_VERIFIED;
  accountId: string;
  verifiedByOperatorId: string;
  applicationId?: string;
  reason?: string;
}

export interface AccountRetailerVerificationRevokedPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RETAILER_VERIFICATION_REVOKED;
  accountId: string;
  revokedByOperatorId: string;
  reason?: string;
}

export interface AccountPakeRecordSetPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_PAKE_RECORD_SET;
  accountId: string;
  suiteId: string; // algorithm agility (OPAQUE/PAKE suite)
  recordB64: string; // suite-specific bytes (base64)
}

export interface AccountTotpEnabledPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_TOTP_ENABLED;
  accountId: string;
  totpSecretEncB64: string; // encrypted secret bytes (base64)
  encScheme: string; // e.g. 'AUTHO_TOTP_ENC_V1'
}

export interface AccountTotpDisabledPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_TOTP_DISABLED;
  accountId: string;
}

export interface AccountRecoveryTotpResetPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_RECOVERY_TOTP_RESET;
  accountId: string;
  totpSecretEncB64: string;
  encScheme: string;
}

export interface AccountPasswordSetPayload extends BaseEventPayload {
  type: EventType.ACCOUNT_PASSWORD_SET;
  accountId: string;
  passwordHash: string;
  passwordKdf?: { saltB64?: string; iterations?: number; hash?: string };
}

export interface AnchorCommittedPayload extends BaseEventPayload {
  type: EventType.ANCHOR_COMMITTED;
  checkpointRoot: string;
  eventCount: number;
  txid: string;
  blockHeight: number;
  quorumSignatures: QuorumSignature[];
}

export interface OperatorCandidateRequestedPayload extends BaseEventPayload {
  type: EventType.OPERATOR_CANDIDATE_REQUESTED;
  candidateId: string;
  gatewayNodeId: string;
  operatorUrl?: string;
  btcAddress: string;
  publicKey: string;
  sponsorId?: string;
  eligibleVoterIds?: string[];
  eligibleVoterCount?: number;
  requiredYesVotes?: number;
  eligibleVotingAt?: number;
}

export interface OperatorCandidateVotePayload extends BaseEventPayload {
  type: EventType.OPERATOR_CANDIDATE_VOTE;
  candidateId: string;
  voterId: string;
  vote: 'approve' | 'reject';
  reason?: string;
}

export interface OperatorHeartbeatPayload extends BaseEventPayload {
  type: EventType.OPERATOR_HEARTBEAT;
  operatorId: string;
}

export interface SettlementFailedPayload extends BaseEventPayload {
  type: EventType.SETTLEMENT_FAILED;
  settlementId: string;
  itemId: string;
  reason: string;
}

export interface OperatorAdmittedPayload extends BaseEventPayload {
  type: EventType.OPERATOR_ADMITTED;
  operatorId: string;
  btcAddress: string;
  publicKey: string;
}

export interface OperatorRejectedPayload extends BaseEventPayload {
  type: EventType.OPERATOR_REJECTED;
  operatorId: string;
  reason: string;
}

export interface OperatorRemovedPayload extends BaseEventPayload {
  type: EventType.OPERATOR_REMOVED;
  operatorId: string;
  reason: string;
}

// Content moderation - Image tombstoning
export interface ItemImageTombstoneProposedPayload extends BaseEventPayload {
  type: EventType.ITEM_IMAGE_TOMBSTONE_PROPOSED;
  proposalId: string;
  itemId: string;
  imageHash: string;  // sha256Hex of the image to tombstone
  proposerOperatorId: string;
  reason: string;  // e.g., 'illegal_content', 'copyright', 'other'
  details?: string;
}

export interface ItemImageTombstoneVotedPayload extends BaseEventPayload {
  type: EventType.ITEM_IMAGE_TOMBSTONE_VOTED;
  proposalId: string;
  operatorId: string;
  vote: 'approve' | 'reject';
}

export interface ItemImageTombstonedPayload extends BaseEventPayload {
  type: EventType.ITEM_IMAGE_TOMBSTONED;
  proposalId: string;
  itemId: string;
  imageHash: string;
  reason: string;
  approvedBy: string[];  // operator IDs who voted approve
}

export type EventPayload =
  | ItemRegisteredPayload
  | VerificationRequestCreatedPayload
  | VerificationRequestAcceptedPayload
  | VerificationRequestCompletedPayload
  | VerificationRequestCancelledPayload
  | OwnershipTransferredPayload
  | AuthenticationPerformedPayload
  | AuthenticationResultRecordedPayload
  | AccountCreatedPayload
  | AccountRoleSetPayload
  | AccountEmailSetPayload
  | AccountPasswordSetPayload
  | AccountRoleApplicationSubmittedPayload
  | AccountRoleApplicationReviewedPayload
  | AccountRoleApplicationVotedPayload
  | AccountRoleApplicationFinalizedPayload
  | AccountRoleInviteCreatedPayload
  | AccountRoleInviteRedeemedPayload
  | AccountVerifierActionCreatedPayload
  | AccountVerifierActionVotedPayload
  | AccountVerifierActionFinalizedPayload
  | AccountVerifierProfileUpdatedPayload
  | AccountVerifierBondProofRecordedPayload
  | AccountVerifierRatedPayload
  | AccountVerifierReportedPayload
  | AccountVerifierRevokedPayload
  | AccountVerifierReactivatedPayload
  | AccountRetailerActionCreatedPayload
  | AccountRetailerActionVotedPayload
  | AccountRetailerActionFinalizedPayload
  | AccountRetailerBlockedPayload
  | AccountRetailerUnblockedPayload
  | AccountRetailerProfileUpdatedPayload
  | AccountRetailerBondProofRecordedPayload
  | AccountRetailerRatedPayload
  | AccountRetailerReportedPayload
  | AccountRetailerVerificationApplicationSubmittedPayload
  | AccountRetailerVerificationApplicationReviewedPayload
  | AccountRetailerVerificationApplicationVotedPayload
  | AccountRetailerVerificationApplicationFinalizedPayload
  | AccountRetailerVerifiedPayload
  | AccountRetailerVerificationRevokedPayload
  | AccountPakeRecordSetPayload
  | AccountTotpEnabledPayload
  | AccountTotpDisabledPayload
  | AccountRecoveryTotpResetPayload
  | SettlementInitiatedPayload
  | SettlementClaimedPayload
  | SettlementAcceptedPayload
  | SettlementPaymentSubmittedPayload
  | SettlementCompletedPayload
  | SettlementFailedPayload
  | ConsignmentCreatedPayload
  | ConsignmentOwnerConfirmedPayload
  | ConsignmentRetailerConfirmedPayload
  | ConsignmentPriceUpdatedPayload
  | ConsignmentCheckoutLockedPayload
  | ConsignmentPaymentSubmittedPayload
  | ConsignmentCancelRequestedPayload
  | ConsignmentCancelConfirmedPayload
  | ConsignmentExpiredPayload
  | ConsignmentCompletedPayload
  | AnchorCommittedPayload
  | OperatorCandidateRequestedPayload
  | OperatorCandidateVotePayload
  | OperatorHeartbeatPayload
  | OperatorAdmittedPayload
  | OperatorRejectedPayload
  | OperatorRemovedPayload
  | ItemImageTombstoneProposedPayload
  | ItemImageTombstoneVotedPayload
  | ItemImageTombstonedPayload
  | NetworkOperatorAnnouncedPayload
  | NetworkOperatorDeannouncedPayload
  | NetworkGatewayAnnouncedPayload
  | NetworkGatewayDeannouncedPayload
  | NetworkSeedAnnouncedPayload;

// Network topology payloads for decentralized discovery
export interface NetworkOperatorAnnouncedPayload extends BaseEventPayload {
  type: EventType.NETWORK_OPERATOR_ANNOUNCED;
  operatorId: string;
  httpUrl: string;
  wsUrl: string;
  torUrl?: string;
  btcAddress: string;
  publicKey: string;
  region?: string;
  version?: string;
}

export interface NetworkOperatorDeannouncedPayload extends BaseEventPayload {
  type: EventType.NETWORK_OPERATOR_DEANNOUNCED;
  operatorId: string;
  reason?: string;
}

export interface NetworkGatewayAnnouncedPayload extends BaseEventPayload {
  type: EventType.NETWORK_GATEWAY_ANNOUNCED;
  gatewayId: string;
  httpUrl: string;
  wsUrl: string;
  torUrl?: string;
  isPublic: boolean;
  operatorId?: string; // Operator vouching for this gateway
  region?: string;
  version?: string;
}

export interface NetworkGatewayDeannouncedPayload extends BaseEventPayload {
  type: EventType.NETWORK_GATEWAY_DEANNOUNCED;
  gatewayId: string;
  reason?: string;
}

export interface NetworkSeedAnnouncedPayload extends BaseEventPayload {
  type: EventType.NETWORK_SEED_ANNOUNCED;
  seedId: string;
  seedType: 'dns' | 'http' | 'ws' | 'tor' | 'ipfs';
  seedValue: string; // domain, URL, or CID
  operatorId: string; // Operator announcing this seed
}

export interface QuorumSignature {
  operatorId: string;
  publicKey: string;
  signature: string;
}

export interface Event {
  eventHash: string;
  prevEventHash: string;
  sequenceNumber: number;
  payload: EventPayload;
  signatures: QuorumSignature[];
  createdAt: number;
}

export interface EventStoreState {
  headHash: string;
  sequenceNumber: number;
  eventCount: number;
  lastCheckpointHash?: string;
  lastCheckpointAt?: number;
}

export interface CheckpointData {
  checkpointRoot: string;
  fromSequence: number;
  toSequence: number;
  eventCount: number;
  merkleRoot: string;
  createdAt: number;
  bitcoinTxid?: string;
  blockHeight?: number;
}
