/**
 * REGULATORY-COMPLIANT ITEM REGISTRY TYPES
 * 
 * This system is a NON-CUSTODIAL REGISTRY of physical item ownership and authenticity.
 * It is NOT a token system, financial platform, or money transmitter.
 * 
 * Key principles:
 * - Item records exist ONLY when physical items exist (1:1 binding)
 * - No pre-creation, no inventory, no supply
 * - Ownership is a state field, not a balance
 * - Payments are peer-to-peer (non-custodial)
 * - System verifies but never touches funds
 */

/**
 * Physical Item Record
 * Created ONLY when a real physical item is manufactured.
 * Cannot exist without a corresponding physical item.
 */
export interface ItemRecord {
  // Unique identifier derived from serial number + metadata
  itemId: string;
  
  // Manufacturer information
  manufacturerId: string;
  manufacturerName: string;

  // Issuer information (manufacturer/authenticator/user)
  issuerRole?: 'manufacturer' | 'authenticator' | 'user';
  issuerAccountId?: string;
  
  // Physical item identification (hashed for privacy)
  serialNumberHash: string;
  
  // Item metadata (hashed, full data stored off-chain)
  metadataHash: string;
  metadata?: {
    itemType: string;
    description: string;
    imageUrl?: string;
    images?: LedgerImage[];
    manufacturingDate: number;
    additionalData?: Record<string, any>;
  };
  
  // Current ownership state (NOT a balance)
  currentOwner: string; // Bitcoin wallet address
  
  // Ownership history (provenance chain)
  ownershipHistory: OwnershipRecord[];
  
  // Authentication attestations (optional third-party verifications)
  authentications: AuthenticationAttestation[];
  
  // Cryptographic signatures
  manufacturerSignature: string;
  operatorQuorumSignatures: string[];
  
  // Timestamps
  registeredAt: number;
  lastUpdatedAt: number;
  
  // Status
  status: 'registered' | 'transferred' | 'authenticated' | 'disputed';

  // Optional per-mint Bitcoin anchor (paid fee tx)
  feeTxid?: string;
  feeBlockHeight?: number;
  feeCommitmentHex?: string;
}

/**
 * Ownership Record
 * Represents a change in ownership state, not a token transfer.
 * Tied to physical item possession.
 */
export interface OwnershipRecord {
  previousOwner: string;
  newOwner: string;
  transferredAt: number;
  
  // Payment verification (non-custodial)
  paymentTxHash?: string; // Bitcoin transaction hash
  paymentVerified: boolean;
  
  // Operator consensus
  operatorSignatures: string[];
  
  // Optional transfer metadata
  transferType: 'sale' | 'gift' | 'warranty_claim' | 'other';
  notes?: string;
}

/**
 * Authentication Attestation
 * Third-party verification of physical item authenticity.
 * Informational only, does not affect ownership.
 */
export interface AuthenticationAttestation {
  attestationId: string;
  authenticatorId: string;
  authenticatorName: string;
  
  // Attestation details
  attestationHash: string;
  issuedAt: number;
  expiresAt?: number;
  
  // Verification result
  isAuthentic: boolean;
  confidence: 'high' | 'medium' | 'low';
  notes?: string;

  images?: LedgerImage[];
  
  // Cryptographic proof
  authenticatorSignature: string;
  operatorQuorumSignatures: string[];

  // Optional per-attestation Bitcoin anchor (paid fee tx)
  feeTxid?: string;
  feeBlockHeight?: number;
  feeCommitmentHex?: string;
}

/**
 * Item Registration Request
 * Manufacturer registers a newly manufactured physical item.
 * Must include proof of physical item existence.
 */
export interface ItemRegistrationRequest {
  manufacturerId: string;
  manufacturerName?: string;
  issuerRole?: 'manufacturer' | 'authenticator' | 'user';
  issuerAccountId?: string;
  serialNumber: string; // Will be hashed
  metadata: {
    itemType: string;
    description: string;
    brand?: string;
    imageUrl?: string;
    images?: LedgerImage[];
    manufacturingDate: number;
    additionalData?: Record<string, any>;
  };
  initialOwner: string; // Usually manufacturer's wallet
  manufacturerSignature: string;

  // Per-mint fee + Bitcoin anchor
  feeQuoteId?: string;
  feeTxid?: string;
  feeCommitmentHex?: string;
  feeBlockHeight?: number;
}

/**
 * Ownership Transfer Request
 * Updates ownership state when physical item changes hands.
 * Requires payment verification (non-custodial).
 */
export interface OwnershipTransferRequest {
  itemId: string;
  currentOwner: string;
  newOwner: string;
  
  // Payment verification (peer-to-peer)
  paymentTxHash: string; // Bitcoin transaction hash
  expectedAmount?: number; // For verification only
  
  // Transfer details
  transferType: 'sale' | 'gift' | 'warranty_claim' | 'other';
  notes?: string;
  
  // Signatures
  currentOwnerSignature: string;
  newOwnerSignature?: string;
}

/**
 * Authentication Request
 * Third-party authenticator verifies physical item.
 */
export interface AuthenticationRequest {
  itemId: string;
  authenticatorId: string;
  serialNumber: string; // To verify against registered hash
  
  // Verification results
  isAuthentic: boolean;
  confidence: 'high' | 'medium' | 'low';
  notes?: string;
  expiresAt?: number;

  images?: LedgerImage[];
  
  authenticatorSignature: string;

  // Per-attestation fee + Bitcoin anchor
  feeQuoteId?: string;
  feeTxid?: string;
  feeCommitmentHex?: string;
  feeBlockHeight?: number;
}

export interface LedgerImage {
  mime: 'image/webp' | 'image/jpeg' | 'image/png';
  dataB64: string;
  sha256Hex: string;
  w: number;
  h: number;
 }

/**
 * Registry Event
 * Immutable record of registry state changes.
 */
export interface RegistryEvent {
  eventId: string;
  eventType: 'ITEM_REGISTERED' | 'OWNERSHIP_TRANSFERRED' | 'ITEM_AUTHENTICATED' | 'ITEM_DISPUTED';
  itemId: string;
  timestamp: number;
  
  // Event-specific data
  data: ItemRegistrationRequest | OwnershipTransferRequest | AuthenticationRequest | any;
  
  // Consensus validation
  operatorSignatures: string[];
  quorumReached: boolean;
  
  // Blockchain anchoring (optional)
  bitcoinTxHash?: string;
  blockHeight?: number;
}

/**
 * Registry Ledger
 * Complete state of all registered items.
 * This is a REGISTRY, not a token ledger.
 */
export interface RegistryLedger {
  // All registered items (indexed by itemId)
  items: Map<string, ItemRecord>;
  
  // Event log (immutable history)
  events: RegistryEvent[];
  
  // Indexes for fast lookup
  itemsByOwner: Map<string, string[]>; // owner -> itemIds
  itemsByManufacturer: Map<string, string[]>; // manufacturerId -> itemIds
  itemsBySerialHash: Map<string, string>; // serialHash -> itemId
  
  // Operator consensus configuration
  operatorId: string;
  operatorPublicKey: string;
  quorumM: number;
  quorumN: number;
  peerOperators: string[];
  
  // Metadata
  lastUpdated: number;
  totalItems: number;
  totalTransfers: number;
}

/**
 * Payment Verification Result
 * Non-custodial verification of peer-to-peer Bitcoin payment.
 * System NEVER touches funds.
 */
export interface PaymentVerification {
  txHash: string;
  verified: boolean;
  amount: number;
  sender: string;
  recipient: string;
  confirmations: number;
  blockHeight?: number;
  timestamp: number;
  
  // Protocol fee verification (paid in same tx via multiple outputs)
  protocolFeeOutput?: {
    address: string;
    amount: number;
    verified: boolean;
  };
}

/**
 * Registry Statistics
 */
export interface RegistryStats {
  totalItems: number;
  totalManufacturers: number;
  totalOwners: number;
  totalTransfers: number;
  totalAuthentications: number;
  itemsByStatus: Record<string, number>;
  recentActivity: RegistryEvent[];
}
