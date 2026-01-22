# Event Store - Decentralized Registry Foundation

## Overview

The Event Store is the foundation of the decentralized registry system. It implements an **append-only event log with hash chains** that allows multiple nodes to maintain a consistent view of the registry state without a central authority.

## Key Concepts

### 1. Append-Only Event Log
- Events are never modified or deleted
- New events are always appended to the end
- Each event has a unique sequence number
- Full history is preserved forever

### 2. Content-Addressed Storage
- Each event has a hash calculated from its content
- Events are stored by their hash (like Git commits)
- Hash = `SHA256(prevHash + sequence + payload + signatures + timestamp)`

### 3. Hash Chain Linking
- Each event references the previous event's hash
- Creates an immutable chain like a blockchain
- Tampering with any event breaks the chain
- Easy to verify integrity

### 4. State Reconstruction
- Current state is built by replaying all events
- Any node can rebuild the full state from the event log
- No need to trust a central database
- Deterministic: same events = same state

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Event Store                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Event 1 ──> Event 2 ──> Event 3 ──> Event 4 ──> ...  │
│    │           │           │           │                │
│    └───────────┴───────────┴───────────┘                │
│              Hash Chain                                  │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                   State Builder                         │
│                                                         │
│  Replays events to build current state:                │
│  - Items registry                                       │
│  - Ownership mapping                                    │
│  - Settlement status                                    │
│  - Operator network                                     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Event Types

### Item Lifecycle
- `ITEM_REGISTERED` - New item added to registry
- `ITEM_METADATA_UPDATED` - Item information updated

### Ownership
- `OWNERSHIP_TRANSFERRED` - Item ownership changed
- `OWNERSHIP_CLAIMED` - Ownership claim made

### Settlement
- `SETTLEMENT_INITIATED` - Escrow settlement started
- `SETTLEMENT_COMPLETED` - Payment confirmed, ownership transferred
- `SETTLEMENT_FAILED` - Settlement cancelled/failed

### Operator Network
- `OPERATOR_CANDIDATE_REQUESTED` - New operator application
- `OPERATOR_CANDIDATE_VOTE` - Vote on candidate
- `OPERATOR_ADMITTED` - Candidate accepted
- `OPERATOR_REJECTED` - Candidate rejected
- `OPERATOR_REMOVED` - Operator removed from network

### Bitcoin Anchoring
- `ANCHOR_COMMITTED` - Checkpoint anchored to Bitcoin
- `CHECKPOINT_CREATED` - Merkle root checkpoint created

## Usage Example

```typescript
import { EventStore, StateBuilder, EventType } from './event-store';

// Initialize
const eventStore = new EventStore('./data/event-store');
const stateBuilder = new StateBuilder(eventStore);

// Append an event
const event = await eventStore.appendEvent({
  type: EventType.ITEM_REGISTERED,
  timestamp: Date.now(),
  nonce: generateNonce(),
  itemId: 'item-001',
  manufacturerId: 'mfr-001',
  serialNumber: 'SN123456',
  metadata: { name: 'Luxury Watch' },
  initialOwner: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
}, []);

// Build current state
const state = await stateBuilder.buildState();
console.log(`Total items: ${state.items.size}`);

// Verify integrity
const isValid = await eventStore.verifyHashChain();
console.log(`Chain valid: ${isValid}`);

// Create checkpoint for Bitcoin anchoring
const checkpoint = await eventStore.createCheckpoint();
console.log(`Checkpoint: ${checkpoint.checkpointRoot}`);
```

## Data Storage

Events are stored in the file system:

```
operator-data/
├── events/
│   ├── abc123...def.json  (event by hash)
│   ├── def456...ghi.json
│   └── ...
├── event-store-state.json (current head/sequence)
└── checkpoint-xyz789.json (checkpoints)
```

## Benefits

### Decentralization
- No single point of failure
- Any node can verify the full history
- Nodes can sync by exchanging events
- No central database required

### Immutability
- Events cannot be changed once written
- Hash chain prevents tampering
- Full audit trail preserved
- Cryptographically verifiable

### Transparency
- All changes are recorded as events
- Complete history is public
- Anyone can verify state transitions
- No hidden modifications

### Resilience
- Nodes can go offline and catch up
- Multiple nodes provide redundancy
- Bitcoin anchoring adds extra security
- Network continues with any active nodes

## Next Steps

1. **Bitcoin Anchoring** - Periodic checkpoints to Bitcoin blockchain
2. **P2P Replication** - Gossip protocol for event distribution
3. **Quorum Signing** - M-of-K signatures for state transitions
4. **Gateway Nodes** - Read-only replication for public access

## Running the Demo

```bash
npm run build
ts-node examples/event-store-demo.ts
```

This will demonstrate:
- Creating events with hash chains
- Verifying chain integrity
- Building state from events
- Creating checkpoints
