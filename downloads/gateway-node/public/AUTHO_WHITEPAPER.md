# Autho: A Bitcoin-Native Protocol for Physical Asset Ownership, Verification, and Commerce

**Version 1.0 | February 2026**

---

## Abstract

Counterfeiting is a $2 trillion annual global problem. Existing solutions rely on centralized databases controlled by single corporations, creating fragile systems that can be shut down, acquired, or corrupted. Autho is an open-source, non-custodial protocol that binds physical items to cryptographic ownership records on a federated append-only ledger, anchored periodically to the Bitcoin blockchain. The protocol enables manufacturers to register products, authenticators to independently verify them, retailers to consign and sell them, and buyers to verify provenance and transfer ownership -- all without any central authority, custodian, or trusted intermediary. Payments settle peer-to-peer in Bitcoin. Communication between participants is end-to-end encrypted with forward secrecy. Anyone can participate by running a gateway node on commodity hardware. The protocol is designed to operate for 250+ years as a public good.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Principles](#2-design-principles)
3. [Network Architecture](#3-network-architecture)
4. [The Ownership Ledger](#4-the-ownership-ledger)
5. [User Roles and Workflows](#5-user-roles-and-workflows)
6. [Consignment and Commerce](#6-consignment-and-commerce)
7. [Encrypted Messaging](#7-encrypted-messaging)
8. [Security Model](#8-security-model)
9. [Gateway Nodes](#9-gateway-nodes)
10. [Economics and Fee Structure](#10-economics-and-fee-structure)
11. [Governance](#11-governance)
12. [Long-Term Sustainability](#12-long-term-sustainability)
13. [Conclusion](#13-conclusion)

---

## 1. Introduction

### 1.1 The Problem

The global counterfeit goods market is estimated at $2 trillion annually, affecting industries from luxury fashion and watches to electronics, pharmaceuticals, and collectibles. Consumers cannot reliably verify whether a product is genuine, and sellers cannot prove provenance in a way that is independently verifiable.

Current anti-counterfeiting solutions suffer from fundamental weaknesses:

- **Centralized databases** controlled by a single company create a single point of failure and a single point of trust.
- **Proprietary systems** lock manufacturers into vendor relationships and create data silos.
- **No interoperability** between brands, retailers, and verification services.
- **No ownership transfer** -- existing systems track products, not ownership.
- **No integrated commerce** -- verification is disconnected from payment and transfer.

### 1.2 The Solution

Autho is an open-source protocol that solves these problems by combining:

1. **Cryptographic ownership records** -- each physical item is bound to a unique record on an append-only ledger, signed by the manufacturer and validated by a federated quorum of operators.
2. **Bitcoin-anchored provenance** -- the ledger's Merkle root is periodically committed to the Bitcoin blockchain, inheriting Bitcoin's immutability and timestamping guarantees.
3. **Non-custodial design** -- users hold their own keys, sign their own transactions, and send payments directly to each other. The protocol never touches funds.
4. **Decentralized infrastructure** -- anyone can run an operator node (validates and co-signs events) or a gateway node (provides API access and serves applications).
5. **Integrated end-to-end encrypted messaging** -- participants can communicate securely with forward secrecy, sealed sender, and replay protection.

---

## 2. Design Principles

### 2.1 Bitcoin is the Only Money

All payments in Autho settle in Bitcoin (on-chain or Lightning). There is no protocol token, no stablecoin dependency, and no fiat integration at the protocol level. Bitcoin was chosen for its censorship resistance, global accessibility, and alignment with the protocol's non-custodial philosophy.

### 2.2 No Blockchain Bloat

Autho does not produce blocks continuously. It maintains an append-only event log validated by a federated operator quorum, and periodically anchors a Merkle root to Bitcoin. This minimizes on-chain footprint while preserving cryptographic guarantees.

### 2.3 Deterministic and Final

Ownership transfers in Autho are irreversible, like wire transfers. There is no arbitration, no chargebacks, and no dispute resolution by committee. The protocol enforces rules through cryptographic signatures and state-machine constraints. Math, not humans, resolves disputes.

### 2.4 Federated Trust with Client-Side Verification

Security does not rely on trusting any single operator. An M-of-N quorum (e.g., 2/3 of active operators) must co-sign every event. Clients independently verify all signatures, state transitions, and quorum requirements. A user who runs their own gateway node trusts no one but the mathematics.

### 2.5 Non-Custodial

The protocol never holds, controls, or has access to user funds, private keys, or physical items. Users authenticate via Bitcoin-compatible key pairs (secp256k1). Operators validate signatures and maintain the ledger -- they never touch money or assets.

**Non-custody has a critical legal implication:** because Autho never takes custody of user assets, it is software -- not a financial service, not a money transmitter, and not subject to KYC/AML requirements. Like Bitcoin Core, it is a protocol, not a company.

---

## 3. Network Architecture

Autho employs a three-tier architecture:

```
                    ┌────────────────────────────┐
                    │     BITCOIN BLOCKCHAIN      │
                    │  (Periodic Merkle Anchors)  │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │   OPERATOR NETWORK (M-of-N) │
                    │                              │
                    │  ┌────────┐   ┌────────┐    │
                    │  │ Op. A  │◄─►│ Op. B  │    │
                    │  └───┬────┘   └────┬───┘    │
                    │      │             │         │
                    │  ┌───┴────┐   ┌────┴───┐    │
                    │  │ Op. C  │◄─►│ Op. D  │    │
                    │  └────────┘   └────────┘    │
                    └──────┬──────────────┬───────┘
                           │              │
              ┌────────────▼──┐    ┌──────▼────────┐
              │  Gateway Node │    │  Gateway Node  │
              │  (Shop/User)  │    │   (Personal)   │
              └───────┬───────┘    └───────┬────────┘
                      │                    │
              ┌───────▼───────┐    ┌───────▼────────┐
              │   End Users   │    │   End Users    │
              │ (Buyers, etc) │    │  (Collectors)  │
              └───────────────┘    └────────────────┘
```

### 3.1 Tier 1: Bitcoin Blockchain

The Bitcoin blockchain serves as an immutable timestamp and integrity anchor. Autho periodically commits a Merkle root of its event log to a Bitcoin transaction. This means:

- Once anchored, the event history inherits Bitcoin's security (proof-of-work, global consensus).
- Anyone can independently verify that the ledger has not been tampered with by checking the anchor transaction.
- Even if every operator went offline, the anchored state can be used to bootstrap a new network.

### 3.2 Tier 2: Operator Network

Operators are independent entities that run the Autho node software. They:

- **Validate events** -- check that every submitted event (item registration, ownership transfer, etc.) conforms to the protocol's state machine rules.
- **Co-sign events** -- provide their cryptographic signature as part of the M-of-N quorum.
- **Maintain the ledger** -- store the full append-only event log and serve it to gateways and clients.
- **Earn fees** -- receive a share of the protocol's title-update fee, paid directly in Bitcoin.

Operators connect to each other via WebSocket for real-time state synchronization. If the main seed node goes offline, operators can sync among themselves, elect a backup leader, and continue processing events -- ensuring the network survives even extended outages of any single node.

**Becoming an operator** requires:
1. Downloading and running the open-source operator node software.
2. Demonstrating 60+ days of uptime.
3. Receiving a 2/3 approval vote from existing active operators.

There is no fee, no registration, and no permission required from any central authority.

### 3.3 Tier 3: Gateway Nodes

Gateway nodes are lightweight access points that anyone can run. They:

- **Connect to multiple operators** and verify consensus (2/3 agreement on ledger state).
- **Cache the ledger locally** for fast reads.
- **Serve the web application** so end users can interact with the protocol via a browser.
- **Proxy API requests** to operators for write operations (registrations, transfers, etc.).
- **Relay encrypted messages** between users.
- **Provide a public URL** via automatic Cloudflare tunnel (no port forwarding or static IP required).

Gateway nodes run on any machine with Node.js installed -- a laptop, a Raspberry Pi, a cloud VM, or a shop's point-of-sale system. Setup takes under 5 minutes (see Section 9).

---

## 4. The Ownership Ledger

### 4.1 Append-Only Event Log

All state changes in Autho are represented as cryptographically signed events appended to an ordered log. Each event contains:

| Field | Description |
|-------|-------------|
| `eventId` | SHA-256 hash of the canonical event serialization |
| `eventType` | The type of state transition (e.g., ITEM_MINTED, ITEM_SETTLED) |
| `itemId` | The item this event affects |
| `height` | Monotonically increasing sequence number |
| `previousEventHash` | Hash of the preceding event (hash-chain integrity) |
| `timestamp` | Unix timestamp |
| `actorSignature` | Signature of the actor performing the action |
| `operatorSignatures` | M-of-N quorum signatures validating the event |

The hash-chain structure ensures that any tampering with historical events would invalidate all subsequent hashes, making forgery detectable.

### 4.2 Item Lifecycle State Machine

Every item exists in exactly one state at any time. The protocol enforces strict transition rules:

```
  MINTED ──────► ACTIVE_HELD ──────► LOCKED_IN_ESCROW
    │                │                     │
    │                │                     ├──► ACTIVE_HELD (settled, new owner)
    │                │                     └──► ACTIVE_HELD (expired, same owner)
    │                │
    │                ├──► IN_CUSTODY (repair/recall)
    │                │         │
    │                │         └──► ACTIVE_HELD (returned)
    │                │
    ▼                ▼
  BURNED ◄───── BURNED (terminal)
```

- **MINTED**: Item registered by a verified manufacturer. Exists on the ledger but not yet assigned to an owner.
- **ACTIVE_HELD**: Owned by a specific Bitcoin address. Can be listed for sale, sent to custody, or burned.
- **LOCKED_IN_ESCROW**: A sale is in progress. The item cannot be transferred to anyone else until payment settles or the lock expires.
- **IN_CUSTODY**: The item is with a manufacturer or service center (e.g., for repair or authentication inspection).
- **BURNED**: Terminal state. The item has been destroyed, recalled, or flagged as counterfeit.

### 4.3 Item Records

Each item on the ledger is bound to its physical counterpart through:

- **Serial number hash** -- the physical serial number is hashed for privacy; the full number is stored off-chain.
- **Metadata hash** -- item type, description, images, and manufacturing date are hashed and stored.
- **Serial authority** -- the entity that issued the serial number (usually the manufacturer; for unbranded collectibles, an authenticator can serve as serial authority by physically marking the item).
- **Ownership history** -- the complete provenance chain from manufacture to current owner.

The combination of `(serialAuthorityAccountId, serialNumber)` is enforced as unique across the ledger, preventing duplicate registration of the same physical item.

---

## 5. User Roles and Workflows

### 5.1 Manufacturers

Manufacturers register on the protocol and mint items:

1. **Register**: Create an account with a Bitcoin-compatible key pair. Provide company details and pay a one-time registration fee in Bitcoin.
2. **Mint items**: For each physical product, submit an ITEM_MINTED event containing the item's metadata hash and serial number hash. The operator quorum validates and co-signs.
3. **Assign ownership**: Transfer the item to its first owner (a retailer, a customer, etc.) via an ITEM_ASSIGNED event.

Manufacturers can also manage product recalls (ITEM_BURNED), custody transfers for repairs, and view analytics on their registered items.

### 5.2 Authenticators

Authenticators are independent third-party experts who examine and attest to items:

1. **Register**: Create an authenticator account specifying a specialization (e.g., "Luxury Watches", "Vintage Sneakers").
2. **Inspect**: Receive items for physical inspection (or inspect remotely via photos/video).
3. **Attest**: Issue an authentication attestation with a confidence score (0-100), scope of verification, and optional expiration.

Attestations are informational only. They do not grant ownership, are not transferable, and are optional. Items function normally without attestations. However, items with high-confidence attestations from reputable authenticators carry more buyer confidence.

For items without manufacturer serial numbers (e.g., vintage collectibles), an authenticator can serve as the **serial authority** by physically marking or etching the item and issuing a serial number, creating a verifiable provenance record where none existed before.

### 5.3 Retailers

Retailers can list and sell items through the consignment system:

1. **Receive consignments**: Manufacturers or owners consign items to the retailer for sale.
2. **Set pricing**: Agree on asking price with the consigner.
3. **Manage storefront**: List items with descriptions, images, and pricing.
4. **Process sales**: When a buyer purchases, the retailer confirms receipt of payment and initiates ownership transfer.

Retailers are rated by buyers (1-5 stars) and subject to community governance. Consistently poor ratings can trigger automated review proposals.

### 5.4 Buyers / Collectors

Buyers interact with the protocol to verify and purchase items:

1. **Verify**: Scan an item's QR code to view its full provenance chain -- manufacturer, ownership history, authentication attestations, and current state.
2. **Purchase**: Send Bitcoin directly to the seller's address. The protocol verifies payment on the Bitcoin blockchain and settles the ownership transfer.
3. **Own**: The item is now registered to the buyer's Bitcoin address. They can hold it, resell it, or consign it.
4. **Communicate**: Message sellers, authenticators, or manufacturers through the protocol's encrypted messaging system.

---

## 6. Consignment and Commerce

### 6.1 Consignment Flow

Autho includes a built-in consignment system for retailers:

```
Owner ──consign──► Retailer ──list──► Buyer
  │                    │                 │
  │                    │            pays BTC (P2P)
  │                    │                 │
  │               confirms payment ◄────┘
  │                    │
  └── ownership transferred to buyer ◄──┘
```

1. **Owner creates consignment** specifying the item, the retailer, and the agreed price.
2. **Retailer confirms** receipt of the physical item.
3. **Retailer lists** the item on their storefront with photos and pricing.
4. **Buyer pays** in Bitcoin directly to the seller's address.
5. **Retailer confirms** payment receipt.
6. **Ownership transfers** automatically to the buyer on the ledger.

### 6.2 Escrow and Settlement

For direct sales (not through a retailer), the protocol uses a time-locked escrow mechanism:

1. **Seller lists** the item with a price and expiry time.
2. **Buyer locks** the item by submitting an ITEM_LOCKED event (state transitions to LOCKED_IN_ESCROW).
3. **Buyer pays** Bitcoin to the seller's address.
4. **Protocol verifies** payment on the Bitcoin blockchain.
5. **Settlement** occurs automatically (ITEM_SETTLED, ownership transfers to buyer).
6. **If payment doesn't arrive** before expiry, the lock releases automatically (ITEM_UNLOCKED_EXPIRED, item returns to seller).

There is no arbitration, no intermediary, and no human judgment. The state machine enforces the rules.

---

## 7. Encrypted Messaging

Autho includes a fully integrated encrypted messaging system that meets or exceeds the security properties of Signal.

### 7.1 Encryption Properties

| Property | Implementation |
|----------|---------------|
| **End-to-end encryption** | All messages encrypted client-side before transmission |
| **Forward secrecy** | Per-message ephemeral Curve25519 keys (v3 envelope) |
| **Sealed sender** | Sender identity is inside the encrypted payload, invisible to the server |
| **Replay protection** | Per-message nonces + timestamp validation |
| **Message padding** | Uniform 1KB padding prevents traffic analysis |
| **Key transparency** | SHA-256 key hashes published for independent verification |
| **Safety numbers** | Users can verify each other's keys via QR code or numeric comparison |
| **Disappearing messages** | Per-conversation timers for automatic message expiration |
| **Metadata protection** | Randomized polling jitter, uniform message sizes |

### 7.2 Voice and Video Calls

The messaging system supports real-time voice and video calls using WebRTC with end-to-end encryption. Call signaling is relayed through the operator network with multi-hop capability:

```
Gateway A → Operator X → Operator Y → Gateway B
```

This ensures any user can reach any other user regardless of which gateway or operator they are connected to, with a maximum of 3 hops to prevent routing loops.

### 7.3 Group Messaging

Group conversations use an MLS-lite (Messaging Layer Security) protocol with shared epoch keys, O(1) encryption cost per message, and epoch rotation when group membership changes.

### 7.4 No Surveillance

The protocol includes **zero moderation or surveillance features** by design. There is no message scanning, no content filtering, no backdoors, and no ability for operators or gateway runners to read user messages. Privacy is a fundamental right, not a feature that can be toggled off.

---

## 8. Security Model

### 8.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Counterfeit item registration** | Only verified manufacturers can mint. Manufacturer public key verified on every scan. |
| **Cloned QR codes** | Ownership proof requires live wallet signature with timestamp and nonce (5-minute validity). |
| **Double-selling** | State machine enforces single active escrow lock. Operators reject conflicting locks. |
| **Rogue operator** | M-of-N quorum required. No single operator can forge state. |
| **Network partition** | Operators sync among themselves. Gateway nodes connect to multiple operators. |
| **Bitcoin anchor tampering** | Merkle root on Bitcoin blockchain is immutable after 6+ confirmations. |
| **Message interception** | End-to-end encryption with forward secrecy. Server never sees plaintext. |
| **Key compromise** | Per-message ephemeral keys limit exposure. Key transparency enables detection. |

### 8.2 Cryptographic Primitives

- **Identity**: secp256k1 key pairs (Bitcoin-compatible)
- **Event signing**: ECDSA signatures
- **Hashing**: SHA-256 (events, items, serial numbers, metadata)
- **Messaging encryption**: Curve25519 + XSalsa20-Poly1305 (NaCl box) with ephemeral keys
- **Key derivation**: Deterministic keys from wallet seed via SHA-256 (stateless, works across nodes)
- **Merkle trees**: For Bitcoin anchoring and state integrity proofs

### 8.3 Client-Side Verification

Every client (including gateway nodes) independently verifies:

1. All operator signatures meet the M-of-N quorum threshold.
2. All state transitions conform to the state machine rules.
3. All actor signatures are valid for the claimed operation.
4. The hash chain is unbroken from genesis to the current event.
5. Bitcoin anchors match the claimed ledger state.

This means a user running their own gateway node achieves **zero-trust verification** -- they do not need to trust any operator, any server, or any third party.

---

## 9. Gateway Nodes

### 9.1 What is a Gateway Node?

A gateway node is a lightweight server that connects to the Autho operator network, syncs the ledger, serves the web application, and provides API access for end users. It is the primary way users interact with the protocol.

**Think of it like this:** operators are the backbone of the network (like Bitcoin miners). Gateways are the access points (like running your own Bitcoin full node with a wallet UI).

### 9.2 Why Run a Gateway?

- **Shops**: Run a gateway to provide your customers with item verification and purchasing directly from your storefront.
- **Collectors**: Run a gateway to verify your collection's provenance without relying on anyone else's server.
- **Communities**: Run a gateway to give your community private, encrypted messaging and item verification.
- **Privacy**: A gateway gives you full client-side verification. You trust math, not servers.

### 9.3 Requirements

- **Node.js 18+** (free, open-source, runs on Windows/Mac/Linux)
- **Any machine**: Laptop, desktop, Raspberry Pi, cloud VM, or dedicated server
- **Internet connection**: Needed to sync with operators
- **No port forwarding required**: Gateway automatically creates a public URL via Cloudflare tunnel

### 9.4 Installation (Under 5 Minutes)

#### Windows

1. Download the gateway package from any Autho node (main node or operator).
2. Double-click `Install-Autho-Gateway.bat`.
3. The installer will:
   - Verify Node.js is installed
   - Install dependencies
   - Generate your gateway identity
   - Create a `gateway.env` configuration file
   - Start the gateway
4. Visit `http://localhost:3001` in your browser.

#### Mac / Linux

```bash
# Download and extract the gateway package
# Then run:
node gateway-package.js
```

#### One-Line Install (PowerShell)

```powershell
irm https://your-autho-node.com/downloads/quick-install.ps1 | iex
```

### 9.5 Configuration

The `gateway.env` file controls gateway behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_PORT` | `3001` | Local HTTP port |
| `GATEWAY_TUNNEL_MODE` | `quick` | `quick` = random Cloudflare URL (instant), `cloudflare_named` = stable custom domain |
| `CLOUDFLARED_TOKEN` | (none) | Required only for named tunnel mode |
| `GATEWAY_PUBLIC_URL` | (auto) | Your gateway's public URL |

**Quick mode** (default): The gateway gets a random `*.trycloudflare.com` URL that changes on restart. Perfect for testing or personal use.

**Named tunnel mode**: Configure a Cloudflare tunnel token and custom domain for a stable, permanent URL. Ideal for shops or public-facing gateways.

### 9.6 How It Works

Once running, the gateway:

1. **Connects** to known seed/operator nodes via WebSocket.
2. **Discovers** all active operators on the network.
3. **Syncs** the full ledger state (items, accounts, events).
4. **Verifies** consensus -- checks that 2/3 of operators agree on the current state.
5. **Serves** the web application at `http://localhost:3001`.
6. **Publishes** a public URL via Cloudflare tunnel.
7. **Relays** API requests and encrypted messages between users and operators.

The gateway stays in sync via real-time WebSocket updates from operators. If an operator goes down, the gateway automatically failovers to other available operators.

---

## 10. Economics and Fee Structure

### 10.1 Protocol Fees

Autho charges a small fee on title-update events (ownership transfers). This fee is the protocol's only revenue source.

| Fee Type | Amount | Trigger |
|----------|--------|---------|
| Title update | 1% of sale price | Ownership transfer (ITEM_SETTLED) |
| Registration | Fixed BTC amount | Manufacturer registration |
| Minting | Fixed BTC amount | Item creation |

### 10.2 Fee Distribution

```
Total Fee (1% of sale)
  ├── Sponsor allocation (protocol-defined)
  └── Operator allocation (protocol-defined)
```

All fees are paid **directly in Bitcoin** to the recipient's address. There is no intermediary, no escrow, and no custodial fee processing. The sponsor address is a fixed protocol constant on mainnet and is not changeable by governance.

### 10.3 Operator Economics

Operators earn their protocol-defined fee share for validation and network participation. As the network processes more transactions, operator revenue grows. This creates a self-sustaining economic model:

- **More transactions** → more fees → incentive to maintain uptime
- **Bad operators** → voted out → lose fee income
- **No subsidy required** → protocol is self-funding from day one

---

## 11. Governance

### 11.1 No Foundation, No Company

Autho is not a company. There is no legal entity, no board of directors, no CEO, no treasury, and no employees. Like Bitcoin, it is an open-source protocol maintained by its community.

**Why no foundation?**

A legal entity creates an attack surface:
- Governments can subpoena a foundation.
- Lawsuits can target a company.
- Regulators can force compliance on a registered entity.

With no entity, there is no one to subpoena, sue, or regulate. The protocol continues regardless.

### 11.2 Autho Improvement Proposals (AIPs)

Protocol changes follow the AIP process:

1. **Proposal**: Anyone submits an AIP via GitHub.
2. **Discussion**: Community reviews and debates.
3. **Implementation**: Developers write and review the code.
4. **Signaling**: Operators signal readiness by upgrading their node version.
5. **Activation**: When 95% of operators signal support, the change activates.

No one can force an upgrade. Operators choose which version to run. The protocol evolves through consensus, not decree.

### 11.3 Operator Governance

Active operators vote on network matters:

- **Admitting new operators**: Requires 2/3 approval from existing operators.
- **Removing bad actors**: Automated proposals triggered by community reports (e.g., 3 one-star reviews within 30 days). Removal requires majority vote.
- **Protocol upgrades**: 95% signaling threshold for activation.

---

## 12. Long-Term Sustainability

### 12.1 The 250-Year Design

Autho is designed with a multi-generational time horizon. Physical items -- watches, art, collectibles, real estate deeds -- can outlive their owners by centuries. The protocol that tracks their provenance must be equally durable.

### 12.2 Durability Mechanisms

| Mechanism | Purpose |
|-----------|---------|
| **Bitcoin anchoring** | Ledger state preserved on the most durable blockchain in existence |
| **Operator redundancy** | M-of-N quorum tolerates operator failure. Network survives with M operators. |
| **Operator-to-operator sync** | Operators sync among themselves when main seed is offline |
| **Open-source code** | Anyone can fork, modify, and run the protocol |
| **No central dependency** | No company, no cloud provider, no domain registrar is a single point of failure |
| **Self-sustaining economics** | Operators earn fees; no external funding needed |
| **Permissionless participation** | New operators and gateways can join at any time |
| **Quantum resistance** | Post-quantum cryptographic primitives implemented (ML-KEM-768), ready for activation |

### 12.3 Failure Scenarios and Recovery

**All operators go offline**: The last Bitcoin-anchored state is preserved on the Bitcoin blockchain. When new operators come online, they can bootstrap from the anchor and rebuild the network.

**Main seed node offline for years**: Operators continue operating among themselves via peer-to-peer sync, leader election, and local consensus. The network degrades gracefully, not catastrophically.

**Cryptographic algorithm broken**: The AIP process allows upgrading to new algorithms. Quantum-resistant primitives (ML-KEM-768 + Curve25519 hybrid) are already implemented and can be activated by operator consensus.

---

## 13. Conclusion

Autho addresses a fundamental gap in the physical world: the absence of a trustworthy, decentralized, and durable system for proving what is real and who owns it. By combining Bitcoin-native economics, federated consensus, non-custodial design, and Signal-grade encrypted communication, Autho creates a protocol that is:

- **Trustworthy** -- cryptographic proofs, not corporate promises.
- **Unstoppable** -- no central entity to shut down, acquire, or coerce.
- **Accessible** -- anyone can run a gateway on a $35 Raspberry Pi.
- **Private** -- end-to-end encryption, no surveillance, no data collection.
- **Durable** -- designed to outlast any company, government, or generation.

The protocol is live, open-source, and available at [github.com/Pink-Mahi/autho](https://github.com/Pink-Mahi/autho).

---

## Appendix A: Technical Specifications

| Component | Specification |
|-----------|--------------|
| Identity | secp256k1 key pairs (Bitcoin-compatible) |
| Event hashing | SHA-256 with canonical JSON serialization |
| Consensus | M-of-N federated quorum (default: 2/3 of active operators) |
| Messaging encryption | Curve25519 ephemeral keys + XSalsa20-Poly1305 (v3 envelope) |
| Post-quantum (ready) | ML-KEM-768 + Curve25519 + AES-256-GCM hybrid (v4 envelope) |
| Bitcoin anchoring | Merkle root committed to OP_RETURN output |
| Transport | HTTPS + WebSocket (TLS) |
| Gateway tunnel | Cloudflare Argo / trycloudflare |
| Minimum Node.js | v18+ |

## Appendix B: Repositories

| Repository | Purpose |
|------------|---------|
| [Pink-Mahi/autho](https://github.com/Pink-Mahi/autho) | Main node + gateway download packages |
| [Pink-Mahi/autho_node](https://github.com/Pink-Mahi/autho_node) | Operator node deployment |

## Appendix C: Glossary

| Term | Definition |
|------|-----------|
| **Operator** | A node that validates events, co-signs with quorum, and maintains the ledger |
| **Gateway** | A lightweight node that syncs the ledger, verifies consensus, and serves the web UI |
| **Event** | A cryptographically signed state transition on the append-only ledger |
| **Quorum** | The minimum number of operator signatures required to validate an event (M-of-N) |
| **Anchor** | A Bitcoin transaction containing the Merkle root of the event log |
| **AIP** | Autho Improvement Proposal -- the process for proposing protocol changes |
| **Attestation** | An authenticator's signed statement about an item's genuineness |
| **Consignment** | A retailer arrangement where items are listed for sale on behalf of the owner |
| **Sealed sender** | An encryption scheme where the sender's identity is hidden inside the ciphertext |
| **Forward secrecy** | A property ensuring that compromising a long-term key does not compromise past messages |

---

*Autho is open-source software released under the MIT License. This document is provided for informational purposes. Autho is not a company, financial service, or custodian.*
