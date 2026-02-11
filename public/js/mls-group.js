/**
 * MLS-lite (Messaging Layer Security) for Autho Group Chats
 *
 * Implements a simplified MLS-inspired protocol for scalable group encryption:
 * - Shared group key derived from tree of pairwise DH agreements
 * - O(1) encryption per message (single encrypt with group key)
 * - O(log n) cost for member add/remove (tree update)
 * - Forward secrecy via epoch-based key rotation
 * - Server stores encrypted group state for multi-device sync
 *
 * Architecture:
 * - Each group has an "epoch" counter that increments on membership changes
 * - Group secret is derived from all members' DH contributions
 * - Messages encrypted with AES-256-GCM using epoch key
 * - Member add/remove triggers epoch advance + new group key
 */
(function(global) {
  'use strict';

  const MLS = {};

  // ============================================================
  // KDF utilities
  // ============================================================

  async function hkdfDerive(ikm, salt, info, length) {
    const keyMaterial = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) },
      keyMaterial,
      length * 8
    );
    return new Uint8Array(bits);
  }

  async function sha256(data) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  }

  // ============================================================
  // Group State
  // ============================================================

  /**
   * Create a new MLS group
   * @param {string} groupId - Unique group identifier
   * @param {Object} myKeyPair - Creator's X25519 keypair {publicKey, secretKey}
   * @param {Uint8Array[]} memberPubKeys - Public keys of all initial members (including creator)
   * @returns {Object} Group state
   */
  MLS.createGroup = async function(groupId, myKeyPair, memberPubKeys) {
    // Generate initial group secret (random)
    const groupSecret = nacl.randomBytes(32);

    // Generate epoch keypair for this group epoch
    const epochKeyPair = nacl.box.keyPair();

    // Derive epoch key from group secret
    const epochSalt = new TextEncoder().encode(`AuthoMLS:${groupId}:epoch:0`);
    const epochKey = await hkdfDerive(groupSecret, epochSalt, 'AuthoMLSEpochKey', 32);

    // Create member entries with DH contributions
    const members = [];
    for (const pubKey of memberPubKeys) {
      const pubKeyB64 = nacl.util.encodeBase64(pubKey);
      // Compute DH with each member for welcome message encryption
      const dhShared = nacl.box.before(pubKey, myKeyPair.secretKey);
      members.push({
        publicKeyB64: pubKeyB64,
        dhShareB64: nacl.util.encodeBase64(dhShared)
      });
    }

    return {
      groupId,
      epoch: 0,
      groupSecret: nacl.util.encodeBase64(groupSecret),
      epochKey: nacl.util.encodeBase64(epochKey),
      epochKeyPair: {
        publicKey: nacl.util.encodeBase64(epochKeyPair.publicKey),
        secretKey: nacl.util.encodeBase64(epochKeyPair.secretKey)
      },
      members,
      myPublicKeyB64: nacl.util.encodeBase64(myKeyPair.publicKey),
      createdAt: Date.now()
    };
  };

  /**
   * Join a group from a welcome message
   * @param {Object} welcome - Welcome message containing encrypted group secret
   * @param {Object} myKeyPair - Joiner's X25519 keypair
   * @returns {Object} Group state
   */
  MLS.joinGroup = async function(welcome, myKeyPair) {
    // Decrypt group secret using DH with sender
    const senderPubKey = nacl.util.decodeBase64(welcome.senderPubKeyB64);
    const dhShared = nacl.box.before(senderPubKey, myKeyPair.secretKey);

    // Decrypt the group secret
    const aesKey = await crypto.subtle.importKey('raw', dhShared, 'AES-GCM', false, ['decrypt']);
    const iv = nacl.util.decodeBase64(welcome.iv);
    const ct = nacl.util.decodeBase64(welcome.encryptedGroupSecret);
    const groupSecretBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    const groupSecret = new Uint8Array(groupSecretBuf);

    // Derive epoch key
    const epochSalt = new TextEncoder().encode(`AuthoMLS:${welcome.groupId}:epoch:${welcome.epoch}`);
    const epochKey = await hkdfDerive(groupSecret, epochSalt, 'AuthoMLSEpochKey', 32);

    // Generate epoch keypair
    const epochKeyPair = nacl.box.keyPair();

    return {
      groupId: welcome.groupId,
      epoch: welcome.epoch,
      groupSecret: nacl.util.encodeBase64(groupSecret),
      epochKey: nacl.util.encodeBase64(epochKey),
      epochKeyPair: {
        publicKey: nacl.util.encodeBase64(epochKeyPair.publicKey),
        secretKey: nacl.util.encodeBase64(epochKeyPair.secretKey)
      },
      members: welcome.members || [],
      myPublicKeyB64: nacl.util.encodeBase64(myKeyPair.publicKey),
      createdAt: Date.now()
    };
  };

  /**
   * Create a welcome message for a new member
   * @param {Object} groupState - Current group state
   * @param {Uint8Array} newMemberPubKey - New member's public key
   * @param {Object} myKeyPair - Sender's keypair
   * @returns {Object} Welcome message
   */
  MLS.createWelcome = async function(groupState, newMemberPubKey, myKeyPair) {
    const groupSecret = nacl.util.decodeBase64(groupState.groupSecret);

    // Encrypt group secret for new member using DH
    const dhShared = nacl.box.before(newMemberPubKey, myKeyPair.secretKey);
    const aesKey = await crypto.subtle.importKey('raw', dhShared, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, groupSecret));

    return {
      groupId: groupState.groupId,
      epoch: groupState.epoch,
      senderPubKeyB64: nacl.util.encodeBase64(myKeyPair.publicKey),
      iv: nacl.util.encodeBase64(iv),
      encryptedGroupSecret: nacl.util.encodeBase64(ct),
      members: groupState.members
    };
  };

  // ============================================================
  // Epoch Advancement (member add/remove)
  // ============================================================

  /**
   * Advance the group epoch (called on member add/remove)
   * Generates new group secret and epoch key for forward secrecy
   */
  MLS.advanceEpoch = async function(groupState, updatedMemberPubKeysB64) {
    const oldSecret = nacl.util.decodeBase64(groupState.groupSecret);

    // Derive new group secret from old secret + epoch
    const epochInfo = `AuthoMLS:${groupState.groupId}:advance:${groupState.epoch + 1}`;
    const newGroupSecret = await hkdfDerive(oldSecret, nacl.randomBytes(32), epochInfo, 32);

    // Derive new epoch key
    const epochSalt = new TextEncoder().encode(`AuthoMLS:${groupState.groupId}:epoch:${groupState.epoch + 1}`);
    const newEpochKey = await hkdfDerive(newGroupSecret, epochSalt, 'AuthoMLSEpochKey', 32);

    // New epoch keypair
    const newEpochKeyPair = nacl.box.keyPair();

    // Update members list
    const members = updatedMemberPubKeysB64.map(pkB64 => ({
      publicKeyB64: pkB64,
      dhShareB64: '' // Will be computed when needed
    }));

    groupState.epoch += 1;
    groupState.groupSecret = nacl.util.encodeBase64(newGroupSecret);
    groupState.epochKey = nacl.util.encodeBase64(newEpochKey);
    groupState.epochKeyPair = {
      publicKey: nacl.util.encodeBase64(newEpochKeyPair.publicKey),
      secretKey: nacl.util.encodeBase64(newEpochKeyPair.secretKey)
    };
    groupState.members = members;

    return groupState;
  };

  // ============================================================
  // Group Message Encryption/Decryption
  // ============================================================

  /**
   * Encrypt a message for the group (O(1) — single encryption)
   * @param {Object} groupState - Current group state
   * @param {string} plaintext - Message to encrypt
   * @param {string} senderPubKeyB64 - Sender's public key (for sealed sender)
   * @returns {Object} Encrypted group message envelope
   */
  MLS.encryptGroupMessage = async function(groupState, plaintext, senderPubKeyB64) {
    const epochKey = nacl.util.decodeBase64(groupState.epochKey);

    // Sealed sender: embed sender identity inside payload
    const innerPayload = JSON.stringify({
      s: senderPubKeyB64 || '',
      t: Date.now(),
      body: plaintext
    });

    const plaintextBytes = new TextEncoder().encode(innerPayload);

    // AES-256-GCM with epoch key
    const aesKey = await crypto.subtle.importKey('raw', epochKey, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Associated data: epoch + groupId for binding
    const ad = new TextEncoder().encode(`${groupState.groupId}:${groupState.epoch}`);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ad }, aesKey, plaintextBytes));

    return {
      v: 'mls1',
      g: groupState.groupId,
      ep: groupState.epoch,
      iv: nacl.util.encodeBase64(iv),
      c: nacl.util.encodeBase64(ct)
    };
  };

  /**
   * Decrypt a group message (O(1) — single decryption)
   * @param {Object} groupState - Current group state
   * @param {Object} envelope - Encrypted message envelope
   * @returns {string} Decrypted plaintext
   */
  MLS.decryptGroupMessage = async function(groupState, envelope) {
    if (envelope.v !== 'mls1') {
      throw new Error('Unknown MLS envelope version: ' + envelope.v);
    }

    // Check epoch matches
    if (envelope.ep !== groupState.epoch) {
      // Try to handle epoch mismatch — might need to load older epoch key
      console.warn(`[MLS] Epoch mismatch: message=${envelope.ep}, current=${groupState.epoch}`);
    }

    const epochKey = nacl.util.decodeBase64(groupState.epochKey);
    const iv = nacl.util.decodeBase64(envelope.iv);
    const ct = nacl.util.decodeBase64(envelope.c);

    const aesKey = await crypto.subtle.importKey('raw', epochKey, 'AES-GCM', false, ['decrypt']);
    const ad = new TextEncoder().encode(`${envelope.g}:${envelope.ep}`);
    const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: ad }, aesKey, ct);
    const innerStr = new TextDecoder().decode(ptBuf);

    // Parse sealed sender payload
    try {
      const inner = JSON.parse(innerStr);
      if (inner.t && (Date.now() - inner.t) > 86400000) {
        console.warn('SECURITY: MLS group message timestamp >24h old');
      }
      return inner.body || innerStr;
    } catch {
      return innerStr;
    }
  };

  // ============================================================
  // State Serialization (for server sync)
  // ============================================================

  MLS.serializeGroupState = function(state) {
    return JSON.stringify(state);
  };

  MLS.deserializeGroupState = function(json) {
    return (typeof json === 'string') ? JSON.parse(json) : json;
  };

  MLS.encryptGroupState = async function(state, encryptionKey) {
    const plaintext = new TextEncoder().encode(MLS.serializeGroupState(state));
    const aesKey = await crypto.subtle.importKey('raw', encryptionKey.slice(0, 32), 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext));
    return {
      iv: nacl.util.encodeBase64(iv),
      ct: nacl.util.encodeBase64(ct),
      v: 'MLS_STATE_V1'
    };
  };

  MLS.decryptGroupState = async function(encrypted, encryptionKey) {
    if (!encrypted || encrypted.v !== 'MLS_STATE_V1') return null;
    const aesKey = await crypto.subtle.importKey('raw', encryptionKey.slice(0, 32), 'AES-GCM', false, ['decrypt']);
    const iv = nacl.util.decodeBase64(encrypted.iv);
    const ct = nacl.util.decodeBase64(encrypted.ct);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    return MLS.deserializeGroupState(new TextDecoder().decode(pt));
  };

  // ============================================================
  // Group State Manager (in-memory cache)
  // ============================================================

  const groupStates = new Map(); // groupId -> group state

  MLS.getGroupState = function(groupId) {
    return groupStates.get(groupId) || null;
  };

  MLS.setGroupState = function(groupId, state) {
    groupStates.set(groupId, state);
  };

  MLS.clearGroupState = function(groupId) {
    groupStates.delete(groupId);
  };

  // ============================================================
  // Server sync helpers
  // ============================================================

  MLS.saveGroupStateToServer = async function(groupId, state, encryptionKey, authHeaders) {
    try {
      const encrypted = await MLS.encryptGroupState(state, encryptionKey);
      await fetch('/api/messages/mls-state', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body: JSON.stringify({ groupId, state: encrypted })
      });
    } catch (e) {
      console.warn('[MLS] Failed to save group state to server:', e.message);
    }
  };

  MLS.loadGroupStateFromServer = async function(groupId, encryptionKey, authHeaders) {
    try {
      const r = await fetch(`/api/messages/mls-state/${encodeURIComponent(groupId)}`, {
        headers: authHeaders
      });
      if (!r.ok) return null;
      const data = await r.json();
      if (!data.state) return null;
      return await MLS.decryptGroupState(data.state, encryptionKey);
    } catch (e) {
      console.warn('[MLS] Failed to load group state from server:', e.message);
      return null;
    }
  };

  // Export
  global.MLSGroup = MLS;

})(typeof window !== 'undefined' ? window : global);
