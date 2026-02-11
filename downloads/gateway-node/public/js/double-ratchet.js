/**
 * Double Ratchet Protocol Implementation for Autho Messaging
 * 
 * Implements Signal's Double Ratchet algorithm adapted for browser-based,
 * multi-device architecture with server-synced encrypted ratchet state.
 *
 * Key concepts:
 * - Root chain: derives new chain keys when DH ratchet advances
 * - Sending chain: derives per-message keys for outgoing messages
 * - Receiving chain: derives per-message keys for incoming messages
 * - DH ratchet: new DH keypair per send turn (not per message)
 * - Symmetric ratchet: KDF chain for per-message keys within a turn
 *
 * State is encrypted with the user's identity key and synced to server
 * for multi-device support.
 */
(function(global) {
  'use strict';

  const DR = {};

  // ============================================================
  // KDF utilities using Web Crypto API
  // ============================================================

  async function hkdfExpand(ikm, salt, info, length) {
    const keyMaterial = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt, info: new TextEncoder().encode(info) },
      keyMaterial,
      length * 8
    );
    return new Uint8Array(bits);
  }

  async function kdfRootKey(rootKey, dhOutput) {
    // KDF_RK(rk, dh_out) -> (new_root_key, chain_key)
    const derived = await hkdfExpand(dhOutput, rootKey, 'AuthoDoubleRatchetRK', 64);
    return {
      rootKey: derived.slice(0, 32),
      chainKey: derived.slice(32, 64)
    };
  }

  async function kdfChainKey(chainKey) {
    // KDF_CK(ck) -> (new_chain_key, message_key)
    const keyMaterial = await crypto.subtle.importKey('raw', chainKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const ckInput = new Uint8Array([0x01]);
    const mkInput = new Uint8Array([0x02]);
    const newCk = new Uint8Array(await crypto.subtle.sign('HMAC', keyMaterial, ckInput));
    const mk = new Uint8Array(await crypto.subtle.sign('HMAC', keyMaterial, mkInput));
    return { chainKey: newCk, messageKey: mk };
  }

  // ============================================================
  // AES-256-GCM encrypt/decrypt with message key
  // ============================================================

  async function encryptWithMessageKey(messageKey, plaintext, associatedData) {
    const aesKey = await crypto.subtle.importKey('raw', messageKey, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: associatedData || new Uint8Array(0) },
      aesKey,
      plaintext
    ));
    return { iv, ciphertext: ct };
  }

  async function decryptWithMessageKey(messageKey, iv, ciphertext, associatedData) {
    const aesKey = await crypto.subtle.importKey('raw', messageKey, 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: associatedData || new Uint8Array(0) },
      aesKey,
      ciphertext
    );
    return new Uint8Array(pt);
  }

  // ============================================================
  // DH operations using NaCl (Curve25519)
  // ============================================================

  function dhKeyPair() {
    return nacl.box.keyPair();
  }

  function dh(mySecretKey, theirPublicKey) {
    // Curve25519 DH: nacl.box.before computes shared secret
    return nacl.box.before(theirPublicKey, mySecretKey);
  }

  // ============================================================
  // Ratchet Session State
  // ============================================================

  /**
   * Initialize a session as the initiator (Alice)
   * Called when sending the first message to a new contact
   *
   * DENIABLE AUTHENTICATION: The triple-DH key agreement (dh1, dh2, dh3)
   * provides cryptographic deniability — both parties can independently
   * compute the same shared secret, so neither can prove to a third party
   * who authored any given message. This is the same property Signal provides.
   */
  DR.initSender = async function(myIdentityKeyPair, theirIdentityPubKey, theirSignedPreKey) {
    // Perform X3DH-like key agreement (provides deniable authentication)
    const ephemeralKeyPair = dhKeyPair();
    const dh1 = dh(myIdentityKeyPair.secretKey, theirSignedPreKey);
    const dh2 = dh(ephemeralKeyPair.secretKey, theirIdentityPubKey);
    const dh3 = dh(ephemeralKeyPair.secretKey, theirSignedPreKey);

    // Combine DH outputs
    const combined = new Uint8Array(dh1.length + dh2.length + dh3.length);
    combined.set(dh1, 0);
    combined.set(dh2, dh1.length);
    combined.set(dh3, dh1.length + dh2.length);

    // Derive initial root key
    const initialSalt = new Uint8Array(32); // zeros
    const { rootKey, chainKey } = await kdfRootKey(initialSalt, combined);

    // Generate first ratchet keypair
    const dhRatchetKeyPair = dhKeyPair();

    // Perform first DH ratchet step
    const dhOut = dh(dhRatchetKeyPair.secretKey, theirSignedPreKey);
    const ratcheted = await kdfRootKey(rootKey, dhOut);

    return {
      // DH ratchet state
      dhSendingKeyPair: dhRatchetKeyPair,
      dhReceivingKey: theirSignedPreKey,
      // Root key
      rootKey: ratcheted.rootKey,
      // Chain keys
      sendingChainKey: ratcheted.chainKey,
      receivingChainKey: null,
      // Message counters
      sendCount: 0,
      recvCount: 0,
      prevSendCount: 0,
      // Skipped message keys (for out-of-order messages)
      skippedKeys: {},
      // Session metadata
      myIdentityPubKey: myIdentityKeyPair.publicKey,
      theirIdentityPubKey: theirIdentityPubKey,
      // Ephemeral key sent with first message (for receiver to init)
      ephemeralPublicKey: ephemeralKeyPair.publicKey,
      initialized: true
    };
  };

  /**
   * Initialize a session as the responder (Bob)
   * Called when receiving the first message from a new contact
   */
  DR.initReceiver = async function(myIdentityKeyPair, mySignedPreKeyPair, theirIdentityPubKey, theirEphemeralPubKey) {
    const dh1 = dh(mySignedPreKeyPair.secretKey, theirIdentityPubKey);
    const dh2 = dh(myIdentityKeyPair.secretKey, theirEphemeralPubKey);
    const dh3 = dh(mySignedPreKeyPair.secretKey, theirEphemeralPubKey);

    const combined = new Uint8Array(dh1.length + dh2.length + dh3.length);
    combined.set(dh1, 0);
    combined.set(dh2, dh1.length);
    combined.set(dh3, dh1.length + dh2.length);

    const initialSalt = new Uint8Array(32);
    const { rootKey, chainKey } = await kdfRootKey(initialSalt, combined);

    return {
      dhSendingKeyPair: mySignedPreKeyPair,
      dhReceivingKey: null, // Will be set on first received message
      rootKey: rootKey,
      sendingChainKey: null,
      receivingChainKey: chainKey,
      sendCount: 0,
      recvCount: 0,
      prevSendCount: 0,
      skippedKeys: {},
      myIdentityPubKey: myIdentityKeyPair.publicKey,
      theirIdentityPubKey: theirIdentityPubKey,
      initialized: true
    };
  };

  // ============================================================
  // Ratchet Encrypt
  // ============================================================

  DR.ratchetEncrypt = async function(session, plaintext) {
    if (!session.sendingChainKey) {
      throw new Error('Session not initialized for sending');
    }

    // Symmetric ratchet: derive message key from sending chain
    const { chainKey, messageKey } = await kdfChainKey(session.sendingChainKey);
    session.sendingChainKey = chainKey;

    // Encrypt
    const plaintextBytes = (typeof plaintext === 'string')
      ? new TextEncoder().encode(plaintext)
      : plaintext;

    const header = {
      dh: nacl.util.encodeBase64(session.dhSendingKeyPair.publicKey),
      n: session.sendCount,
      pn: session.prevSendCount
    };

    const headerBytes = new TextEncoder().encode(JSON.stringify(header));
    const { iv, ciphertext } = await encryptWithMessageKey(messageKey, plaintextBytes, headerBytes);

    session.sendCount++;

    return {
      header,
      iv: nacl.util.encodeBase64(iv),
      ciphertext: nacl.util.encodeBase64(ciphertext)
    };
  };

  // ============================================================
  // Ratchet Decrypt
  // ============================================================

  const MAX_SKIP = 256;

  async function skipMessageKeys(session, until) {
    if (session.recvCount + MAX_SKIP < until) {
      throw new Error('Too many skipped messages');
    }
    while (session.recvCount < until) {
      const { chainKey, messageKey } = await kdfChainKey(session.receivingChainKey);
      session.receivingChainKey = chainKey;
      const key = session.recvCount.toString();
      const dhKey = nacl.util.encodeBase64(session.dhReceivingKey || new Uint8Array(32));
      if (!session.skippedKeys[dhKey]) session.skippedKeys[dhKey] = {};
      session.skippedKeys[dhKey][key] = nacl.util.encodeBase64(messageKey);
      session.recvCount++;
    }
  }

  function trySkippedMessageKeys(session, header) {
    const dhKey = header.dh;
    const n = String(header.n);
    if (session.skippedKeys[dhKey] && session.skippedKeys[dhKey][n]) {
      const mkB64 = session.skippedKeys[dhKey][n];
      delete session.skippedKeys[dhKey][n];
      if (Object.keys(session.skippedKeys[dhKey]).length === 0) {
        delete session.skippedKeys[dhKey];
      }
      return nacl.util.decodeBase64(mkB64);
    }
    return null;
  }

  async function dhRatchetStep(session, header) {
    const theirNewDhPub = nacl.util.decodeBase64(header.dh);

    // Skip any remaining message keys in current receiving chain
    if (session.receivingChainKey) {
      await skipMessageKeys(session, header.pn);
    }

    session.prevSendCount = session.sendCount;
    session.sendCount = 0;
    session.recvCount = 0;
    session.dhReceivingKey = theirNewDhPub;

    // Receiving chain: DH with their new key and our current sending key
    const dhRecv = dh(session.dhSendingKeyPair.secretKey, theirNewDhPub);
    const recvRatchet = await kdfRootKey(session.rootKey, dhRecv);
    session.rootKey = recvRatchet.rootKey;
    session.receivingChainKey = recvRatchet.chainKey;

    // Generate new sending keypair
    session.dhSendingKeyPair = dhKeyPair();

    // Sending chain: DH with our new key and their key
    const dhSend = dh(session.dhSendingKeyPair.secretKey, theirNewDhPub);
    const sendRatchet = await kdfRootKey(session.rootKey, dhSend);
    session.rootKey = sendRatchet.rootKey;
    session.sendingChainKey = sendRatchet.chainKey;
  }

  DR.ratchetDecrypt = async function(session, message) {
    const { header, iv, ciphertext } = message;

    // Try skipped message keys first
    const skippedMk = trySkippedMessageKeys(session, header);
    if (skippedMk) {
      const headerBytes = new TextEncoder().encode(JSON.stringify(header));
      const pt = await decryptWithMessageKey(
        skippedMk,
        nacl.util.decodeBase64(iv),
        nacl.util.decodeBase64(ciphertext),
        headerBytes
      );
      return new TextDecoder().decode(pt);
    }

    // Check if we need a DH ratchet step
    const theirDhPub = nacl.util.decodeBase64(header.dh);
    const currentReceiving = session.dhReceivingKey
      ? nacl.util.encodeBase64(session.dhReceivingKey)
      : null;

    if (header.dh !== currentReceiving) {
      // New DH ratchet key from sender — perform DH ratchet step
      await dhRatchetStep(session, header);
    }

    // Skip any message keys we missed
    await skipMessageKeys(session, header.n);

    // Derive message key from receiving chain
    const { chainKey, messageKey } = await kdfChainKey(session.receivingChainKey);
    session.receivingChainKey = chainKey;
    session.recvCount++;

    // Decrypt
    const headerBytes = new TextEncoder().encode(JSON.stringify(header));
    const pt = await decryptWithMessageKey(
      messageKey,
      nacl.util.decodeBase64(iv),
      nacl.util.decodeBase64(ciphertext),
      headerBytes
    );
    return new TextDecoder().decode(pt);
  };

  // ============================================================
  // Session State Serialization (for server sync)
  // ============================================================

  DR.serializeSession = function(session) {
    const s = {
      dhSendPub: nacl.util.encodeBase64(session.dhSendingKeyPair.publicKey),
      dhSendSec: nacl.util.encodeBase64(session.dhSendingKeyPair.secretKey),
      dhRecvPub: session.dhReceivingKey ? nacl.util.encodeBase64(session.dhReceivingKey) : null,
      rootKey: nacl.util.encodeBase64(session.rootKey),
      sendCk: session.sendingChainKey ? nacl.util.encodeBase64(session.sendingChainKey) : null,
      recvCk: session.receivingChainKey ? nacl.util.encodeBase64(session.receivingChainKey) : null,
      sendN: session.sendCount,
      recvN: session.recvCount,
      prevN: session.prevSendCount,
      skipped: session.skippedKeys,
      myIdPub: nacl.util.encodeBase64(session.myIdentityPubKey),
      theirIdPub: nacl.util.encodeBase64(session.theirIdentityPubKey),
      ephPub: session.ephemeralPublicKey ? nacl.util.encodeBase64(session.ephemeralPublicKey) : undefined
    };
    return JSON.stringify(s);
  };

  DR.deserializeSession = function(json) {
    const s = (typeof json === 'string') ? JSON.parse(json) : json;
    return {
      dhSendingKeyPair: {
        publicKey: nacl.util.decodeBase64(s.dhSendPub),
        secretKey: nacl.util.decodeBase64(s.dhSendSec)
      },
      dhReceivingKey: s.dhRecvPub ? nacl.util.decodeBase64(s.dhRecvPub) : null,
      rootKey: nacl.util.decodeBase64(s.rootKey),
      sendingChainKey: s.sendCk ? nacl.util.decodeBase64(s.sendCk) : null,
      receivingChainKey: s.recvCk ? nacl.util.decodeBase64(s.recvCk) : null,
      sendCount: s.sendN || 0,
      recvCount: s.recvN || 0,
      prevSendCount: s.prevN || 0,
      skippedKeys: s.skipped || {},
      myIdentityPubKey: nacl.util.decodeBase64(s.myIdPub),
      theirIdentityPubKey: nacl.util.decodeBase64(s.theirIdPub),
      ephemeralPublicKey: s.ephPub ? nacl.util.decodeBase64(s.ephPub) : undefined,
      initialized: true
    };
  };

  // ============================================================
  // Encrypted State Storage (encrypt session for server sync)
  // ============================================================

  DR.encryptSessionState = async function(session, encryptionKey) {
    const plaintext = new TextEncoder().encode(DR.serializeSession(session));
    const aesKey = await crypto.subtle.importKey('raw', encryptionKey.slice(0, 32), 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext));
    return {
      iv: nacl.util.encodeBase64(iv),
      ct: nacl.util.encodeBase64(ct),
      v: 'DR_STATE_V1'
    };
  };

  DR.decryptSessionState = async function(encrypted, encryptionKey) {
    if (!encrypted || encrypted.v !== 'DR_STATE_V1') return null;
    const aesKey = await crypto.subtle.importKey('raw', encryptionKey.slice(0, 32), 'AES-GCM', false, ['decrypt']);
    const iv = nacl.util.decodeBase64(encrypted.iv);
    const ct = nacl.util.decodeBase64(encrypted.ct);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    const json = new TextDecoder().decode(pt);
    return DR.deserializeSession(json);
  };

  // ============================================================
  // Session Manager: handles per-conversation ratchet sessions
  // ============================================================

  const sessions = new Map(); // conversationId -> session

  DR.getSession = function(conversationId) {
    return sessions.get(conversationId) || null;
  };

  DR.setSession = function(conversationId, session) {
    sessions.set(conversationId, session);
  };

  DR.clearSession = function(conversationId) {
    sessions.delete(conversationId);
  };

  DR.clearAllSessions = function() {
    sessions.clear();
  };

  // ============================================================
  // Server sync helpers
  // ============================================================

  DR.saveSessionToServer = async function(conversationId, session, encryptionKey, authHeaders) {
    try {
      const encrypted = await DR.encryptSessionState(session, encryptionKey);
      await fetch('/api/messages/ratchet-state', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body: JSON.stringify({ conversationId, state: encrypted })
      });
    } catch (e) {
      console.warn('[DoubleRatchet] Failed to save session to server:', e.message);
    }
  };

  DR.loadSessionFromServer = async function(conversationId, encryptionKey, authHeaders) {
    try {
      const r = await fetch(`/api/messages/ratchet-state/${encodeURIComponent(conversationId)}`, {
        headers: authHeaders
      });
      if (!r.ok) return null;
      const data = await r.json();
      if (!data.state) return null;
      return await DR.decryptSessionState(data.state, encryptionKey);
    } catch (e) {
      console.warn('[DoubleRatchet] Failed to load session from server:', e.message);
      return null;
    }
  };

  // Export
  global.DoubleRatchet = DR;

})(typeof window !== 'undefined' ? window : global);
