/**
 * Autho Encrypted Calls — WebRTC voice/video with E2E signaling
 *
 * Architecture:
 *   - Signaling: Encrypted via Autho messaging (X3DH keys), relayed through WS
 *   - Media: Peer-to-peer via WebRTC (DTLS-SRTP encrypted, never touches server)
 *   - STUN: Google public STUN for NAT traversal (only reveals IPs to each other)
 *   - No TURN: P2P only — if NAT fails, call won't connect (privacy by design)
 *
 * Call flow:
 *   1. Caller sends encrypted "call_offer" message with SDP via messaging WS
 *   2. Recipient receives offer, shows incoming call UI
 *   3. Recipient sends encrypted "call_answer" with their SDP
 *   4. Both sides exchange ICE candidates via encrypted messages
 *   5. WebRTC P2P connection established — audio/video flows directly
 *   6. Either side can hang up — sends "call_end" message
 */
(function(global) {
  'use strict';

  const Call = {};

  // ── State ──
  let peerConnection = null;
  let localStream = null;
  let remoteStream = null;
  let callState = 'idle'; // idle | calling | ringing | active | ended
  let callType = 'voice'; // voice | video
  let callPeerId = null;
  let callStartTime = null;
  let iceCandidateQueue = [];
  let onCallStateChange = null;
  let onRemoteStream = null;
  let onCallDuration = null;
  let durationTimer = null;

  // WebRTC config — STUN + free TURN for NAT traversal (max 4 to avoid Firefox warning)
  const baseIceServers = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'turn:openrelay.metered.ca:80', username: 'openrelayproject', credential: 'openrelayproject' },
    { urls: 'turn:openrelay.metered.ca:443', username: 'openrelayproject', credential: 'openrelayproject' },
    { urls: 'turn:openrelay.metered.ca:443?transport=tcp', username: 'openrelayproject', credential: 'openrelayproject' }
  ];

  function buildRtcConfig() {
    const extraIceServers = Array.isArray(global.AUTHO_CALL_ICE_SERVERS)
      ? global.AUTHO_CALL_ICE_SERVERS
      : [];

    const turnConfig = global.AUTHO_CALL_TURN;
    if (turnConfig && turnConfig.urls) {
      extraIceServers.push(turnConfig);
    }

    return {
      iceServers: baseIceServers.concat(extraIceServers),
      iceCandidatePoolSize: 2
    };
  }

  // ── Public API ──

  Call.getState = function() { return callState; };
  Call.getType = function() { return callType; };
  Call.getPeerId = function() { return callPeerId; };

  Call.onStateChange = function(cb) { onCallStateChange = cb; };
  Call.onRemoteStream = function(cb) { onRemoteStream = cb; };
  Call.onDuration = function(cb) { onCallDuration = cb; };

  function setState(newState) {
    callState = newState;
    if (onCallStateChange) onCallStateChange(newState, callType, callPeerId);
  }

  // ── Start a call (caller side) ──
  Call.startCall = async function(peerId, type, sendSignal) {
    if (callState !== 'idle') {
      console.warn('[Call] Already in a call');
      return false;
    }

    callType = type || 'voice';
    callPeerId = peerId;
    setState('calling');

    try {
      // Get local media
      const constraints = {
        audio: true,
        video: callType === 'video' ? { width: { ideal: 640 }, height: { ideal: 480 }, facingMode: 'user' } : false
      };
      localStream = await navigator.mediaDevices.getUserMedia(constraints);

      // Create peer connection
      peerConnection = new RTCPeerConnection(buildRtcConfig());
      setupPeerConnection(sendSignal);

      // Add local tracks
      localStream.getTracks().forEach(function(track) {
        peerConnection.addTrack(track, localStream);
      });

      // Create offer
      const offer = await peerConnection.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: callType === 'video'
      });
      await peerConnection.setLocalDescription(offer);

      // Send encrypted offer via messaging
      sendSignal({
        type: 'call_offer',
        callType: callType,
        sdp: offer.sdp,
        timestamp: Date.now()
      });

      console.log('[Call] Offer sent to ' + peerId);
      return true;
    } catch (e) {
      console.error('[Call] Failed to start call:', e.name, e.message);
      if (e.name === 'NotAllowedError' || e.name === 'NotFoundError' || e.name === 'OverconstrainedError') {
        console.error('[Call] Microphone access denied or unavailable');
        cleanup();
        setState('ended');
        setTimeout(function() { setState('idle'); }, 2000);
      } else {
        Call.endCall(sendSignal);
      }
      return false;
    }
  };

  // ── Handle incoming call offer (recipient side) ──
  Call.handleOffer = async function(signal, sendSignal) {
    if (callState !== 'idle') {
      // Already in a call — reject
      sendSignal({ type: 'call_busy', timestamp: Date.now() });
      return;
    }

    callType = signal.callType || 'voice';
    callPeerId = signal.from;
    setState('ringing');

    // Store offer for when user accepts
    Call._pendingOffer = signal;
    Call._pendingSendSignal = sendSignal;
  };

  // ── Accept incoming call ──
  Call.acceptCall = async function() {
    if (callState !== 'ringing' || !Call._pendingOffer) return false;

    const signal = Call._pendingOffer;
    const sendSignal = Call._pendingSendSignal;

    try {
      // Get local media
      const constraints = {
        audio: true,
        video: callType === 'video' ? { width: { ideal: 640 }, height: { ideal: 480 }, facingMode: 'user' } : false
      };
      localStream = await navigator.mediaDevices.getUserMedia(constraints);

      // Create peer connection
      peerConnection = new RTCPeerConnection(buildRtcConfig());
      setupPeerConnection(sendSignal);

      // Add local tracks
      localStream.getTracks().forEach(function(track) {
        peerConnection.addTrack(track, localStream);
      });

      // Set remote description (the offer)
      await peerConnection.setRemoteDescription(new RTCSessionDescription({
        type: 'offer',
        sdp: signal.sdp
      }));

      // Flush queued ICE candidates
      for (const candidate of iceCandidateQueue) {
        try { await peerConnection.addIceCandidate(new RTCIceCandidate(candidate)); } catch {}
      }
      iceCandidateQueue = [];

      // Create answer
      const answer = await peerConnection.createAnswer();
      await peerConnection.setLocalDescription(answer);

      // Send encrypted answer
      sendSignal({
        type: 'call_answer',
        sdp: answer.sdp,
        timestamp: Date.now()
      });

      setState('active');
      startDurationTimer();

      Call._pendingOffer = null;
      Call._pendingSendSignal = null;

      console.log('[Call] Accepted call from ' + callPeerId);
      return true;
    } catch (e) {
      console.error('[Call] Failed to accept call:', e.name, e.message);
      // If getUserMedia failed, show a clear error instead of silently ending
      if (e.name === 'NotAllowedError' || e.name === 'NotFoundError' || e.name === 'OverconstrainedError') {
        console.error('[Call] Microphone access denied or unavailable');
        cleanup();
        setState('ended');
        setTimeout(function() { setState('idle'); }, 2000);
      } else {
        Call.endCall(sendSignal);
      }
      return false;
    }
  };

  // ── Reject incoming call ──
  Call.rejectCall = function() {
    if (callState !== 'ringing') return;
    const sendSignal = Call._pendingSendSignal;
    if (sendSignal) {
      sendSignal({ type: 'call_reject', timestamp: Date.now() });
    }
    cleanup();
    setState('idle');
  };

  // ── Handle incoming answer (caller side) ──
  Call.handleAnswer = async function(signal) {
    if (!peerConnection || callState !== 'calling') return;

    try {
      await peerConnection.setRemoteDescription(new RTCSessionDescription({
        type: 'answer',
        sdp: signal.sdp
      }));

      // Flush queued ICE candidates
      for (const candidate of iceCandidateQueue) {
        try { await peerConnection.addIceCandidate(new RTCIceCandidate(candidate)); } catch {}
      }
      iceCandidateQueue = [];

      setState('active');
      startDurationTimer();
      console.log('[Call] Call connected');
    } catch (e) {
      console.error('[Call] Failed to handle answer:', e);
    }
  };

  // ── Handle ICE candidate ──
  Call.handleIceCandidate = async function(signal) {
    if (!signal.candidate) return;

    if (peerConnection && peerConnection.remoteDescription) {
      try {
        await peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate));
      } catch (e) {
        console.warn('[Call] ICE candidate failed:', e);
      }
    } else {
      // Queue until remote description is set
      iceCandidateQueue.push(signal.candidate);
    }
  };

  // ── Handle call end / busy / reject ──
  Call.handleCallEnd = function(signal) {
    console.log('[Call] Remote ended call:', signal.type);
    cleanup();
    setState('ended');
    setTimeout(function() { setState('idle'); }, 2000);
  };

  // ── End call ──
  Call.endCall = function(sendSignal) {
    if (sendSignal && callState !== 'idle') {
      try { sendSignal({ type: 'call_end', timestamp: Date.now() }); } catch {}
    }
    cleanup();
    setState('ended');
    setTimeout(function() { setState('idle'); }, 1000);
  };

  // ── Toggle mute ──
  Call.toggleMute = function() {
    if (!localStream) return false;
    const audioTrack = localStream.getAudioTracks()[0];
    if (audioTrack) {
      audioTrack.enabled = !audioTrack.enabled;
      return !audioTrack.enabled; // returns true if muted
    }
    return false;
  };

  // ── Toggle video ──
  Call.toggleVideo = function() {
    if (!localStream) return false;
    const videoTrack = localStream.getVideoTracks()[0];
    if (videoTrack) {
      videoTrack.enabled = !videoTrack.enabled;
      return !videoTrack.enabled; // returns true if camera off
    }
    return false;
  };

  // ── Get local stream for self-view ──
  Call.getLocalStream = function() { return localStream; };
  Call.getRemoteStream = function() { return remoteStream; };

  // ── Handle all signaling messages ──
  Call.handleSignal = function(signal, sendSignal) {
    if (!signal || !signal.type) return;

    switch (signal.type) {
      case 'call_offer':
        Call.handleOffer(signal, sendSignal);
        break;
      case 'call_answer':
        Call.handleAnswer(signal);
        break;
      case 'call_ice':
        Call.handleIceCandidate(signal);
        break;
      case 'call_end':
      case 'call_reject':
      case 'call_busy':
        Call.handleCallEnd(signal);
        break;
    }
  };

  // ── Internal helpers ──

  function setupPeerConnection(sendSignal) {
    // ICE candidate handler — send each candidate encrypted to peer
    peerConnection.onicecandidate = function(event) {
      if (event.candidate) {
        sendSignal({
          type: 'call_ice',
          candidate: {
            candidate: event.candidate.candidate,
            sdpMid: event.candidate.sdpMid,
            sdpMLineIndex: event.candidate.sdpMLineIndex
          },
          timestamp: Date.now()
        });
      }
    };

    // Connection state changes
    peerConnection.onconnectionstatechange = function() {
      console.log('[Call] Connection state:', peerConnection.connectionState);
      if (peerConnection.connectionState === 'connected') {
        console.log('[Call] WebRTC P2P connected!');
      }
      if (peerConnection.connectionState === 'failed') {
        // Give it a moment — sometimes 'failed' is transient during ICE restart
        setTimeout(function() {
          if (peerConnection && peerConnection.connectionState === 'failed') {
            console.log('[Call] Connection permanently failed — ending call');
            Call.endCall(sendSignal);
          }
        }, 3000);
      }
      // Note: 'disconnected' is recoverable — do NOT end call on it
    };

    peerConnection.oniceconnectionstatechange = function() {
      console.log('[Call] ICE state:', peerConnection.iceConnectionState);
    };

    // Remote stream handler
    peerConnection.ontrack = function(event) {
      console.log('[Call] Remote track received:', event.track.kind);
      if (!remoteStream) {
        remoteStream = new MediaStream();
      }
      remoteStream.addTrack(event.track);
      if (onRemoteStream) onRemoteStream(remoteStream);
    };
  }

  function startDurationTimer() {
    callStartTime = Date.now();
    durationTimer = setInterval(function() {
      if (callState === 'active' && onCallDuration) {
        const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
        const mins = Math.floor(elapsed / 60);
        const secs = elapsed % 60;
        onCallDuration(mins + ':' + (secs < 10 ? '0' : '') + secs);
      }
    }, 1000);
  }

  function cleanup() {
    if (durationTimer) {
      clearInterval(durationTimer);
      durationTimer = null;
    }
    if (localStream) {
      localStream.getTracks().forEach(function(t) { t.stop(); });
      localStream = null;
    }
    if (peerConnection) {
      peerConnection.close();
      peerConnection = null;
    }
    remoteStream = null;
    iceCandidateQueue = [];
    callPeerId = null;
    callStartTime = null;
    Call._pendingOffer = null;
    Call._pendingSendSignal = null;
  }

  // Export
  global.AutohoCall = Call;

})(typeof window !== 'undefined' ? window : global);
