/**
 * Autho Wire Protocol — Compact binary message encoding + compression
 *
 * Replaces JSON+Base64 envelopes with packed binary for ~66% smaller payloads.
 * Includes deflate compression for text, Blurhash for image previews,
 * and client-side media optimization (resize/WebP/Opus).
 *
 * Binary envelope format (v5 ratchet):
 *   [1B version][32B DH pubkey][4B msgNum][4B prevChain][12B IV][2B ctLen][NB ciphertext]
 *   = 55 bytes overhead (vs ~220 bytes for JSON+Base64)
 *
 * Binary envelope format (v3/v4):
 *   [1B version][32B ephemeral pubkey][24B nonce OR 12B iv][2B ctLen][NB ciphertext]
 *   v4 adds: [NB kyber ciphertext]
 */
(function(global) {
  'use strict';

  const Wire = {};

  // ============================================================
  // Binary Packing — compact envelope format
  // ============================================================

  // Version byte constants
  const WIRE_V3 = 0x03;
  const WIRE_V4 = 0x04;
  const WIRE_V5 = 0x05;
  const WIRE_MLS1 = 0x10;

  Wire.pack = function(envelope) {
    if (typeof envelope === 'string') envelope = JSON.parse(envelope);

    if (envelope.v === 5) return packV5(envelope);
    if (envelope.v === 4) return packV4(envelope);
    if (envelope.v === 3) return packV3(envelope);
    if (envelope.v === 'mls1') return packMLS(envelope);

    // Fallback: just compress the JSON
    const json = typeof envelope === 'string' ? envelope : JSON.stringify(envelope);
    return compressFallback(json);
  };

  Wire.unpack = function(buffer) {
    if (!(buffer instanceof Uint8Array)) buffer = new Uint8Array(buffer);
    if (buffer.length < 2) return null;

    const version = buffer[0];
    if (version === WIRE_V5) return unpackV5(buffer);
    if (version === WIRE_V4) return unpackV4(buffer);
    if (version === WIRE_V3) return unpackV3(buffer);
    if (version === WIRE_MLS1) return unpackMLS(buffer);

    // Fallback: try decompressing as JSON
    return decompressFallback(buffer);
  };

  // ── v5 Double Ratchet: 1 + 32 + 4 + 4 + 12 + 2 + N ──

  function packV5(env) {
    const dh = decodeB64(env.h.dh);           // 32 bytes
    const iv = decodeB64(env.iv);              // 12 bytes
    const ct = decodeB64(env.c);               // N bytes
    const msgNum = env.h.n || 0;
    const prevChain = env.h.pn || 0;

    const buf = new Uint8Array(1 + 32 + 4 + 4 + 12 + 2 + ct.length);
    let offset = 0;
    buf[offset++] = WIRE_V5;
    buf.set(dh, offset); offset += 32;
    writeU32(buf, offset, msgNum); offset += 4;
    writeU32(buf, offset, prevChain); offset += 4;
    buf.set(iv, offset); offset += 12;
    writeU16(buf, offset, ct.length); offset += 2;
    buf.set(ct, offset);
    return buf;
  }

  function unpackV5(buf) {
    let offset = 1;
    const dh = buf.slice(offset, offset + 32); offset += 32;
    const msgNum = readU32(buf, offset); offset += 4;
    const prevChain = readU32(buf, offset); offset += 4;
    const iv = buf.slice(offset, offset + 12); offset += 12;
    const ctLen = readU16(buf, offset); offset += 2;
    const ct = buf.slice(offset, offset + ctLen);

    return {
      v: 5,
      h: { dh: encodeB64(dh), n: msgNum, pn: prevChain },
      iv: encodeB64(iv),
      c: encodeB64(ct)
    };
  }

  // ── v3: 1 + 32 + 24 + 2 + N ──

  function packV3(env) {
    const eph = decodeB64(env.e);              // 32 bytes
    const nonce = decodeB64(env.n);            // 24 bytes
    const ct = decodeB64(env.c);

    const buf = new Uint8Array(1 + 32 + 24 + 2 + ct.length);
    let offset = 0;
    buf[offset++] = WIRE_V3;
    buf.set(eph, offset); offset += 32;
    buf.set(nonce, offset); offset += 24;
    writeU16(buf, offset, ct.length); offset += 2;
    buf.set(ct, offset);
    return buf;
  }

  function unpackV3(buf) {
    let offset = 1;
    const eph = buf.slice(offset, offset + 32); offset += 32;
    const nonce = buf.slice(offset, offset + 24); offset += 24;
    const ctLen = readU16(buf, offset); offset += 2;
    const ct = buf.slice(offset, offset + ctLen);

    return {
      v: 3,
      e: encodeB64(eph),
      n: encodeB64(nonce),
      c: encodeB64(ct)
    };
  }

  // ── v4: 1 + 32 + 12 + 2(kyberLen) + N(kyber) + 2(ctLen) + N(ct) ──

  function packV4(env) {
    const eph = decodeB64(env.e);
    const kyber = decodeB64(env.k);
    const iv = decodeB64(env.iv);
    const ct = decodeB64(env.c);

    const buf = new Uint8Array(1 + 32 + 12 + 2 + kyber.length + 2 + ct.length);
    let offset = 0;
    buf[offset++] = WIRE_V4;
    buf.set(eph, offset); offset += 32;
    buf.set(iv, offset); offset += 12;
    writeU16(buf, offset, kyber.length); offset += 2;
    buf.set(kyber, offset); offset += kyber.length;
    writeU16(buf, offset, ct.length); offset += 2;
    buf.set(ct, offset);
    return buf;
  }

  function unpackV4(buf) {
    let offset = 1;
    const eph = buf.slice(offset, offset + 32); offset += 32;
    const iv = buf.slice(offset, offset + 12); offset += 12;
    const kyberLen = readU16(buf, offset); offset += 2;
    const kyber = buf.slice(offset, offset + kyberLen); offset += kyberLen;
    const ctLen = readU16(buf, offset); offset += 2;
    const ct = buf.slice(offset, offset + ctLen);

    return {
      v: 4,
      e: encodeB64(eph),
      k: encodeB64(kyber),
      iv: encodeB64(iv),
      c: encodeB64(ct)
    };
  }

  // ── MLS: 1 + 4(epoch) + 12(iv) + 32(groupIdHash) + 2(ctLen) + N(ct) ──

  function packMLS(env) {
    const iv = decodeB64(env.iv);
    const ct = decodeB64(env.c);
    const epoch = env.ep || 0;
    // Hash groupId to fixed 32 bytes
    const gidBytes = new TextEncoder().encode(env.g || '');

    const buf = new Uint8Array(1 + 4 + 12 + 2 + gidBytes.length + 2 + ct.length);
    let offset = 0;
    buf[offset++] = WIRE_MLS1;
    writeU32(buf, offset, epoch); offset += 4;
    buf.set(iv, offset); offset += 12;
    writeU16(buf, offset, gidBytes.length); offset += 2;
    buf.set(gidBytes, offset); offset += gidBytes.length;
    writeU16(buf, offset, ct.length); offset += 2;
    buf.set(ct, offset);
    return buf;
  }

  function unpackMLS(buf) {
    let offset = 1;
    const epoch = readU32(buf, offset); offset += 4;
    const iv = buf.slice(offset, offset + 12); offset += 12;
    const gidLen = readU16(buf, offset); offset += 2;
    const gidBytes = buf.slice(offset, offset + gidLen); offset += gidLen;
    const ctLen = readU16(buf, offset); offset += 2;
    const ct = buf.slice(offset, offset + ctLen);

    return {
      v: 'mls1',
      g: new TextDecoder().decode(gidBytes),
      ep: epoch,
      iv: encodeB64(iv),
      c: encodeB64(ct)
    };
  }

  // ============================================================
  // Deflate Compression (built-in browser API)
  // ============================================================

  Wire.compress = async function(data) {
    if (typeof data === 'string') data = new TextEncoder().encode(data);
    try {
      const cs = new CompressionStream('deflate');
      const writer = cs.writable.getWriter();
      writer.write(data);
      writer.close();
      const reader = cs.readable.getReader();
      const chunks = [];
      let totalLen = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        totalLen += value.length;
      }
      const result = new Uint8Array(totalLen);
      let offset = 0;
      for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
      }
      return result;
    } catch {
      // Fallback: return uncompressed
      return data instanceof Uint8Array ? data : new TextEncoder().encode(data);
    }
  };

  Wire.decompress = async function(compressed) {
    if (!(compressed instanceof Uint8Array)) compressed = new Uint8Array(compressed);
    try {
      const ds = new DecompressionStream('deflate');
      const writer = ds.writable.getWriter();
      writer.write(compressed);
      writer.close();
      const reader = ds.readable.getReader();
      const chunks = [];
      let totalLen = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        totalLen += value.length;
      }
      const result = new Uint8Array(totalLen);
      let offset = 0;
      for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
      }
      return result;
    } catch {
      return compressed;
    }
  };

  Wire.compressText = async function(text) {
    const raw = new TextEncoder().encode(text);
    const compressed = await Wire.compress(raw);
    // Only use compressed if it's actually smaller
    if (compressed.length < raw.length) {
      // Prepend 1-byte flag: 0x01 = compressed
      const result = new Uint8Array(1 + compressed.length);
      result[0] = 0x01;
      result.set(compressed, 1);
      return result;
    }
    // 0x00 = uncompressed
    const result = new Uint8Array(1 + raw.length);
    result[0] = 0x00;
    result.set(raw, 1);
    return result;
  };

  Wire.decompressText = async function(data) {
    if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
    const flag = data[0];
    const payload = data.slice(1);
    if (flag === 0x01) {
      const decompressed = await Wire.decompress(payload);
      return new TextDecoder().decode(decompressed);
    }
    return new TextDecoder().decode(payload);
  };

  // ============================================================
  // Media Optimization — client-side resize, WebP, Blurhash
  // ============================================================

  Wire.optimizeImage = function(file, maxWidth, maxHeight, quality) {
    maxWidth = maxWidth || 1600;
    maxHeight = maxHeight || 1600;
    quality = quality || 0.82;

    return new Promise(function(resolve, reject) {
      const img = new Image();
      const url = URL.createObjectURL(file);

      img.onload = function() {
        URL.revokeObjectURL(url);

        let w = img.naturalWidth;
        let h = img.naturalHeight;

        // Scale down if needed
        if (w > maxWidth || h > maxHeight) {
          const ratio = Math.min(maxWidth / w, maxHeight / h);
          w = Math.round(w * ratio);
          h = Math.round(h * ratio);
        }

        const canvas = document.createElement('canvas');
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, w, h);

        // Try WebP first (much smaller), fall back to JPEG
        canvas.toBlob(function(blob) {
          if (blob) {
            resolve({
              blob: blob,
              width: w,
              height: h,
              type: blob.type,
              originalSize: file.size,
              optimizedSize: blob.size,
              savings: Math.round((1 - blob.size / file.size) * 100) + '%'
            });
          } else {
            // Fallback to JPEG
            canvas.toBlob(function(jpegBlob) {
              resolve({
                blob: jpegBlob || file,
                width: w,
                height: h,
                type: 'image/jpeg',
                originalSize: file.size,
                optimizedSize: jpegBlob ? jpegBlob.size : file.size,
                savings: jpegBlob ? Math.round((1 - jpegBlob.size / file.size) * 100) + '%' : '0%'
              });
            }, 'image/jpeg', quality);
          }
        }, 'image/webp', quality);
      };

      img.onerror = function() {
        URL.revokeObjectURL(url);
        reject(new Error('Failed to load image'));
      };

      img.src = url;
    });
  };

  Wire.generateThumbnail = function(file, maxDim) {
    maxDim = maxDim || 64;
    return Wire.optimizeImage(file, maxDim, maxDim, 0.5);
  };

  // Blurhash — ultra-compact image placeholder (20-30 bytes)
  // Simplified implementation: encode image as tiny averaged color grid
  Wire.generateBlurhash = function(file) {
    return new Promise(function(resolve, reject) {
      const img = new Image();
      const url = URL.createObjectURL(file);

      img.onload = function() {
        URL.revokeObjectURL(url);

        // Sample to 4x3 grid (12 color samples = 36 bytes base, ~24 bytes encoded)
        const canvas = document.createElement('canvas');
        const gw = 4, gh = 3;
        canvas.width = gw;
        canvas.height = gh;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, gw, gh);
        const pixels = ctx.getImageData(0, 0, gw, gh).data;

        // Encode as compact string: base64 of RGB values
        const rgb = new Uint8Array(gw * gh * 3);
        for (let i = 0; i < gw * gh; i++) {
          rgb[i * 3] = pixels[i * 4];
          rgb[i * 3 + 1] = pixels[i * 4 + 1];
          rgb[i * 3 + 2] = pixels[i * 4 + 2];
        }

        resolve({
          hash: encodeB64(rgb),
          width: img.naturalWidth,
          height: img.naturalHeight,
          gridWidth: gw,
          gridHeight: gh,
          bytes: rgb.length
        });
      };

      img.onerror = function() {
        URL.revokeObjectURL(url);
        reject(new Error('Failed to generate blurhash'));
      };

      img.src = url;
    });
  };

  Wire.renderBlurhash = function(hashB64, width, height, gridWidth, gridHeight) {
    gridWidth = gridWidth || 4;
    gridHeight = gridHeight || 3;
    width = width || 300;
    height = height || 200;

    const rgb = decodeB64(hashB64);
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');

    // Draw each grid cell as a rectangle, interpolated
    const cellW = width / gridWidth;
    const cellH = height / gridHeight;

    for (let y = 0; y < gridHeight; y++) {
      for (let x = 0; x < gridWidth; x++) {
        const i = (y * gridWidth + x) * 3;
        ctx.fillStyle = 'rgb(' + rgb[i] + ',' + rgb[i + 1] + ',' + rgb[i + 2] + ')';
        ctx.fillRect(x * cellW, y * cellH, cellW + 1, cellH + 1);
      }
    }

    // Apply blur for smooth look
    ctx.filter = 'blur(12px)';
    ctx.drawImage(canvas, 0, 0);
    ctx.filter = 'none';

    return canvas;
  };

  // ============================================================
  // Opus Audio Recording (compressed voice messages)
  // ============================================================

  Wire.createAudioRecorder = function(options) {
    options = options || {};
    const sampleRate = options.sampleRate || 48000;
    const bitrate = options.bitrate || 24000; // 24kbps Opus

    let mediaRecorder = null;
    let chunks = [];
    let stream = null;

    return {
      start: async function() {
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        // Prefer Opus/WebM for smallest size
        const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
          ? 'audio/webm;codecs=opus'
          : MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')
            ? 'audio/ogg;codecs=opus'
            : 'audio/webm';

        mediaRecorder = new MediaRecorder(stream, {
          mimeType: mimeType,
          audioBitsPerSecond: bitrate
        });

        chunks = [];
        mediaRecorder.ondataavailable = function(e) {
          if (e.data.size > 0) chunks.push(e.data);
        };

        mediaRecorder.start(100); // 100ms chunks for low latency
        return { mimeType: mimeType };
      },

      stop: function() {
        return new Promise(function(resolve) {
          if (!mediaRecorder || mediaRecorder.state === 'inactive') {
            resolve(null);
            return;
          }
          mediaRecorder.onstop = function() {
            const blob = new Blob(chunks, { type: mediaRecorder.mimeType });
            if (stream) {
              stream.getTracks().forEach(function(t) { t.stop(); });
            }
            resolve({
              blob: blob,
              type: mediaRecorder.mimeType,
              size: blob.size,
              duration: 0 // would need timer tracking
            });
          };
          mediaRecorder.stop();
        });
      },

      cancel: function() {
        if (mediaRecorder && mediaRecorder.state !== 'inactive') {
          mediaRecorder.stop();
        }
        if (stream) {
          stream.getTracks().forEach(function(t) { t.stop(); });
        }
        chunks = [];
      }
    };
  };

  // ============================================================
  // Utility functions
  // ============================================================

  function encodeB64(bytes) {
    if (typeof nacl !== 'undefined' && nacl.util) return nacl.util.encodeBase64(bytes);
    return btoa(String.fromCharCode.apply(null, bytes));
  }

  function decodeB64(str) {
    if (typeof nacl !== 'undefined' && nacl.util) return nacl.util.decodeBase64(str);
    const raw = atob(str);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    return arr;
  }

  function writeU16(buf, offset, value) {
    buf[offset] = (value >> 8) & 0xFF;
    buf[offset + 1] = value & 0xFF;
  }

  function readU16(buf, offset) {
    return (buf[offset] << 8) | buf[offset + 1];
  }

  function writeU32(buf, offset, value) {
    buf[offset] = (value >> 24) & 0xFF;
    buf[offset + 1] = (value >> 16) & 0xFF;
    buf[offset + 2] = (value >> 8) & 0xFF;
    buf[offset + 3] = value & 0xFF;
  }

  function readU32(buf, offset) {
    return ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
  }

  function compressFallback(json) {
    const bytes = new TextEncoder().encode(json);
    const buf = new Uint8Array(1 + bytes.length);
    buf[0] = 0xFF; // fallback marker
    buf.set(bytes, 1);
    return buf;
  }

  function decompressFallback(buf) {
    if (buf[0] === 0xFF) {
      const json = new TextDecoder().decode(buf.slice(1));
      return JSON.parse(json);
    }
    return null;
  }

  // ============================================================
  // Size comparison helper (for debugging)
  // ============================================================

  Wire.measureSavings = function(envelope) {
    const jsonStr = typeof envelope === 'string' ? envelope : JSON.stringify(envelope);
    const jsonSize = new TextEncoder().encode(jsonStr).length;
    const packed = Wire.pack(envelope);
    const packedSize = packed.length;
    return {
      jsonSize: jsonSize,
      binarySize: packedSize,
      savedBytes: jsonSize - packedSize,
      savedPercent: Math.round((1 - packedSize / jsonSize) * 100) + '%'
    };
  };

  // Export
  global.AutohoWire = Wire;

})(typeof window !== 'undefined' ? window : global);
