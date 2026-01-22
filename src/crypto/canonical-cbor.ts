function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

const MIN_INT64 = -9223372036854775808n;
const MAX_INT64 = 9223372036854775807n;
const MAX_UINT64 = 18446744073709551615n;

function encodeUnsignedInt(value: bigint): Buffer {
  if (value < 0n) throw new Error('Unsigned int must be >= 0');
  return encodeMajorAndArg(0, value);
}

function encodeNegativeInt(value: bigint): Buffer {
  if (value >= 0n) throw new Error('Negative int must be < 0');
  const n = (-1n - value);
  return encodeMajorAndArg(1, n);
}

function encodeMajorAndArg(major: number, arg: bigint): Buffer {
  if (arg < 0n) throw new Error('CBOR arg must be >= 0');

  if (arg <= 23n) {
    return Buffer.from([((major << 5) | Number(arg)) & 0xff]);
  }

  if (arg <= 0xffn) {
    return Buffer.from([((major << 5) | 24) & 0xff, Number(arg) & 0xff]);
  }

  if (arg <= 0xffffn) {
    const b = Buffer.alloc(3);
    b[0] = ((major << 5) | 25) & 0xff;
    b.writeUInt16BE(Number(arg), 1);
    return b;
  }

  if (arg <= 0xffffffffn) {
    const b = Buffer.alloc(5);
    b[0] = ((major << 5) | 26) & 0xff;
    b.writeUInt32BE(Number(arg), 1);
    return b;
  }

  if (arg <= 0xffffffffffffffffn) {
    const b = Buffer.alloc(9);
    b[0] = ((major << 5) | 27) & 0xff;
    b.writeBigUInt64BE(arg, 1);
    return b;
  }

  throw new Error('CBOR integer too large (must fit in uint64)');
}

function encodeBytes(bytes: Buffer): Buffer {
  return Buffer.concat([encodeMajorAndArg(2, BigInt(bytes.length)), bytes]);
}

function encodeText(text: string): Buffer {
  const bytes = Buffer.from(text, 'utf8');
  return Buffer.concat([encodeMajorAndArg(3, BigInt(bytes.length)), bytes]);
}

function encodeArray(arr: unknown[]): Buffer {
  const parts: Buffer[] = [encodeMajorAndArg(4, BigInt(arr.length))];
  for (const item of arr) {
    parts.push(canonicalCborEncode(item));
  }
  return Buffer.concat(parts);
}

function compareBytes(a: Buffer, b: Buffer): number {
  if (a.length !== b.length) return a.length - b.length;
  return Buffer.compare(a, b);
}

function encodeMap(entries: Array<{ keyBytes: Buffer; valueBytes: Buffer }>): Buffer {
  entries.sort((x, y) => compareBytes(x.keyBytes, y.keyBytes));
  const parts: Buffer[] = [encodeMajorAndArg(5, BigInt(entries.length))];
  for (const { keyBytes, valueBytes } of entries) {
    parts.push(keyBytes);
    parts.push(valueBytes);
  }
  return Buffer.concat(parts);
}

function encodeBignumTag(tag: number, magnitude: bigint): Buffer {
  if (magnitude < 0n) throw new Error('Bignum magnitude must be >= 0');
  let hex = magnitude.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  const bytes = hex.length === 0 ? Buffer.from([0]) : Buffer.from(hex, 'hex');
  const tagBytes = encodeMajorAndArg(6, BigInt(tag));
  return Buffer.concat([tagBytes, encodeBytes(bytes)]);
}

function normalizeNumberToBigInt(value: number): bigint {
  if (!Number.isFinite(value)) throw new Error('CBOR does not allow NaN/Infinity');
  if (!Number.isInteger(value)) throw new Error('CBOR canonical encoding forbids floats');
  if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
    throw new Error('Unsafe integer: represent as bigint');
  }
  return BigInt(value);
}

export function canonicalCborEncode(value: unknown): Buffer {
  if (value === null) return Buffer.from([0xf6]);

  if (value === undefined) return Buffer.from([0xf7]);

  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);

  if (typeof value === 'number') {
    const n = normalizeNumberToBigInt(value);
    if (n < MIN_INT64 || n > MAX_INT64) {
      throw new Error('Integer out of int64 range: represent as bigint');
    }
    return n >= 0n ? encodeUnsignedInt(n) : encodeNegativeInt(n);
  }

  if (typeof value === 'bigint') {
    if (value < 0n) {
      if (value < MIN_INT64) {
        throw new Error('Integer out of int64 range');
      }
      return encodeNegativeInt(value);
    }

    if (value > MAX_UINT64) {
      throw new Error('Integer out of uint64 range');
    }

    return encodeUnsignedInt(value);
  }

  if (typeof value === 'string') return encodeText(value);

  if (Buffer.isBuffer(value)) return encodeBytes(value);
  if (value instanceof Uint8Array) return encodeBytes(Buffer.from(value));

  if (Array.isArray(value)) return encodeArray(value);

  if (isPlainObject(value)) {
    const entries: Array<{ keyBytes: Buffer; valueBytes: Buffer }> = [];
    for (const key of Object.keys(value)) {
      const keyBytes = encodeText(key);
      const valueBytes = canonicalCborEncode((value as Record<string, unknown>)[key]);
      entries.push({ keyBytes, valueBytes });
    }
    return encodeMap(entries);
  }

  throw new Error(`Unsupported CBOR type: ${typeof value}`);
}
