// Minimal synchronous Buffer compatibility layer for the CLC browser lab.
// It implements only the Buffer surface consumed by clc_semantics.ts.
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });

function bytesFromBase64(text: string): Uint8Array {
  const normalized = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const raw = atob(padded);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesFromHex(text: string): Uint8Array {
  const clean = text.length % 2 === 0 ? text : text.slice(0, -1);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToBase64(bytes: Uint8Array, url = false): string {
  let raw = "";
  for (const b of bytes) raw += String.fromCharCode(b);
  const value = btoa(raw);
  return url
    ? value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
    : value;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

// The Node-compatible static overload is intentionally wider than Uint8Array.
// @ts-expect-error browser shim mirrors Buffer.from's runtime contract.
export class Buffer extends Uint8Array {
  static from(value: unknown, encoding = "utf8"): Buffer {
    if (value instanceof Buffer) return new Buffer(value);
    if (value instanceof Uint8Array) return new Buffer(value);
    if (value instanceof ArrayBuffer) return new Buffer(new Uint8Array(value));
    if (typeof value === "number") return new Buffer(value);
    if (typeof value !== "string") {
      throw new TypeError("Buffer.from value must be a string, bytes, or arrayBuffer");
    }
    if (encoding === "hex") return new Buffer(bytesFromHex(value));
    if (encoding === "base64" || encoding === "base64url") {
      return new Buffer(bytesFromBase64(value));
    }
    if (encoding === "ascii") {
      const out = new Uint8Array(value.length);
      for (let i = 0; i < value.length; i++) out[i] = value.charCodeAt(i) & 0x7f;
      return new Buffer(out);
    }
    return new Buffer(encoder.encode(value));
  }

  static alloc(size: number): Buffer {
    return new Buffer(size);
  }

  static concat(values: readonly Uint8Array[]): Buffer {
    const size = values.reduce((sum, value) => sum + value.length, 0);
    const out = Buffer.alloc(size);
    let offset = 0;
    for (const value of values) {
      out.set(value, offset);
      offset += value.length;
    }
    return out;
  }

  static byteLength(value: string | Uint8Array, encoding = "utf8"): number {
    if (typeof value !== "string") return value.byteLength;
    if (encoding === "hex") return Math.floor(value.length / 2);
    if (encoding === "base64" || encoding === "base64url") {
      return bytesFromBase64(value).length;
    }
    return encoder.encode(value).length;
  }

  static compare(a: Uint8Array, b: Uint8Array): number {
    const length = Math.min(a.length, b.length);
    for (let i = 0; i < length; i++) {
      if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
  }

  toString(encoding = "utf8", start = 0, end = this.length): string {
    const bytes = this.subarray(start, end);
    if (encoding === "hex") return bytesToHex(bytes);
    if (encoding === "base64") return bytesToBase64(bytes);
    if (encoding === "base64url") return bytesToBase64(bytes, true);
    if (encoding === "ascii") {
      let out = "";
      for (const b of bytes) out += String.fromCharCode(b);
      return out;
    }
    return decoder.decode(bytes);
  }
}
