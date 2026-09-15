// CLC-v1 Capability Language Core - TypeScript reference implementation.
//
// This is an independent implementation of the CLC-v1 authorization
// semantics. It is NOT a translation of the Go or Python implementation; it
// follows the spec text directly (capability-language-core-v1.md):
//   - §6.2 params representation + input normalization
//   - §6.3 Entails algorithm
//   - §7 intersection rules
//   - §8 constraint evaluation (authorization side)
//   - §9 decision function + §9.3 resolved reason ordering + §9.4 reason codes
//   - §12.1 language revision compatibility
//
// The对外判决 must match the Go and Python implementations exactly on the
// conformance corpus and the shared property cases. Where the reference
// implementations diverge on inputs the corpus does not exercise, this file
// follows the spec, and the divergence is recorded in
// capability/data/_vectors/clc-v1/clc-v1-ambiguities.md.

import { createHash } from 'node:crypto';

export interface Grant {
    id: string;
    params?: Record<string, unknown> | null;
    constraints?: string[];
}
export interface Operation {
    id: string;
    params?: Record<string, unknown> | null;
}

export interface Decision {
    verdict: 'allow' | 'deny' | 'allow_unresolved';
    reason?: string;
    // Unresolved lists recognized-but-unevaluated constraints carried on an
    // allow_unresolved verdict (§8.4 residual-obligation channel, rev
    // CLC-1.3): non-empty means the consumer must evaluate/confirm each
    // constraint before acting, else deny (AAC §6.6).  Empty/absent on deny
    // and on a fully-evaluated allow.  Ordered deterministically
    // (sorted, deduped).
    unresolved?: string[];
}

export interface MatchResult {
    entails: boolean;
    reason?: string;
}

// A fail-closed evaluation error.  The message is the reason string and MAY
// carry a ": <detail>" diagnostic suffix (§9.4).
export class SemanticsError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SemanticsError';
    }
}

// Known constraint types for v1, read from the §8.1 grammar scheme:type[:params]
// (type = the second ':'-delimited segment).  Unknown types fail closed.
// rev CLC-1.3: core recognition is by (scheme,type) PAIR — only
// `varwof/constraint-v1` declares core-recognized types; any other scheme's
// constraint (including e.g. `foo/db-v1:max_rows`) fails closed with
// unknown_constraint.  The type name alone never selects an evaluator.
export const RESERVED_SCHEME = 'varwof/constraint-v1';
export const KNOWN_CONSTRAINT_TYPES = new Set(['max_rows', 'time', 'network']);
// (scheme,type) pairs the v0 core recognizes: only the reserved scheme.
export const RECOGNIZED_CONSTRAINT_IDENTITIES = new Set(
    [...KNOWN_CONSTRAINT_TYPES].map((t) => `${RESERVED_SCHEME}:${t}`),
);

// CLC-v1 §12.1: the language revision this implementation declares.
// (rev CLC-1.3 · 2026-09-12: CLC-1.3 is additive — `allow_unresolved`
// verdict + §9.3 identity/aggregation clarifications — so CLC-1.2/1.1
// inputs still read fine.)
// (rev CLC-1.6 · 2026-09-14: `jcs-sha256` is a real RFC 8785 implementation.
// The material projection digest and `clc-action:` identifier change for
// material containing `&`, `<` or `>`; the decoded params path refuses
// malformed Unicode (lone surrogates / invalid UTF-8) with
// invalid_params_number and counts the §6.2 size in JCS bytes, not a
// deserializer's re-encoding; the raw params size counts the JCS (RFC 8785
// §3.2.2.2) octets of every decoded character — `"`, `\` and the control
// shortcuts escape as two, every other control as `\u00xx` (six), and
// `&`/`<`/`>`/U+2028/U+2029/non-ASCII stay raw — and includes both string
// quotes, so the raw and decoded limits agree; CLC-1.4/1.5 inputs still read.)
export const CLC_REVISION = 'CLC-1.8';
// §6.2 step 4: bounds on the JCS-serialized params form.
export const MAX_PARAMS_SERIALIZED_BYTES = 512;
export const MAX_PARAMS_NESTING = 32;

// Verdicts (rev CLC-1.3: allow_unresolved is the independent verdict for
// recognized-but-unevaluated constraint obligations, §8.4).
export const VERDICT_ALLOW = 'allow';
export const VERDICT_DENY = 'deny';
export const VERDICT_ALLOW_UNRESOLVED = 'allow_unresolved';

// utf8Len returns the UTF-8 octet length of a string.  Section 6.2 measures
// the canonical serialization in octets, never in UTF-16 code units.
function utf8Len(s: string): number {
    return new TextEncoder().encode(s).length;
}

// jcsOctets: JCS (RFC 8785 §3.2.2.2) octet length of one decoded character:
// `"`, `\` and the control shortcuts \b \f \n \r \t escape as two octets, any
// other control character as `\u00xx` (six), and everything else (&, <, >,
// non-ASCII, astral) is emitted raw as its UTF-8 encoding.  The raw-path size
// cap uses this so it agrees with the decoded path.
function jcsOctets(cp: number): number {
    if (cp === 0x22 || cp === 0x5c || (cp >= 0x08 && cp <= 0x0d && cp !== 0x0b)) {
        return 2;
    }
    if (cp < 0x20) {
        return 6;
    }
    return utf8Len(String.fromCharCode(cp));
}

// isPlainObject: value is a JSON object, not an array, not null.
function isPlainObject(v: unknown): v is Record<string, unknown> {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// canonicalReason: stable reason code, everything before the first ':' (§9.4).
export function canonicalReason(reason?: string): string {
    if (!reason) {
        return '';
    }
    const i = reason.indexOf(':');
    return i >= 0 ? reason.slice(0, i) : reason;
}

export function validateCapabilityId(id?: string | null): void {
    if (!id) {
        throw new SemanticsError('missing_capability_id');
    }
    // Forbidden v1 shapes (§3): bare *, **, {a,b}, [a-z], partial-segment *.
    if (id === '*') {
        throw new SemanticsError('unsupported_wildcard');
    }
    if (id.includes('**')) {
        throw new SemanticsError('unsupported_wildcard');
    }
    if (id.includes('{') || id.includes('}')) {
        throw new SemanticsError('unsupported_wildcard');
    }
    if (id.includes('[') || id.includes(']')) {
        throw new SemanticsError('unsupported_wildcard');
    }
    const parts = id.split(':');
    for (let i = 0; i < parts.length; i++) {
        const p = parts[i];
        if (p.includes('*')) {
            if (p !== '*') {
                throw new SemanticsError('unsupported_wildcard');
            }
            if (i !== parts.length - 1) {
                throw new SemanticsError('unsupported_wildcard');
            }
        }
    }
    // Must have at least scheme:action (§3).
    if (parts.length < 2) {
        throw new SemanticsError('invalid_capability_id');
    }
    // §3 scheme grammar: vendor "/" product "-v" major (rev CLC-1.2).
    if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9-]+-v[0-9]+$/.test(parts[0])) {
        throw new SemanticsError('invalid_capability_id');
    }
}

// validateParams: reject null parameter values (CLC-v1 §5.2) and apply the
// §6.2 step 4 caps to the decoded-object path (§6.2 step 6, rev CLC-1.2):
// the depth cap uses the decoded structure, the size cap a canonical
// (sorted-key, compact) serialization.  Caps resolve before the null check
// (layer order).  The offending key is carried as a ": <detail>" suffix
// (§9.4).
function rejectNonFinite(value: unknown): void {
    if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new SemanticsError('invalid_params_number');
    }
    if (Array.isArray(value)) { value.forEach(rejectNonFinite); }
    else if (isPlainObject(value)) { Object.values(value).forEach(rejectNonFinite); }
}

// rejectUnpairedSurrogates: refuse lone UTF-16 surrogates anywhere in a
// decoded params structure (rev CLC-1.6).  A lone surrogate has no UTF-8 form
// and no JCS encoding (RFC 8785 §3.2.2.2); `JSON.stringify` would escape it
// and `TextEncoder` would silently repair it to U+FFFD.  It must produce the
// same stable denial (invalid_params_number) as the raw boundary check, before
// any serialization.
function rejectUnpairedSurrogates(value: unknown): void {
    if (typeof value === 'string') {
        rejectUnpairedSurrogateString(value, '');
        return;
    }
    if (Array.isArray(value)) { value.forEach(rejectUnpairedSurrogates); }
    else if (isPlainObject(value)) {
        for (const k of Object.keys(value)) {
            rejectUnpairedSurrogateString(k, k);
            rejectUnpairedSurrogates(value[k]);
        }
    }
}

function rejectUnpairedSurrogateString(s: string, key: string): void {
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
            if (next < 0xdc00 || next > 0xdfff) {
                throw new SemanticsError(key ? `invalid_params_number: lone surrogate in key ${JSON.stringify(key)}`
                                            : 'invalid_params_number: lone surrogate');
            }
            i++;
            continue;
        }
        if (c >= 0xdc00 && c <= 0xdfff) {
            throw new SemanticsError(key ? `invalid_params_number: lone surrogate in key ${JSON.stringify(key)}`
                                        : 'invalid_params_number: lone surrogate');
        }
    }
}

export function validateParams(params?: Record<string, unknown> | null): void {
    if (!params) {
        return;
    }
    if (!isPlainObject(params)) {
        // §6.2: params must be an object; a top-level array or scalar is the
        // same stable denial as unparsable JSON, checked before the caps so
        // all three implementations agree on invalid_params_number.
        throw new SemanticsError('invalid_params_number');
    }
    rejectUnpairedSurrogates(params);
    if (paramsDepth(params, 1) > MAX_PARAMS_NESTING) {
        throw new SemanticsError('invalid_params_size');
    }
    if (utf8Len(canonicalStringify(params)) > MAX_PARAMS_SERIALIZED_BYTES) {
        throw new SemanticsError('invalid_params_size');
    }
    for (const [k, v] of Object.entries(params)) {
        if (v === null) {
            throw new SemanticsError(`invalid_params_null: ${k}`);
        }
        rejectNonFinite(v);
    }
}

// paramsDepth: nesting depth of a decoded params value, counting objects and
// arrays with the params object as level 1 (§6.2 step 4).
function paramsDepth(v: unknown, depth: number): number {
    let max = depth;
    if (Array.isArray(v)) {
        for (const c of v) {
            max = Math.max(max, paramsDepth(c, depth + 1));
        }
    } else if (isPlainObject(v)) {
        for (const c of Object.values(v)) {
            max = Math.max(max, paramsDepth(c, depth + 1));
        }
    }
    return max;
}

// Significant decimal digits of a numeric literal (§6.2 step 3: > 17 rejects).
export function significantDigits(lit: string): number {
    let s = lit;
    const e = s.search(/[eE]/);
    if (e >= 0) {
        s = s.slice(0, e);
    }
    if (s.startsWith('-')) {
        s = s.slice(1);
    }
    s = s.replace('.', '');
    s = s.replace(/^0+/, '');
    s = s.replace(/0+$/, '');
    return s.length;
}

const NUMERIC_LITERAL_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;

// checkParamsNumber rejects non-finite or over-precision numeric params
// (§6.2 step 3).
function checkParamsNumber(lit: string): void {
    if (!NUMERIC_LITERAL_RE.test(lit)) {
        throw new SemanticsError(`invalid_params_number: ${lit}`);
    }
    const f = parseFloat(lit);
    if (!Number.isFinite(f)) {
        throw new SemanticsError(`invalid_params_number: ${lit}`);
    }
    if (significantDigits(lit) > 17) {
        throw new SemanticsError(`invalid_params_number: ${lit}`);
    }
}

// validateRawParams validates the raw JSON text of an operation's params
// object at the input boundary (§6.2, §9.3 layer 2), before any layer runs.
// Unlike a decoded object, the raw text preserves duplicate keys, number
// literals, nesting depth and serialized size.  Rejections follow §6.2 order:
// size/depth first (returned as invalid_params_size), then duplicate keys,
// then number shape; malformed input and a non-object params value fall into
// invalid_params_number.  The parsed value is returned for the caller.
// Two-pass scan.  §6.2 item 5 fixes the order of the input-boundary checks:
// size/depth (4) → duplicate keys (2) → number shape (3).  A single pass threw
// duplicate-key / bad-number errors from inside the parser, so for a payload
// that was *both* over-limit and duplicate/bad-number the reported code was the
// reverse of the spec.  Pass 1 computes size and depth only; pass 2 enforces the
// rest.  Depth is still checked inline (it is part of check 4).
function scanRawParams(raw: string, strict: boolean): { value: unknown; compact: number; depth: number } {
    let t = raw.trim();
    if (t === '' || !t.startsWith('{')) {
        throw new SemanticsError('invalid_params_number');
    }

    let i = 0;
    let depth = 0;
    let compact = 0;

    const skipWs = (): void => {
        while (i < t.length && (t[i] === ' ' || t[i] === '\t' || t[i] === '\n' || t[i] === '\r')) {
            i++;
        }
    };

    const fail = (): never => {
        throw new SemanticsError('invalid_params_number');
    };

    const parseString = (): string => {
        // Caller positioned on the opening '"'.
        let out = '';
        i++; // opening quote
        compact += 2; // the surrounding quotes are two serialized octets each
        while (i < t.length) {
            const ch = t[i];
            if (ch === '"') {
                i++;
                return out;
            }
            if (ch === '\\') {
                // Compact accounting keeps duplicate keys visible (the size
                // rule runs before the duplicate-key check, §6.2 item 5) and
                // counts octets: a \uXXXX escape contributes the UTF-8 octet
                // length of the decoded character, other escapes stay escaped
                // as JCS requires for control characters.
                const escStart = i;
                const next = t[i + 1] ?? '';
                switch (next) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        const hex = t.slice(i + 2, i + 6);
                        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
                            fail();
                        }
                        const hi = parseInt(hex, 16);
                        if (hi >= 0xd800 && hi <= 0xdbff) {
                            // A high surrogate must be followed by a low
                            // surrogate escape: the pair is one character, and
                            // a lone surrogate cannot be encoded (RFC 8785).
                            const loHex = t.slice(i + 8, i + 12);
                            if (t[i + 6] !== '\\' || (t[i + 7] ?? '') !== 'u' ||
                                !/^[0-9a-fA-F]{4}$/.test(loHex)) {
                                fail();
                            }
                            const lo = parseInt(loHex, 16);
                            if (lo < 0xdc00 || lo > 0xdfff) {
                                fail();
                            }
                            out += String.fromCharCode(hi, lo);
                            compact += 4; // the astral character: four UTF-8 octets
                            i += 12;
                            continue;
                        }
                        if (hi >= 0xdc00 && hi <= 0xdfff) {
                            fail(); // lone low surrogate
                        }
                        out += String.fromCharCode(hi);
                        compact += jcsOctets(hi);
                        i += 6;
                        continue;
                    }
                    default: fail();
                }
                const decodedChar = out.slice(-1);
                compact += jcsOctets(decodedChar.charCodeAt(0));
                i += 2;
                continue;
            }
            // A literal character is measured by Unicode scalar value, not
            // by UTF-16 code unit: an astral character is one scalar of four
            // UTF-8 octets, and counting its two halves would double the
            // count.  A control character or a lone surrogate is not text
            // JSON can carry unescaped, and Go and Python refuse both.
            const cp = t.codePointAt(i)!;
            if (cp < 0x20 || (cp >= 0xd800 && cp <= 0xdfff)) {
                fail();
            }
            const scalar = String.fromCodePoint(cp);
            out += scalar;
            compact += utf8Len(scalar);
            i += scalar.length;
        }
        fail();
    };

    const parseValue = (): unknown => {
        skipWs();
        if (i >= t.length) {
            fail();
        }
        const ch = t[i];
        if (ch === '{') {
            depth += 1;
            if (depth > MAX_PARAMS_NESTING) {
                throw new SemanticsError('invalid_params_size');
            }
            compact += 1;
            i++;
            const obj: Record<string, unknown> = {};
            const seen = new Set<string>();
            skipWs();
            if (t[i] === '}') {
                compact += 1;
                i++;
                return obj;
            }
            while (true) {
                skipWs();
                if (i >= t.length) {
                    fail();
                }
                if (t[i] !== '"') {
                    fail();
                }
                const key = parseString();
                compact += 1; // ':'
                skipWs();
                if (t[i] !== ':') {
                    fail();
                }
                i++;
                if (seen.has(key) && strict) {
                    throw new SemanticsError(`invalid_params_duplicate_key: ${key}`);
                }
                seen.add(key);
                obj[key] = parseValue();
                skipWs();
                if (t[i] === ',') {
                    compact += 1;
                    i++;
                    continue;
                }
                if (t[i] === '}') {
                    compact += 1;
                    i++;
                    break;
                }
                fail();
            }
            return obj;
        }
        if (ch === '[') {
            depth += 1;
            if (depth > MAX_PARAMS_NESTING) {
                throw new SemanticsError('invalid_params_size');
            }
            compact += 1;
            i++;
            const arr: unknown[] = [];
            skipWs();
            if (t[i] === ']') {
                compact += 1;
                i++;
                return arr;
            }
            while (true) {
                arr.push(parseValue());
                skipWs();
                if (t[i] === ',') {
                    compact += 1;
                    i++;
                    continue;
                }
                if (t[i] === ']') {
                    compact += 1;
                    i++;
                    break;
                }
                fail();
            }
            return arr;
        }
        if (ch === '"') {
            return parseString();
        }
        if (ch === 't') {
            if (t.slice(i, i + 4) === 'true') {
                compact += 4;
                i += 4;
                return true;
            }
            fail();
        }
        if (ch === 'f') {
            if (t.slice(i, i + 5) === 'false') {
                compact += 5;
                i += 5;
                return false;
            }
            fail();
        }
        if (ch === 'n') {
            if (t.slice(i, i + 4) === 'null') {
                compact += 4;
                i += 4;
                return null;
            }
            fail();
        }
        // Number literal: scan [0-9+-.eE] then validate shape.
        const start = i;
        while (i < t.length && /[0-9+\-.eE]/.test(t[i])) {
            i++;
        }
        const lit = t.slice(start, i);
        // §6.2 step 4 counts JCS bytes, and JCS rewrites the token: 1e-6
        // becomes 0.000001 and 1.0 becomes 1.  The received token is still
        // what the precision check below sees.
        const number = Number(lit);
        compact += Number.isFinite(number) ? JSON.stringify(number).length : lit.length;
        if (strict) {
            checkParamsNumber(lit);
        }
        return parseFloat(lit);
    };

    const result = parseValue();
    skipWs();
    if (i !== t.length) {
        // Trailing tokens after the params object → malformed.
        fail();
    }
    return { value: result, compact, depth };
}

// validateRawParams validates a raw params object at the input boundary,
// reporting the first failing check in the order §6.2 item 5 fixes.
export function validateRawParams(raw: string): Record<string, unknown> {
    const first = scanRawParams(raw, false);
    if (first.compact > MAX_PARAMS_SERIALIZED_BYTES || first.depth > MAX_PARAMS_NESTING) {
        throw new SemanticsError('invalid_params_size');
    }
    const second = scanRawParams(raw, true);
    return second.value as Record<string, unknown>;
}

function parseRevision(rev: string): [number, number] | null {
    const m = /^CLC-(\d+)\.(\d+)$/.exec(rev);
    if (!m) {
        return null;
    }
    return [parseInt(m[1], 10), parseInt(m[2], 10)];
}

// revisionCompatible reports whether an input declaring the given CLC revision
// may be evaluated by this implementation (§12.1). A mismatch fails closed
// with unsupported_language_revision — never a silent downgrade.
export function revisionCompatible(inputRevision: string): boolean {
    const ir = parseRevision(inputRevision);
    if (!ir) {
        return false;
    }
    const ours = parseRevision(CLC_REVISION);
    if (!ours) {
        return false;
    }
    return ir[0] === ours[0] && ir[1] <= ours[1];
}

// namespaceOf returns scheme:action_class (the first two ':'-delimited
// segments), per CLC-v1 §9.3 layer 3.
export function namespaceOf(capId: string): string {
    const parts = capId.split(':');
    return parts.length >= 2 ? parts[0] + ':' + parts[1] : capId;
}

// matchId checks if grant ID covers operation ID per CLC-v1 §5.1 + §9.3.
// Layer 3 (namespace = scheme + action Class) first, then Layer 4 (path
// coverage). A trailing * matches one or more segments.
export function matchId(grantId: string, opId: string): [boolean, string] {
    const gParts = grantId.split(':');
    const oParts = opId.split(':');

    // §9.3 layer 3: namespace (scheme + action Class).
    if (namespaceOf(grantId) !== namespaceOf(opId)) {
        return [false, 'different_namespace'];
    }

    // §9.3 layer 4: path coverage within the same namespace.
    if (gParts.length !== oParts.length) {
        if (gParts[gParts.length - 1] === '*') {
            if (oParts.length <= gParts.length - 1) {
                return [false, 'wildcard_requires_trailing_segment'];
            }
            for (let idx = 0; idx < gParts.length - 1; idx++) {
                if (gParts[idx] !== oParts[idx]) {
                    return [false, 'literal_mismatch'];
                }
            }
            return [true, ''];
        }
        // Exact grant does not broaden to a longer path.
        return [false, 'literal_mismatch'];
    }

    for (let idx = 0; idx < gParts.length; idx++) {
        if (gParts[idx] === '*') {
            if (idx === gParts.length - 1) {
                return [true, ''];
            }
            return [false, 'literal_mismatch'];
        }
        if (gParts[idx] !== oParts[idx]) {
            return [false, 'literal_mismatch'];
        }
    }
    return [true, ''];
}

// isEmptyBound: explicit empty [] or {} param value (CLC-v1 §9.3 layer 5).
export function isEmptyBound(v: unknown): boolean {
    return (Array.isArray(v) && v.length === 0) ||
        (isPlainObject(v) && Object.keys(v).length === 0);
}

export function hasEmptyBound(params: Record<string, unknown>): boolean {
    return Object.values(params).some(isEmptyBound);
}

// jsonEqual reports exact JSON-value equality, used for set membership
// (v1.1 enum rule) and intersection element math. Numbers compare as exact
// values, not bounds.
function jsonEqual(a: unknown, b: unknown): boolean {
    if (typeof a === 'number' && typeof b === 'number') {
        return a === b;
    }
    if (typeof a !== typeof b) {
        return false;
    }
    if (a === b) {
        return true;
    }
    if (Array.isArray(a) && Array.isArray(b)) {
        if (a.length !== b.length) {
            return false;
        }
        for (let i = 0; i < a.length; i++) {
            if (!jsonEqual(a[i], b[i])) {
                return false;
            }
        }
        return true;
    }
    if (isPlainObject(a) && isPlainObject(b)) {
        const ka = Object.keys(a).sort();
        const kb = Object.keys(b).sort();
        if (ka.length !== kb.length) {
            return false;
        }
        for (let i = 0; i < ka.length; i++) {
            if (ka[i] !== kb[i]) {
                return false;
            }
            if (!jsonEqual(a[ka[i]], b[kb[i]])) {
                return false;
            }
        }
        return true;
    }
    return false;
}

// canonicalStringify renders a JSON value with object keys sorted — the
// order-independent form used to compare expected vs actual results, matching
// Go's json.Marshal (sorted map keys) and Python's sort_keys=True.
export function canonicalStringify(v: unknown): string {
    if (v === null) {
        return 'null';
    }
    if (typeof v === 'number') {
        // JSON.stringify(1) === '1' — same canonical form as Go/Python for the
        // numeric shapes the corpus uses.
        return JSON.stringify(v);
    }
    if (typeof v === 'string' || typeof v === 'boolean') {
        return JSON.stringify(v);
    }
    if (Array.isArray(v)) {
        return '[' + v.map(canonicalStringify).join(',') + ']';
    }
    if (isPlainObject(v)) {
        const parts: string[] = [];
        for (const k of Object.keys(v).sort()) {
            parts.push(JSON.stringify(k) + ':' + canonicalStringify(v[k]));
        }
        return '{' + parts.join(',') + '}';
    }
    return 'null';
}

// canonicalJSON renders a JSON value per RFC 8785 (JCS) — the same bytes Go's
// `CanonicalJSON` emits.  Object keys sort by UTF-16 code units (§3.2.3;
// JavaScript's default string order), strings use the §3.2.2.2 escape set
// (`JSON.stringify` does not escape `&`, `<` or `>`), and numbers use
// ECMAScript Number::toString.  A non-finite number has no JSON encoding.
// wellFormed refuses unpaired surrogates: a lone UTF-16 surrogate is not valid
// Unicode, so it has no UTF-8 form and no JCS encoding (RFC 8785 §3.2.2.2).
function wellFormed(s: string, what: string): string {
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
            if (next < 0xdc00 || next > 0xdfff) {
                throw new SemanticsError('canonical_lone_surrogate: ' + what);
            }
            i++;
            continue;
        }
        if (c >= 0xdc00 && c <= 0xdfff) {
            throw new SemanticsError('canonical_lone_surrogate: ' + what);
        }
    }
    return s;
}

export function canonicalJSON(v: unknown): string {
    if (v === null) return 'null';
    if (typeof v === 'number') {
        if (!Number.isFinite(v)) throw new SemanticsError('canonical_invalid_number');
        return JSON.stringify(v);
    }
    if (typeof v === 'string') return JSON.stringify(wellFormed(v, 'string'));
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (Array.isArray(v)) return '[' + v.map(canonicalJSON).join(',') + ']';
    if (isPlainObject(v)) {
        const parts: string[] = [];
        for (const k of Object.keys(v).sort()) {
            parts.push(JSON.stringify(wellFormed(k, 'key')) + ':' + canonicalJSON(v[k]));
        }
        return '{' + parts.join(',') + '}';
    }
    throw new SemanticsError('canonical_unexpected_type');
}

// computeActionId is §4.3's projection identity over the declared material
// fields: clc-action:1:<type>:<suite>:<b64url(sha256(JCS(projection)))>.  A
// declared field that is absent makes the action non-matchable.
export function computeActionId(
    actionType: string,
    materialFields: string[],
    suite: string,
    action: Record<string, unknown>,
): string {
    const projection: Record<string, unknown> = {};
    for (const field of materialFields) {
        if (!Object.prototype.hasOwnProperty.call(action, field)) {
            throw new SemanticsError('action_not_matchable: ' + field);
        }
        projection[field] = action[field];
    }
    const digest = createHash('sha256').update(canonicalJSON(projection), 'utf8').digest('base64url');
    return `clc-action:1:${actionType}:${suite}:${digest}`;
}

// valueSubset checks if a single value is a subset of the grant value.
// Type dispatch mirrors the §6.2 table: number = bound (op ≤ grant), string =
// exact, boolean = exact (NOTE: Python's isinstance(x, (int,float)) catches
// bool and treats it as a number, a deviation on inputs the corpus does not
// exercise), array = allowed set (enum), object = recursive.
export function valueSubset(
    opVal: unknown,
    grantVal: unknown,
): [boolean, string] {
    if (opVal === null) {
        return [false, 'invalid_params_null'];
    }
    if (grantVal === null) {
        return [false, 'empty_bound_denies_class'];
    }

    if (typeof grantVal === 'number') {
        if (typeof opVal !== 'number') {
            return [false, 'params_exceed_grant'];
        }
        if (opVal > grantVal) {
            return [false, 'params_exceed_grant'];
        }
        return [true, ''];
    }
    if (typeof grantVal === 'string') {
        if (typeof opVal !== 'string' || opVal !== grantVal) {
            return [false, 'params_exceed_grant'];
        }
        return [true, ''];
    }
    if (typeof grantVal === 'boolean') {
        if (typeof opVal !== 'boolean' || opVal !== grantVal) {
            return [false, 'params_exceed_grant'];
        }
        return [true, ''];
    }
    if (Array.isArray(grantVal)) {
        // v1.1 enum semantics: an array-valued grant parameter is the set of
        // allowed values. The request may supply a scalar (must equal a member)
        // or an array (every element must equal a member). Members compare by
        // exact equality. An explicitly empty grant set denies the class.
        if (grantVal.length === 0) {
            return [false, 'empty_bound_denies_class'];
        }
        const elems = Array.isArray(opVal) ? opVal : [opVal];
        for (const o of elems) {
            if (!grantVal.some((g) => jsonEqual(o, g))) {
                return [false, 'not_in_enum'];
            }
        }
        return [true, ''];
    }
    if (isPlainObject(grantVal)) {
        if (!isPlainObject(opVal)) {
            return [false, 'params_exceed_grant'];
        }
        for (const [k, gvv] of Object.entries(grantVal)) {
            if (!(k in opVal)) {
                return [false, 'params_missing'];
            }
            const [ok, reason] = valueSubset(opVal[k], gvv);
            if (!ok) {
                return [false, reason];
            }
        }
        return [true, ''];
    }

    // Exact equality (fallback).
    return jsonEqual(opVal, grantVal) ? [true, ''] : [false, 'params_exceed_grant'];
}

// paramsSubset checks if operation params are a subset of grant params per
// CLC-v1 §5.2 + §9.3 layers 5-9. When several conditions fail at once, the
// resolved reason follows the fixed §9.3 ordering (empty bound, null,
// presence incl. key closure, enum, bound).
export function paramsSubset(
    opParams?: Record<string, unknown> | null,
    grantParams?: Record<string, unknown> | null,
): [boolean, string] {
    if (grantParams == null || Object.keys(grantParams).length === 0) {
        // Rev CLC-1.3 (§9.3): an absent OR empty params object is
        // unconstrained — the empty map declares no keys, so no key closure.
        return [true, ''];
    }
    if (opParams == null) {
        return [false, 'params_missing'];
    }

    // §9.3 layer 5: explicit empty bound ([] or {}) on the grant side.
    for (const gv of Object.values(grantParams)) {
        if (isEmptyBound(gv)) {
            return [false, 'empty_bound_denies_class'];
        }
    }

    // §9.3 layer 6: null values.
    for (const [k, gv] of Object.entries(grantParams)) {
        if (gv === null) {
            return [false, `invalid_params_null: ${k}`];
        }
    }
    for (const [k, ov] of Object.entries(opParams)) {
        if (ov === null) {
            return [false, `invalid_params_null: ${k}`];
        }
    }

    // §9.3 layer 7: presence — every grant key must be present in the op
    // (params_missing) before every op key must be declared by the grant
    // (undeclared_param); the missing-key check resolves first.
    for (const k of Object.keys(grantParams)) {
        if (!(k in opParams)) {
            return [false, 'params_missing'];
        }
    }
    for (const k of Object.keys(opParams)) {
        if (!(k in grantParams)) {
            return [false, `undeclared_param: ${k}`];
        }
    }

    // §9.3 layers 8-9: per-key value checks (enum membership, bounds).
    for (const [k, gv] of Object.entries(grantParams)) {
        const [ok, reason] = valueSubset(opParams[k], gv);
        if (!ok) {
            return [false, reason];
        }
    }
    return [true, ''];
}

// entails checks if a grant covers an operation per CLC-v1 §6.3.
export function entails(grant: Grant, op: Operation): MatchResult {
    try {
        validateCapabilityId(grant.id);
    } catch (e) {
        return { entails: false, reason: (e as SemanticsError).message };
    }
    try {
        validateCapabilityId(op.id);
    } catch (e) {
        return { entails: false, reason: (e as SemanticsError).message };
    }

    // §6.3 step 1: scheme check.
    const gScheme = grant.id.split(':')[0];
    const oScheme = op.id.split(':')[0];
    if (gScheme !== oScheme) {
        return { entails: false, reason: 'different_namespace' };
    }

    // §6.3 step 2: id coverage.
    const [okId, idReason] = matchId(grant.id, op.id);
    if (!okId) {
        return { entails: false, reason: idReason };
    }

    // §6.3 step 3: grant params absent OR empty → true (unconstrained; rev
    // CLC-1.3 §9.3 makes {} ≡ absent).
    if (grant.params == null || Object.keys(grant.params).length === 0) {
        return { entails: true };
    }

    // §9.3 layer 6 resolves before presence (layer 7): null values in either
    // side fail before an absent operation params object is judged
    // params_missing (validateParams also applies the §6.2 step 4 object-path
    // size/depth caps, rev CLC-1.2).
    try {
        validateParams(grant.params);
    } catch (e) {
        return { entails: false, reason: (e as SemanticsError).message };
    }
    try {
        validateParams(op.params);
    } catch (e) {
        return { entails: false, reason: (e as SemanticsError).message };
    }

    // §6.3 step 4: op params absent → false (bounded grant, fail-closed).
    if (op.params == null) {
        return { entails: false, reason: 'params_missing' };
    }

    // §6.3 step 5: params subset.
    const [ok, reason] = paramsSubset(op.params, grant.params);
    if (!ok) {
        return { entails: false, reason };
    }

    return { entails: true };
}

// intersectValue intersects two values (§7; §9.3 layer 10 no_overlap on empty).
function intersectValue(a: unknown, b: unknown): unknown {
    if (typeof a === 'number' && typeof b === 'number') {
        return Math.min(a, b);
    }
    if (Array.isArray(a) && Array.isArray(b)) {
        const result = a.filter((x) => b.some((y) => jsonEqual(x, y)));
        if (result.length === 0) {
            throw new SemanticsError('no_overlap');
        }
        return result;
    }
    if (isPlainObject(a) && isPlainObject(b)) {
        // Object values intersect per shared key, and only when the key sets
        // are identical (rev CLC-1.2): a shared-keys result would drop a key
        // the other source constrains, so it is not covered by every source
        // (P11 — composition narrows only).  Differing key sets deny
        // no_overlap.
        const aKeys = Object.keys(a);
        if (aKeys.length !== Object.keys(b).length || !aKeys.every((k) => k in b)) {
            throw new SemanticsError('no_overlap');
        }
        const result: Record<string, unknown> = {};
        for (const k of aKeys) {
            result[k] = intersectValue(a[k], b[k]);
        }
        if (Object.keys(result).length === 0) {
            throw new SemanticsError('no_overlap');
        }
        return result;
    }
    if (jsonEqual(a, b)) {
        return a;
    }
    throw new SemanticsError('no_overlap');
}

// intersect combines multiple grants per CLC-v1 §7.
export function intersect(grants: Grant[]): Grant {
    if (grants.length === 0) {
        throw new SemanticsError('absent_source');
    }

    // §9.3 layer 5: deny-when-declared — any source with an explicitly empty
    // bound ([] or {}) denies the class before any member math.
    for (const g of grants) {
        if (g.params != null && hasEmptyBound(g.params)) {
            throw new SemanticsError('empty_bound_denies_class');
        }
    }

    // Start with the first grant.
    const result: Grant = {
        id: grants[0].id,
        params: grants[0].params,
        constraints: [...(grants[0].constraints ?? [])],
    };

    // Null values in any source's params are invalid in v1 (§5.2).
    validateParams(result.params);
    for (const g of grants.slice(1)) {
        validateParams(g.params);

        // §7 rule 2: the result must be covered by every source, so the
        // *narrower* identifier wins. The comparison is deliberately params-free:
        // entails() is the authorization relation and fails closed when a bounded
        // grant meets an operation without params (§6.3 step 4).
        if (result.id !== g.id) {
            if (entails({ id: result.id }, { id: g.id }).entails) {
                result.id = g.id; // g is narrower
            } else if (!entails({ id: g.id }, { id: result.id }).entails) {
                throw new SemanticsError('no_overlap');
            }
            // otherwise result stays the narrower identifier
        }

        // §7 rule 6: intersect params. `!= null` (not truthiness): a present-but-
        // empty params object declares no constraint and must not displace an
        // accumulated bound (P11; intersect-008/-009).
        if (result.params != null && g.params != null) {
            const intersected: Record<string, unknown> = {};
            for (const [k, rv] of Object.entries(result.params)) {
                if (k in g.params) {
                    intersected[k] = intersectValue(rv, g.params[k]);
                } else {
                    intersected[k] = rv;
                }
            }
            for (const [k, gv] of Object.entries(g.params)) {
                if (!(k in result.params)) {
                    intersected[k] = gv;
                }
            }
            result.params = intersected;
        } else if (g.params == null) {
            // g declares no constraint at all (params absent): keep accumulated.
        } else {
            // result is unconstrained (params absent), adopt g's params.
            result.params = g.params;
        }

        // §7 rule 3: constraints are conjunctive, so the merge is a set union —
        // every constraint of every source stays in force.
        const merged = new Set([...(result.constraints ?? []), ...(g.constraints ?? [])]);
        result.constraints = [...merged];
    }

    return result;
}

// validateConstraint checks a constraint against §8.1's type×value grammar
// (rev CLC-1.2): an unrecognized type → unknown_constraint; a recognized
// type whose value is out of grammar → invalid_constraint.
export function validateConstraint(c: string): void {
    const parts = c.split(':');
    if (parts.length < 2 || !RECOGNIZED_CONSTRAINT_IDENTITIES.has(`${parts[0]}:${parts[1]}`)) {
        throw new SemanticsError('unknown_constraint');
    }
    switch (parts[1]) {
        case 'max_rows':
            // Strict JSON non-negative integer, exactly one token (§8.1
            // value-grammar table).
            if (parts.length !== 3 || !isStrictJSONInteger(parts[2])) {
                throw new SemanticsError(`invalid_constraint: ${c}`);
            }
            break;
        case 'time': {
            // Value = JSON array of ≤32 {start,end} UTC daily windows (§8.1).
            const joined = constraintParams(c);
            if (!joined.startsWith('window:') || !validTimeWindowJSON(joined.slice('window:'.length))) {
                throw new SemanticsError(`invalid_constraint: ${c}`);
            }
            break;
        }
        case 'network': {
            // Value = JSON array of ≤32 CIDR strings (§8.1).
            const joined = constraintParams(c);
            if (!joined.startsWith('cidr:') || !validCIDRListJSON(joined.slice('cidr:'.length))) {
                throw new SemanticsError(`invalid_constraint: ${c}`);
            }
            break;
        }
    }
}

// checkConstraint evaluates a known constraint against an operation (§8.1).
// §8.1 defines the v1 known types; only max_rows has an auth-side evaluator
// here (time/network are recognized-but-unevaluated — they surface via the
// decision's unresolved field, §8.4).  rev CLC-1.2: max_rows uses a strict
// integer and fails closed when the op carries no max_rows value.
export function checkConstraint(c: string, op: Operation): string | null {
    const parts = c.split(':');
    // Defensive identity gate (rev CLC-1.3): validateConstraint is
    // authoritative and rejects non-core schemes first, so this is
    // unreachable via authorize.
    if (!RECOGNIZED_CONSTRAINT_IDENTITIES.has(`${parts[0]}:${parts[1]}`)) {
        return null;
    }
    const constraintType = parts[1];
    if (constraintType === 'max_rows') {
        if (parts.length !== 3 || !isStrictJSONInteger(parts[2])) {
            // Unreachable via authorize (validateConstraint rejects the grant
            // with invalid_constraint first); defensive no-op.
            return null;
        }
        const maxVal = parseInt(parts[2], 10);
        const rows = op.params?.max_rows;
        if (rows === undefined || rows === null) {
            // Op-absent max_rows → fail closed (§8.1 value-grammar table).
            return 'max_rows:violated';
        }
        // Op-side value domain (rev CLC-1.4): a row count must be a finite
        // non-negative integer; anything else cannot be shown to satisfy the
        // constraint, so it fails closed instead of passing unchecked.
        if (typeof rows !== 'number' || !Number.isFinite(rows) ||
            !Number.isInteger(rows) || rows < 0) {
            return 'max_rows:violated';
        }
        if (rows > maxVal) {
            return 'max_rows:violated';
        }
    }
    return null;
}

// coreEvaluatesConstraint reports whether the v1 core has an evaluator for a
// constraint's type (§8.1).  Only max_rows is core-evaluated; time/network
// are recognized-but-unevaluated and surface via unresolved (§8.4).
function coreEvaluatesConstraint(c: string): boolean {
    const parts = c.split(':');
    if (parts.length < 2) {
        return false;
    }
    return parts[0] === RESERVED_SCHEME && parts[1] === 'max_rows';
}

// constraintParams: a constraint's value part — everything after
// `scheme:type:` — with JSON colons preserved (rejoined from the colon-split
// parts; rev CLC-1.2 fixes the kind of corruption that chopped window arrays
// on inner colons).  Callers strip the type-specific domain crumb
// (`window:` / `cidr:`).
function constraintParams(c: string): string {
    const parts = c.split(':');
    if (parts.length < 3) {
        return '';
    }
    return parts.slice(2).join(':');
}

// isStrictJSONInteger: canonical JSON non-negative integer — digits only, no
// sign, no fraction, no exponent, no leading zero (rev CLC-1.2 value
// grammar).  Deliberately stricter than parseFloat, which accepts "10abc"
// and "1e3".
function isStrictJSONInteger(s: string): boolean {
    if (s === '') {
        return false;
    }
    if (s.length > 1 && s[0] === '0') {
        return false;
    }
    return /^[0-9]+$/.test(s);
}

const MAX_TIME_WINDOWS = 32;
const MAX_CIDR_LIST = 32;
const TIME_OF_DAY_RE = /^([01]?[0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$/;

// validTimeWindowJSON validates the time constraint's value grammar (§8.1,
// rev CLC-1.3): a non-empty JSON array of ≤32 objects, each exactly
// {start,end} of a time-of-day (HH:MM[:SS]) treated as UTC, daily-repeating.
// Each segment is SAME-DAY: startSod < endSod where the reserved end "00:00"
// denotes next-day midnight (86400s) — a single segment may not cross
// midnight (22:00→06:00 is invalid and must be split), the full-day segment
// 00:00→00:00 is invalid, and the list must be ascending and non-overlapping
// (touching allowed).
function validTimeWindowJSON(raw: string): boolean {
    let segments: unknown;
    try {
        segments = JSON.parse(raw);
    } catch (e) {
        return false;
    }
    if (!Array.isArray(segments) || segments.length === 0 || segments.length > MAX_TIME_WINDOWS) {
        return false;
    }
    let prevEnd = -1;
    for (const s of segments) {
        if (!isPlainObject(s)) {
            return false;
        }
        const keys = Object.keys(s).sort();
        if (keys.length !== 2 || keys[0] !== 'end' || keys[1] !== 'start') {
            return false;
        }
        const start = s['start'];
        const end = s['end'];
        if (typeof start !== 'string' || typeof end !== 'string') {
            return false;
        }
        if (!TIME_OF_DAY_RE.test(start) || !TIME_OF_DAY_RE.test(end)) {
            return false;
        }
        const startSod = secondsOfDay(start);
        let endSod = secondsOfDay(end);
        if (end === '00:00') {
            endSod = 86400; // reserved: next-day midnight
        }
        if (startSod >= endSod) {
            return false; // same-day start before end
        }
        if (start === '00:00' && end === '00:00') {
            return false; // full-day segment is invalid
        }
        if (prevEnd >= 0 && startSod < prevEnd) {
            return false; // not ascending / overlapping (touching allowed)
        }
        prevEnd = endSod;
    }
    return true;
}

// secondsOfDay converts an HH:MM[:SS] string to seconds since midnight.
function secondsOfDay(t: string): number {
    const p = t.split(':').map((x) => parseInt(x, 10));
    const s = p.length === 3 ? p[2] : 0;
    return p[0] * 3600 + p[1] * 60 + s;
}

const IPV4_CIDR_RE = /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[12][0-9]|3[0-2])$/;
const IPV6_SHAPE_RE = /^[0-9a-fA-F:]+$/;

function validIPv4Octets(ip: string): boolean {
    for (const p of ip.split('.')) {
        const n = Number(p);
        if (!Number.isInteger(n) || n < 0 || n > 255) {
            return false;
        }
    }
    return true;
}

// validCIDRString validates a numeric CIDR string (shape-only, §8.1 value
// grammar; the core does not evaluate network constraints — that is the
// scheme's job per §11).  Plugs the stdlib-IP-parse gap: parsed entirely by
// hand so the Go/Python/TS accept sets stay identical.
function validCIDRString(s: string): boolean {
    const slash = s.lastIndexOf('/');
    if (slash <= 0 || slash === s.length - 1) {
        return false;
    }
    const ipPart = s.slice(0, slash);
    const prefix = s.slice(slash + 1);
    if (!isStrictJSONInteger(prefix)) {
        return false;
    }
    const mask = parseInt(prefix, 10);
    if (mask < 0 || mask > 128) {
        return false;
    }
    if (ipPart.includes(':')) {
        if (mask > 128) {
            return false;
        }
        // Shape-only: allow "::"-compressed forms; reject a lone trailing ":".
        return IPV6_SHAPE_RE.test(ipPart) && !(ipPart.endsWith(':') && !ipPart.endsWith('::'));
    }
    if (mask > 32) {
        return false;
    }
    return IPV4_CIDR_RE.test(s) && validIPv4Octets(ipPart);
}

// validCIDRListJSON validates the network constraint's value grammar: a
// non-empty JSON array of ≤32 numeric CIDR strings.
function validCIDRListJSON(raw: string): boolean {
    let list: unknown;
    try {
        list = JSON.parse(raw);
    } catch (e) {
        return false;
    }
    if (!Array.isArray(list) || list.length === 0 || list.length > MAX_CIDR_LIST) {
        return false;
    }
    return list.every((e) => typeof e === 'string' && validCIDRString(e));
}

// isParamsLevelReason reports whether an entailment failure is a params-level
// reason (propagated by authorize) rather than an ID-level reason (collapsed
// to capability_not_authorized per CLC-v1 §9 step 3 + §9.3 note).
export function isParamsLevelReason(reason: string): boolean {
    const prefixes = [
        'params_missing',
        'undeclared_param',
        'params_exceed_grant',
        'empty_bound_denies_class',
        'not_in_enum',
        'invalid_params_null',
        'invalid_params_duplicate_key',
        'invalid_params_number',
        'invalid_params_size',
        'unsupported_language_revision',
    ];
    return prefixes.some((p) => reason.startsWith(p));
}

// authorize evaluates the decision function per CLC-v1 §9.
export function authorize(
    effectiveGrant: Grant | null | undefined,
    op: Operation | null | undefined,
): Decision {
    // Single effective grant (§9.3 single-grant path).
    return authorizeSet([effectiveGrant], op);
}

// authorizeSet evaluates the §9.3 multi-grant aggregation (rev CLC-1.3):
//   - grants all absent (null or empty id) → deny capability_not_authorized
//     (resolved before any layer check, per §9.3 pre-check);
//   - otherwise operation layer-1 validation runs first (id, params null);
//   - each grant whose id covers the operation is a covering grant; params
//     (paramsSubset) then constraints (validate/check) are evaluated;
//   - ANY covering grant whose params+constraints fully allow authorizes the
//     operation (union semantics);
//   - residual obligations (recognized-but-unevaluated constraints) union
//     across the covering-and-allowing grants → allow_unresolved;
//   - if no covering grant allows: params/constraint-level denials surface as
//     the first covering grant's reason in canonical (input) order; grants
//     that did not cover collapse to capability_not_authorized.
export function authorizeSet(
    grants: Array<Grant | null | undefined>,
    op: Operation | null | undefined,
): Decision {
    if (!grants.some((g) => g && g.id)) {
        return { verdict: VERDICT_DENY, reason: 'capability_not_authorized' };
    }

    // Absent operation → fail-closed (layer 1).
    if (op == null || !op.id) {
        return { verdict: VERDICT_DENY, reason: 'missing_capability_id' };
    }

    // Step 1: validate the operation. The specific layer-1 code is propagated
    // (missing / unsupported_wildcard / invalid_capability_id).
    try {
        validateCapabilityId(op.id);
    } catch (e) {
        return { verdict: VERDICT_DENY, reason: (e as SemanticsError).message };
    }

    // Validate operation params for null (§9.3 layer 6).
    try {
        validateParams(op.params);
    } catch (e) {
        return { verdict: VERDICT_DENY, reason: (e as SemanticsError).message };
    }

    // Step 2/3 across the grant set.
    const unresolved: string[] = [];
    let denyReasonFirst = ''; // first covering-grant params/constraint-layer denial (input order)
    let anyAllowed = false;
    for (const g of grants) {
        if (!g || !g.id) {
            continue;
        }
        const result = entails(g, op);
        if (!result.entails) {
            const reason = result.reason ?? '';
            if (isParamsLevelReason(reason) && !denyReasonFirst) {
                denyReasonFirst = reason;
            }
            continue;
        }

        // Evaluate constraints (layer 11; §9 step 4, rev CLC-1.3).
        let failed = false;
        const pg: string[] = [];
        for (const c of g.constraints ?? []) {
            try {
                validateConstraint(c);
            } catch (e) {
                failed = true;
                if (!denyReasonFirst) {
                    denyReasonFirst = (e as SemanticsError).message;
                }
                break;
            }
            const violation = checkConstraint(c, op);
            if (violation) {
                failed = true;
                if (!denyReasonFirst) {
                    denyReasonFirst = violation;
                }
                break;
            }
            if (!coreEvaluatesConstraint(c)) {
                pg.push(c);
            }
        }
        if (failed) {
            continue;
        }
        // This covering grant authorizes the operation; keep scanning so the
        // residual-obligation union is stable across grant order.
        anyAllowed = true;
        unresolved.push(...pg);
    }

    if (!anyAllowed) {
        if (denyReasonFirst) {
            return { verdict: VERDICT_DENY, reason: denyReasonFirst };
        }
        return { verdict: VERDICT_DENY, reason: 'capability_not_authorized' };
    }
    const uniq = [...new Set(unresolved)].sort();
    if (uniq.length > 0) {
        return { verdict: VERDICT_ALLOW_UNRESOLVED, unresolved: uniq };
    }
    return { verdict: VERDICT_ALLOW };
}