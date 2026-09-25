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
    param_bounds?: Record<string, unknown> | null;
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

// ContainmentResult is the §13.3 return shape of contains() — the JSON object
// {contains, reason}.  Rev CLC-1.15: the public surface no longer reuses the
// entailment's MatchResult{entails}, so a caller reads the §13.3 field names
// directly and no runner needs a translation layer.  `reason` is empty on
// success and carries the first failing layer's code on failure.
export interface ContainmentResult {
    contains: boolean;
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
// (rev CLC-1.15 · 2026-09-25: corrective — the §6.6 cross-family numeric ×
// enum meet is refused (invalid_params_binding) in either order instead of
// reducing to the filtered enum; ConstraintUnion sorts in UTF-8 byte order
// (§7.1); contains() returns the §13.3 {contains, reason} shape.  Inputs
// without param_bounds are unaffected; CLC-1.14 and earlier inputs still
// read.)
export const CLC_REVISION = 'CLC-1.15';
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
    // A bare $ anchor also matches before a trailing newline; the
    // (?![\s\S]) end-of-string assertion rejects stray "\n" (audit R13).
    if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9-]+-v[0-9]+$(?![\s\S])/.test(parts[0])) {
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
    if (params == null) {
        // Absent (null/undefined) is unconstrained.  Note the explicit
        // null-check (not a falsy check): a falsy scalar like 0/""/false is
        // NOT an absent object — it must be rejected as invalid_params_number
        // below, mirroring Python (audit 2026-09-16, R5/F8; previously a
        // falsy scalar slipped through here).
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
        if (Object.keys(grantVal).length === 0) {
            // rev CLC-1.3: an empty params object is unconstrained (§9.3),
            // at every nesting depth — it declares no keys, no closure.
            return [true, ''];
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
        // §9.3 layer 7 (request side): key closure recurses — every op key
        // inside a nested object must be declared by the grant key (audit
        // 2026-09-16, R16), resolved after the missing-key check above.
        for (const k of Object.keys(opVal)) {
            if (!(k in grantVal)) {
                return [false, `undeclared_param: ${k}`];
            }
        }
        return [true, ''];
    }

    // Exact equality (fallback).
    return jsonEqual(opVal, grantVal) ? [true, ''] : [false, 'params_exceed_grant'];
}

// ---- rev CLC-1.10 §6.5 extended parameter bounds -------------------------

function isNumber(v: unknown): v is number {
    return typeof v === 'number' && Number.isFinite(v);
}

function boundOptional(b: unknown): boolean {
    return isPlainObject(b) && b['optional'] === true;
}

function validateBound(b: unknown): string {
    if (!isPlainObject(b)) {
        return 'invalid_params_binding: bound is not an object';
    }
    let hasNumeric = false;
    let hasEnum = false;
    let hasNested = false;
    for (const k of Object.keys(b)) {
        if (k === 'min' || k === 'max' || k === 'step') {
            hasNumeric = true;
        } else if (k === 'enum' || k === 'min_items' || k === 'max_items') {
            hasEnum = true;
        } else if (k === 'nested') {
            hasNested = true;
        } else if (k === 'optional') {
            if (typeof b[k] !== 'boolean') {
                return 'invalid_params_binding: optional is not a boolean';
            }
        } else {
            return `invalid_params_binding: unknown Bound member ${k}`;
        }
    }
    if ((hasNumeric ? 1 : 0) + (hasEnum ? 1 : 0) + (hasNested ? 1 : 0) > 1) {
        return 'invalid_params_binding: mixed bound families';
    }
    for (const k of ['min', 'max', 'step']) {
        if (k in b && !isNumber(b[k])) {
            return `invalid_params_binding: ${k} is not a number`;
        }
    }
    if (isNumber(b['step']) && b['step'] <= 0) {
        return 'invalid_params_binding: step must be positive';
    }
    if (isNumber(b['min']) && isNumber(b['max']) && b['min'] > b['max']) {
        return 'invalid_params_binding: min > max';
    }
    if ('enum' in b && !Array.isArray(b['enum'])) {
        return 'invalid_params_binding: enum is not an array';
    }
    for (const k of ['min_items', 'max_items']) {
        if (k in b) {
            const n = b[k];
            if (!isNumber(n) || n < 0 || !Number.isInteger(n)) {
                return `invalid_params_binding: ${k} is not a non-negative integer`;
            }
        }
    }
    if (isNumber(b['min_items']) && isNumber(b['max_items']) && b['min_items'] > b['max_items']) {
        return 'invalid_params_binding: min_items > max_items';
    }
    if ('nested' in b) {
        if (!isPlainObject(b['nested'])) {
            return 'invalid_params_binding: nested is not an object';
        }
        for (const nb of Object.values(b['nested'])) {
            const r = validateBound(nb);
            if (r) {
                return r;
            }
        }
    }
    return '';
}

export function validateParamBounds(
    bounds?: Record<string, unknown> | null,
    params?: Record<string, unknown> | null,
): string {
    if (bounds == null) {
        return '';
    }
    try {
        validateParams(bounds);
    } catch (e) {
        return (e as SemanticsError).message;
    }
    for (const [k, b] of Object.entries(bounds)) {
        if (k === '') {
            return 'invalid_params_binding: empty key';
        }
        if (params != null && k in params) {
            return `invalid_params_binding: ${k} in both params and param_bounds`;
        }
        const r = validateBound(b);
        if (r) {
            return r;
        }
    }
    return '';
}

function isMultipleOf(v: number, step: number): boolean {
    if (step === 0) {
        return false;
    }
    const q = v / step;
    return q === Math.trunc(q) && q * step === v;
}

function nestedSubset(op: Record<string, unknown>, nested: Record<string, unknown>): [boolean, string] {
    for (const [k, b] of Object.entries(nested)) {
        if (!(k in op)) {
            if (boundOptional(b)) {
                continue;
            }
            return [false, 'params_missing'];
        }
        const [ok, reason] = boundSubset(op[k], b);
        if (!ok) {
            return [false, reason];
        }
    }
    for (const k of Object.keys(op)) {
        if (!(k in nested)) {
            return [false, `undeclared_param: ${k}`];
        }
    }
    return [true, ''];
}

function boundSubset(opVal: unknown, bound: unknown): [boolean, string] {
    if (!isPlainObject(bound)) {
        return [false, 'invalid_params_binding'];
    }
    if ('enum' in bound) {
        const gv = bound['enum'];
        if (!Array.isArray(gv)) {
            return [false, 'invalid_params_binding'];
        }
        if (gv.length === 0) {
            return [false, 'empty_bound_denies_class'];
        }
        const elems = Array.isArray(opVal) ? opVal : [opVal];
        for (const o of elems) {
            if (!gv.some((g) => jsonEqual(o, g))) {
                return [false, 'not_in_enum'];
            }
        }
    }
    if ('min_items' in bound || 'max_items' in bound) {
        const card = Array.isArray(opVal) ? opVal.length : 1;
        if (isNumber(bound['min_items']) && card < bound['min_items']) {
            return [false, 'params_cardinality'];
        }
        if (isNumber(bound['max_items']) && card > bound['max_items']) {
            return [false, 'params_cardinality'];
        }
    }
    if ('nested' in bound) {
        if (!isPlainObject(opVal) || !isPlainObject(bound['nested'])) {
            return [false, 'params_exceed_grant'];
        }
        return nestedSubset(opVal, bound['nested']);
    }
    if ('min' in bound || 'max' in bound || 'step' in bound) {
        if (!isNumber(opVal)) {
            return [false, 'params_exceed_grant'];
        }
        if (isNumber(bound['min']) && opVal < bound['min']) {
            return [false, 'params_out_of_range'];
        }
        if (isNumber(bound['max']) && opVal > bound['max']) {
            return [false, 'params_out_of_range'];
        }
        if (isNumber(bound['step']) && !isMultipleOf(opVal, bound['step'])) {
            return [false, 'params_not_multiple'];
        }
    }
    return [true, ''];
}

// ---- rev CLC-1.14 §6.6 BoundMeet -----------------------------------------

function canonicalEnumMembers(members: unknown[]): unknown[] {
    const seen = new Map<string, unknown>();
    for (const m of members) {
        let k: string;
        try {
            k = canonicalJSON(m);
        } catch {
            k = String(m);
        }
        if (!seen.has(k)) {
            seen.set(k, m);
        }
    }
    return [...seen.keys()].sort().map((k) => seen.get(k));
}

function boundFamily(b: unknown): string {
    if (!isPlainObject(b)) {
        return 'invalid';
    }
    if ('nested' in b) {
        return 'nested';
    }
    if ('enum' in b || 'min_items' in b || 'max_items' in b) {
        return 'enum';
    }
    if ('min' in b || 'max' in b || 'step' in b) {
        return 'numeric';
    }
    return 'none';
}

function boundDeniesClass(b: unknown): boolean {
    if (!isPlainObject(b)) {
        return false;
    }
    const e = b['enum'];
    if (Array.isArray(e) && e.length === 0) {
        return true;
    }
    const nm = b['nested'];
    if (isPlainObject(nm)) {
        return Object.values(nm).some((x) => boundDeniesClass(x));
    }
    return false;
}

function boundsDenyClass(bounds: unknown): boolean {
    return isPlainObject(bounds) && Object.values(bounds).some((b) => boundDeniesClass(b));
}

function copyBound(src: Record<string, unknown>, optional: boolean): Record<string, unknown> {
    const res: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(src)) {
        if (k !== 'optional') {
            res[k] = v;
        }
    }
    if (optional) {
        res['optional'] = true;
    }
    return res;
}

function numericMeet(a: Record<string, unknown>, b: Record<string, unknown>): [Record<string, unknown>, string] {
    const res: Record<string, unknown> = {};
    const amin = a['min'];
    const bmin = b['min'];
    if (isNumber(amin) && isNumber(bmin)) {
        res['min'] = amin > bmin ? amin : bmin;
    } else if (isNumber(amin)) {
        res['min'] = amin;
    } else if (isNumber(bmin)) {
        res['min'] = bmin;
    }
    const amax = a['max'];
    const bmax = b['max'];
    if (isNumber(amax) && isNumber(bmax)) {
        res['max'] = amax < bmax ? amax : bmax;
    } else if (isNumber(amax)) {
        res['max'] = amax;
    } else if (isNumber(bmax)) {
        res['max'] = bmax;
    }
    const as = a['step'];
    const bs = b['step'];
    if (isNumber(as) && isNumber(bs)) {
        if (isMultipleOf(as, bs)) {
            res['step'] = as;
        } else if (isMultipleOf(bs, as)) {
            res['step'] = bs;
        } else {
            return [{}, 'invalid_params_binding'];
        }
    } else if (isNumber(as)) {
        res['step'] = as;
    } else if (isNumber(bs)) {
        res['step'] = bs;
    }
    if (isNumber(res['min']) && isNumber(res['max']) && (res['min'] as number) > (res['max'] as number)) {
        return [{}, 'no_overlap'];
    }
    return [res, ''];
}

function enumMeet(a: Record<string, unknown>, b: Record<string, unknown>): [Record<string, unknown>, string] {
    const res: Record<string, unknown> = {};
    const ae = a['enum'];
    const be = b['enum'];
    if (Array.isArray(ae) && Array.isArray(be)) {
        const inter = ae.filter((x) => be.some((y) => jsonEqual(x, y)));
        if (inter.length === 0) {
            return [{}, 'no_overlap'];
        }
        res['enum'] = canonicalEnumMembers(inter);
    } else if (Array.isArray(ae)) {
        res['enum'] = [...ae];
    } else if (Array.isArray(be)) {
        res['enum'] = [...be];
    }
    const amin = a['min_items'];
    const bmin = b['min_items'];
    if (isNumber(amin) && isNumber(bmin)) {
        res['min_items'] = amin > bmin ? amin : bmin;
    } else if (isNumber(amin)) {
        res['min_items'] = amin;
    } else if (isNumber(bmin)) {
        res['min_items'] = bmin;
    }
    const amax = a['max_items'];
    const bmax = b['max_items'];
    if (isNumber(amax) && isNumber(bmax)) {
        res['max_items'] = amax < bmax ? amax : bmax;
    } else if (isNumber(amax)) {
        res['max_items'] = amax;
    } else if (isNumber(bmax)) {
        res['max_items'] = bmax;
    }
    if (isNumber(res['min_items']) && isNumber(res['max_items']) && (res['min_items'] as number) > (res['max_items'] as number)) {
        return [{}, 'no_overlap'];
    }
    return [res, ''];
}

function nestedMeet(a: Record<string, unknown>, b: Record<string, unknown>): [Record<string, unknown>, string] {
    const an = a['nested'];
    const bn = b['nested'];
    if (!isPlainObject(an) || !isPlainObject(bn) || Object.keys(an).length !== Object.keys(bn).length) {
        return [{}, 'no_overlap'];
    }
    const res: Record<string, unknown> = {};
    for (const [k, av] of Object.entries(an)) {
        if (!(k in bn)) {
            return [{}, 'no_overlap'];
        }
        const [m, err] = boundMeet(av, bn[k]);
        if (err) {
            return [{}, err];
        }
        res[k] = m;
    }
    return [{ nested: res }, ''];
}

function boundMeet(a: unknown, b: unknown): [Record<string, unknown>, string] {
    if (!isPlainObject(a) || !isPlainObject(b)) {
        return [{}, 'invalid_params_binding'];
    }
    const af = boundFamily(a);
    const bf = boundFamily(b);
    if (af === 'invalid' || bf === 'invalid') {
        return [{}, 'invalid_params_binding'];
    }
    const opt = boundOptional(a) && boundOptional(b);
    if (af === 'none' || bf === 'none') {
        return [copyBound(af === 'none' ? b : a, opt), ''];
    }
    let res: Record<string, unknown>;
    let err: string;
    if (af === 'numeric' && bf === 'numeric') {
        [res, err] = numericMeet(a, b);
    } else if (af === 'enum' && bf === 'enum') {
        [res, err] = enumMeet(a, b);
    } else if (af === 'nested' && bf === 'nested') {
        [res, err] = nestedMeet(a, b);
    } else if ((af === 'numeric' && bf === 'enum') || (af === 'enum' && bf === 'numeric')) {
        // rev CLC-1.15 §6.6: a cross-family numeric × enum meet has no sound
        // representation — the CLC-1.14 filtered-enum result was broader than
        // either source (it accepted array requests, e.g. [3], that the numeric
        // side fail-closes at §6.5 layer 9).  Refused in either source order
        // and regardless of whether any member falls inside the numeric range:
        // the family clash is decided before any member or range math.
        return [{}, 'invalid_params_binding'];
    } else if (af === 'nested' || bf === 'nested') {
        // scalar (numeric/enum) ∩ object (nested), either order: refused like
        // the numeric × enum pair — no single-family Bound can carry both the
        // scalar side's shape constraint and the object recursion (§6.6 rev
        // CLC-1.15; design-notes D12).  The family clash is decided before any
        // member, range or key-set math.
        return [{}, 'invalid_params_binding'];
    } else {
        return [{}, 'invalid_params_binding'];
    }
    if (err) {
        return [{}, err];
    }
    return [copyBound(res, opt), ''];
}

function intersectBounds(
    a: Record<string, unknown>,
    b: Record<string, unknown>,
): Record<string, unknown> {
    const out: Record<string, unknown> = { ...a };
    for (const [k, bv] of Object.entries(b)) {
        if (k in out) {
            const [m, err] = boundMeet(out[k], bv);
            if (err) {
                throw new SemanticsError(err);
            }
            out[k] = m;
        } else {
            out[k] = bv;
        }
    }
    return out;
}

function entailsDeclared(
    opParams: Record<string, unknown> | null | undefined,
    grantParams: Record<string, unknown>,
    grantBounds: Record<string, unknown>,
): [boolean, string] {
    for (const gv of Object.values(grantParams)) {
        if (isEmptyBound(gv)) {
            return [false, 'empty_bound_denies_class'];
        }
    }
    for (const [k, gv] of Object.entries(grantParams)) {
        if (gv === null) {
            return [false, `invalid_params_null: ${k}`];
        }
    }
    if (opParams != null) {
        for (const [k, ov] of Object.entries(opParams)) {
            if (ov === null) {
                return [false, `invalid_params_null: ${k}`];
            }
        }
    }
    for (const k of Object.keys(grantParams)) {
        if (opParams == null || !(k in opParams)) {
            return [false, 'params_missing'];
        }
    }
    for (const [k, b] of Object.entries(grantBounds)) {
        if (boundOptional(b)) {
            continue;
        }
        if (opParams == null || !(k in opParams)) {
            return [false, 'params_missing'];
        }
    }
    if (opParams != null) {
        for (const k of Object.keys(opParams)) {
            if (!(k in grantParams) && !(k in grantBounds)) {
                return [false, `undeclared_param: ${k}`];
            }
        }
    }
    for (const [k, gv] of Object.entries(grantParams)) {
        const [ok, reason] = valueSubset(opParams ? opParams[k] : undefined, gv);
        if (!ok) {
            return [false, reason];
        }
    }
    for (const [k, b] of Object.entries(grantBounds)) {
        if (opParams == null || !(k in opParams)) {
            continue;
        }
        const [ok, reason] = boundSubset(opParams[k], b);
        if (!ok) {
            return [false, reason];
        }
    }
    return [true, ''];
}

function boundWithin(child: unknown, parent: unknown): string | null {
    if (!isPlainObject(child) || !isPlainObject(parent)) {
        return 'params_not_narrower';
    }
    if (!boundOptional(parent) && boundOptional(child)) {
        return 'params_not_narrower';
    }
    if (isNumber(parent['min'])) {
        if (!isNumber(child['min']) || child['min'] < parent['min']) {
            return 'params_not_narrower';
        }
    }
    if (isNumber(parent['max'])) {
        if (!isNumber(child['max']) || child['max'] > parent['max']) {
            return 'params_not_narrower';
        }
    }
    if (isNumber(parent['step'])) {
        if (!isNumber(child['step']) || !isMultipleOf(child['step'], parent['step'])) {
            return 'params_not_narrower';
        }
    }
    if (Array.isArray(parent['enum'])) {
        if (!Array.isArray(child['enum'])) {
            return 'params_not_narrower';
        }
        const pe = parent['enum'];
        for (const e of child['enum'] as unknown[]) {
            if (!pe.some((p) => jsonEqual(e, p))) {
                return 'params_not_narrower';
            }
        }
    }
    if (isNumber(parent['min_items'])) {
        if (!isNumber(child['min_items']) || child['min_items'] < parent['min_items']) {
            return 'params_not_narrower';
        }
    }
    if (isNumber(parent['max_items'])) {
        if (!isNumber(child['max_items']) || child['max_items'] > parent['max_items']) {
            return 'params_not_narrower';
        }
    }
    if (isPlainObject(parent['nested'])) {
        if (!isPlainObject(child['nested'])) {
            return 'params_not_narrower';
        }
        const pn = parent['nested'];
        const cn = child['nested'];
        for (const [k, pbn] of Object.entries(pn)) {
            if (!(k in cn)) {
                return 'params_not_narrower';
            }
            if (boundWithin(cn[k], pbn) != null) {
                return 'params_not_narrower';
            }
        }
        for (const k of Object.keys(cn)) {
            if (!(k in pn)) {
                return 'params_not_narrower';
            }
        }
    }
    return null;
}

// materializeDefaults applies the §6.5 scheme-default rule (explicit >
// default > absent); a default never adds a key the grant does not declare.
export function materializeDefaults(
    grant: Grant,
    op: Operation,
    defaults?: Record<string, unknown> | null,
): Operation {
    if (defaults == null || Object.keys(defaults).length === 0) {
        return op;
    }
    const declared = new Set([
        ...Object.keys(grant.params ?? {}),
        ...Object.keys(grant.param_bounds ?? {}),
    ]);
    const params: Record<string, unknown> = { ...(op.params ?? {}) };
    let injected = false;
    for (const [k, dv] of Object.entries(defaults)) {
        if (!declared.has(k)) {
            continue;
        }
        if (!(k in params)) {
            params[k] = dv;
            injected = true;
        }
    }
    if (!injected) {
        return op;
    }
    return { id: op.id, params };
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

    // §6.3 step 3: grant params absent OR the empty OBJECT {} → true
    // (unconstrained; rev CLC-1.3 §9.3 makes {} ≡ absent).  Only absence and
    // {} count: a falsy scalar or an array must NOT be treated as
    // unconstrained — that was a fail-open (audit 2026-09-16, R6); such a
    // grant is invalid_params_number below.  rev CLC-1.10: a grant is
    // unconstrained only when it declares neither params nor param_bounds.
    const gp = grant.params;
    const gb = grant.param_bounds;
    const hasParams = gp != null && isPlainObject(gp) && Object.keys(gp).length > 0;
    const hasBounds = gb != null && isPlainObject(gb) && Object.keys(gb).length > 0;
    if (!hasParams && !hasBounds) {
        return { entails: true };
    }

    // §9.1 layer 2 (rev CLC-1.10): param_bounds grammar + binding rule.
    const bindReason = validateParamBounds(gb, gp);
    if (bindReason) {
        return { entails: false, reason: bindReason };
    }

    // §9.3 layer 6 resolves before presence (layer 7): null values in either
    // side fail before an absent operation params object is judged
    // params_missing (validateParams also applies the §6.2 step 4 object-path
    // size/depth caps, rev CLC-1.2).
    if (hasParams) {
        try {
            validateParams(gp);
        } catch (e) {
            return { entails: false, reason: (e as SemanticsError).message };
        }
    }
    if (op.params != null) {
        try {
            validateParams(op.params);
        } catch (e) {
            return { entails: false, reason: (e as SemanticsError).message };
        }
    }

    // §6.3 steps 4–5: presence and params subset over the §6.5 declared set.
    const [ok, reason] = entailsDeclared(
        op.params,
        (isPlainObject(gp) ? gp : {}) as Record<string, unknown>,
        (isPlainObject(gb) ? gb : {}) as Record<string, unknown>,
    );
    if (!ok) {
        return { entails: false, reason };
    }

    return { entails: true };
}

// Contains reports whether a child grant stays inside a parent grant's
// declared authorization boundary, per draft-wei-clc-ext-00 §4 (CLD-D).
//
// The relation is compared on DECLARED sets and DECLARED bounds, not on
// behavior (CLC-v1 §12 keeps that scope).  If any layer of §4 fails,
// Contains is false with the first failing layer's reason code.  The return
// is the §13.3 ContainmentResult shape {contains, reason} (rev CLC-1.15) —
// the same field names the relation signature defines.  Layer
// semantics match the extension draft:
//   - layer 1: both grants valid (identifier + params grammar);
//   - layer 2: child id covered by parent id via CLC-v1 path coverage;
//   - layer 3: child params within parent's declared bounds and child key
//     set closed by parent.
//
// Constraints are deliberately NOT part of this relation.  Constraints are a
// separate axis that composes by UNION (conjunction) across a delegation chain
// (see intersect, §7), not by subset: a child's constraint set is never
// compared to its parent's here.  Delegation mode is likewise a carrier
// concept (AIC-JWT DA binds it); the language relation takes no mode.
export function contains(parent: Grant, child: Grant): ContainmentResult {
    // Layer 1: grant validity — fail-closed on either side.  The reason is a
    // valid CLC-A code (invalid_capability_id, invalid_params_*).
    for (const g of [parent, child]) {
        try {
            validateCapabilityId(g.id);
        } catch (e) {
            return { contains: false, reason: (e as SemanticsError).message };
        }
        if (g.params != null) {
            try {
                validateParams(g.params);
            } catch (e) {
                return { contains: false, reason: (e as SemanticsError).message };
            }
        }
        const bindReason = validateParamBounds(g.param_bounds, g.params);
        if (bindReason) {
            return { contains: false, reason: bindReason };
        }
    }

    // Layer 2: identifier coverage — the CLC-v1 path-coverage relation,
    // parameters excluded.  The extension §4.2 keeps the core's
    // different_namespace for scheme/action-class mismatch and collapses every
    // other coverage failure into the layer-2 reason child_exceeds_parent.
    const [okId, idReason] = matchId(parent.id, child.id);
    if (!okId) {
        if (idReason === 'different_namespace') {
            return { contains: false, reason: idReason };
        }
        return { contains: false, reason: 'child_exceeds_parent' };
    }

    // Layer 3: parameter narrowing.
    const pp = parent.params;
    const cp = child.params;
    const pbn = parent.param_bounds;
    const cbn = child.param_bounds;
    const ppEmpty = pp == null || (isPlainObject(pp) && Object.keys(pp).length === 0);
    const cpEmpty = cp == null || (isPlainObject(cp) && Object.keys(cp).length === 0);
    const pbnEmpty = pbn == null || (isPlainObject(pbn) && Object.keys(pbn).length === 0);
    const cbnEmpty = cbn == null || (isPlainObject(cbn) && Object.keys(cbn).length === 0);
    if (ppEmpty && pbnEmpty) {
        // Parent unconstrained (absent OR {}): contains any child params.
    } else if (cpEmpty && cbnEmpty) {
        // Child unconstrained under a bounded parent: declaring nothing is
        // not "a subset of the parent's bounds" (§4.3 extra rule).
        return { contains: false, reason: 'params_not_narrower' };
    } else {
        const parentParams = (pp ?? {}) as Record<string, unknown>;
        const childParams = (cp ?? {}) as Record<string, unknown>;
        const parentBounds = (pbn ?? {}) as Record<string, unknown>;
        const childBounds = (cbn ?? {}) as Record<string, unknown>;
        for (const k of Object.keys(parentParams)) {
            if (!(k in childParams)) {
                // Child omits the key, or declares it in the other
                // representation (§6.5 binding rule).
                return { contains: false, reason: 'params_not_narrower' };
            }
            if (containsWithin(childParams[k], parentParams[k]) != null) {
                return { contains: false, reason: 'params_not_narrower' };
            }
        }
        for (const k of Object.keys(parentBounds)) {
            if (!(k in childBounds)) {
                return { contains: false, reason: 'params_not_narrower' };
            }
            if (boundWithin(childBounds[k], parentBounds[k]) != null) {
                return { contains: false, reason: 'params_not_narrower' };
            }
        }
        // Key closure is symmetric: a child that adds a key the parent does
        // not declare allows operations the parent denies (undeclared_param).
        for (const k of Object.keys(childParams)) {
            if (!(k in parentParams)) {
                return { contains: false, reason: 'params_not_narrower' };
            }
        }
        for (const k of Object.keys(childBounds)) {
            if (!(k in parentBounds)) {
                return { contains: false, reason: 'params_not_narrower' };
            }
        }
    }

    return { contains: true, reason: '' };
}

// containsWithin reports whether a child declared value is within a parent
// declared bound using the same JSON subset semantic as §5.2 valueSubset
// (numbers as upper bounds, arrays as membership sets, objects per key).
function containsWithin(childVal: unknown, parentBound: unknown): string | null {
    if (childVal == null) {
        return 'invalid_params_null';
    }
    if (parentBound == null) {
        return null;
    }
    const [ok, reason] = valueSubset(childVal, parentBound);
    return ok ? null : reason;
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

    // rev CLC-1.14 §6.6: an explicit empty enum in a Bound denies the class.
    for (const g of grants) {
        if (boundsDenyClass(g.param_bounds)) {
            throw new SemanticsError('empty_bound_denies_class');
        }
    }

    // rev CLC-1.14 §6.6 "Key site": a key declared in params by one source and
    // in param_bounds by another is refused.
    const paramsKeys = new Set<string>();
    const boundsKeys = new Set<string>();
    for (const g of grants) {
        for (const k of Object.keys(g.params ?? {})) {
            paramsKeys.add(k);
        }
        for (const k of Object.keys(g.param_bounds ?? {})) {
            boundsKeys.add(k);
        }
    }
    for (const k of boundsKeys) {
        if (paramsKeys.has(k)) {
            throw new SemanticsError('invalid_params_binding');
        }
    }

    // Start with the first grant.
    const result: Grant = {
        id: grants[0].id,
        params: grants[0].params,
        param_bounds: grants[0].param_bounds ? { ...grants[0].param_bounds } : grants[0].param_bounds,
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

        // §6.6 BoundMeet (rev CLC-1.14): union keys, meet shared ones.
        const rb = result.param_bounds ?? {};
        const gb = g.param_bounds ?? {};
        if (Object.keys(rb).length > 0 && Object.keys(gb).length > 0) {
            result.param_bounds = intersectBounds(rb, gb);
        } else if (Object.keys(gb).length > 0) {
            result.param_bounds = { ...gb };
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
        // rev CLC-1.10/1.14: extended-bound reason codes are params-level too.
        'params_cardinality',
        'params_out_of_range',
        'params_not_multiple',
        'invalid_params_binding',
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

// authorizeJsonText is the normative entry point for a caller that holds the
// operation's params as JSON text: validateRawParams runs the §6.2
// input-boundary checks on that text and returns the decoded object, so one
// call covers the boundary and the decision.  Prefer it over JSON.parse
// followed by authorizeSet, because the parse is lossy for exactly the inputs
// §6.2 refuses (§6.2 item 7).  rawParams may be empty for an operation that
// carries no params; a refusal is returned as deny with the §6.2 reason code.
export function authorizeJsonText(
    grants: Array<Grant | null | undefined>,
    opId: string,
    rawParams = '',
): Decision {
    if (!rawParams) {
        return authorizeSet(grants, { id: opId });
    }
    let params: Record<string, unknown>;
    try {
        params = validateRawParams(rawParams);
    } catch (error) {
        if (error instanceof SemanticsError) {
            return { verdict: VERDICT_DENY, reason: error.message };
        }
        throw error;
    }
    return authorizeSet(grants, { id: opId, params });
}

// The caller must already have run the §6.2 input-boundary checks on the text
// it received, if it received text.  A params value that has been through a
// JSON decoder no longer carries the information those checks use: a decoder
// that repairs an invalid surrogate or octet produces a value indistinguishable
// from a legitimate U+FFFD (§6.2 item 7).  A caller holding the raw text should
// call authorizeJsonText.
//
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
    const uniq = [...new Set(unresolved)].sort(utf8ByteCompare);
    if (uniq.length > 0) {
        return { verdict: VERDICT_ALLOW_UNRESOLVED, unresolved: uniq };
    }
    return { verdict: VERDICT_ALLOW };
}
// Resolution is a consumer's per-obligation report to resolve() (§8.5, rev
// CLC-1.11).
export interface Resolution {
    constraint: string;
    status: 'satisfied' | 'violated' | 'unknown';
}

const VALID_RESOLUTION_STATUSES = new Set(['satisfied', 'violated', 'unknown']);
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function validNow(now: string): Date | null {
    if (!RFC3339_RE.test(now)) {
        return null;
    }
    const d = new Date(now);
    if (Number.isNaN(d.getTime())) {
        return null;
    }
    return d;
}

// evalCoreTimeWindow returns true (in window) / false (outside) when c is a
// core-recognized §8.1 time:window obligation, else null (not core-evaluable).
function evalCoreTimeWindow(c: string, now: Date): boolean | null {
    try {
        validateConstraint(c);
    } catch {
        return null;
    }
    const parts = c.split(':');
    if (parts.length < 2 || `${parts[0]}:${parts[1]}` !== `${RESERVED_SCHEME}:time`) {
        return null;
    }
    const joined = constraintParams(c);
    if (!joined.startsWith('window:')) {
        return null;
    }
    let segments: Array<{ start: string; end: string }>;
    try {
        segments = JSON.parse(joined.slice('window:'.length));
    } catch {
        return null;
    }
    const sod = now.getUTCHours() * 3600 + now.getUTCMinutes() * 60 + now.getUTCSeconds();
    for (const seg of segments) {
        const start = secondsOfDay(seg.start);
        let end = secondsOfDay(seg.end);
        if (seg.end === '00:00') {
            end = 86400;
        }
        if (sod >= start && sod < end) {
            return true;
        }
    }
    return false;
}

function violatedReason(c: string): string {
    const parts = c.split(':');
    if (parts.length >= 2 && parts[1]) {
        return `${parts[1]}:violated`;
    }
    return 'violated';
}

function stricterStatus(a: 'satisfied' | 'violated' | 'unknown', b: 'satisfied' | 'violated' | 'unknown'): 'satisfied' | 'violated' | 'unknown' {
    const rank: Record<string, number> = { violated: 2, satisfied: 1, unknown: 0 };
    return rank[b] > rank[a] ? b : a;
}

// resolve collapses a decision's §8.4 obligations with consumer reports and an
// optional clock (§8.5, rev CLC-1.11).  Deterministic, fail-closed, idempotent
// and monotone; terminal deny/allow decisions pass through unchanged; it
// neither invents nor drops obligations.
export function resolve(
    decision: Decision,
    resolutions: Resolution[] = [],
    now?: string | null,
): Decision {
    // Rule 1: terminal verdicts are fixed.
    if (decision.verdict === VERDICT_DENY || decision.verdict === VERDICT_ALLOW) {
        return { ...decision };
    }
    if (decision.verdict !== VERDICT_ALLOW_UNRESOLVED) {
        return { verdict: VERDICT_DENY, reason: 'invalid_resolution' };
    }

    // Rule 2: malformed input fails closed, before any discharge.
    for (const r of resolutions) {
        if (!r || !r.constraint || !VALID_RESOLUTION_STATUSES.has(r.status)) {
            return { verdict: VERDICT_DENY, reason: 'invalid_resolution' };
        }
    }
    let nowDate: Date | null = null;
    if (now !== undefined && now !== null) {
        nowDate = validNow(now);
        if (nowDate === null) {
            return { verdict: VERDICT_DENY, reason: 'invalid_timestamp' };
        }
    }

    // Rules 3-5: status per obligation, most-restrictive-first.
    const obligations = [...new Set(decision.unresolved ?? [])].sort(utf8ByteCompare);
    const remainder: string[] = [];
    for (const o of obligations) {
        let status: 'satisfied' | 'violated' | 'unknown' = 'unknown';
        for (const r of resolutions) {
            if (r.constraint === o) {
                status = stricterStatus(status, r.status);
            }
        }
        if (nowDate !== null) {
            const clock = evalCoreTimeWindow(o, nowDate);
            if (clock === true) {
                status = stricterStatus(status, 'satisfied');
            } else if (clock === false) {
                status = stricterStatus(status, 'violated');
            }
        }
        if (status === 'violated') {
            return { verdict: VERDICT_DENY, reason: violatedReason(o) };
        }
        if (status !== 'satisfied') {
            remainder.push(o);
        }
    }

    if (remainder.length === 0) {
        return { verdict: VERDICT_ALLOW };
    }
    return { verdict: VERDICT_ALLOW_UNRESOLVED, unresolved: remainder };
}

// utf8ByteCompare orders two strings by their UTF-8 encodings, octet by
// octet (§7.1, rev CLC-1.15).  JavaScript's default `<`/`sort()` compares
// UTF-16 code units, which places supplementary-plane characters (surrogate
// pairs, first unit U+D800–U+DBFF) BEFORE U+E000–U+FFFF characters although
// their code points are higher; UTF-8 octet order equals code-point order for
// well-formed text and is the collation all three implementations share.
const utf8Encoder = new TextEncoder();
function utf8ByteCompare(a: string, b: string): number {
    const ba = utf8Encoder.encode(a);
    const bb = utf8Encoder.encode(b);
    const n = Math.min(ba.length, bb.length);
    for (let i = 0; i < n; i++) {
        if (ba[i] !== bb[i]) {
            return ba[i] - bb[i];
        }
    }
    return ba.length - bb.length;
}

// constraintUnion is the derived chain-constraint projection (§7.1, rev
// CLC-1.12): the normalized union of every constraint string carried by the
// grants in chain — duplicates folded, sorted in UTF-8 byte order (rev
// CLC-1.15 pins the collation).  A projection, not a meet: it compares no
// identifiers or params, reads no constraint values and checks no
// containment.  An empty chain fails closed with absent_source (§7 rule 5).
export function constraintUnion(chain: Grant[]): string[] {
    if (chain.length === 0) {
        throw new SemanticsError('absent_source');
    }
    const out = new Set<string>();
    for (const g of chain) {
        for (const c of g.constraints ?? []) {
            out.add(c);
        }
    }
    return [...out].sort(utf8ByteCompare);
}

// authorizeWithChain is the fused chain check (§13.11, rev CLC-1.13, CLC-D):
// each adjacent hop is checked with contains(), and the operation is
// authorized against intersect(chain).  An empty chain denies absent_source;
// the first hop whose containment fails ends the call with that hop's §13.5
// reason code (before op validation); an intersect refusal is returned as
// deny(reason).  Judging the operation against the intersection is what brings
// every ancestor's params and constraints into force — constraints are outside
// containment (a union axis), so authorizing against the leaf alone would be
// unsound.
export function authorizeWithChain(chain: Grant[], op: Operation): Decision {
    if (chain.length === 0) {
        return { verdict: VERDICT_DENY, reason: 'absent_source' };
    }
    for (let i = 0; i + 1 < chain.length; i++) {
        const r = contains(chain[i], chain[i + 1]);
        if (!r.contains) {
            return { verdict: VERDICT_DENY, reason: r.reason ?? 'child_exceeds_parent' };
        }
    }
    let effective: Grant;
    try {
        effective = intersect(chain);
    } catch (e) {
        return { verdict: VERDICT_DENY, reason: (e as Error).message };
    }
    return authorize(effective, op);
}
