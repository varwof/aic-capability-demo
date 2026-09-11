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
    verdict: 'allow' | 'deny';
    reason?: string;
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
// NOTE: Go's known set is {max_rows, time:window, network:cidr} but read via
// parts[1], which per this grammar makes Go reject time:window/network:cidr as
// unknown; the corpus only exercises max_rows and unknown types, so the sets
// behave identically there.  See ambiguities.md.
export const KNOWN_CONSTRAINT_TYPES = new Set(['max_rows', 'time', 'network']);

// CLC-v1 §12.1: the language revision this implementation declares.
export const CLC_REVISION = 'CLC-1.1';
// §6.2 step 4: bounds on the JCS-serialized params form.
export const MAX_PARAMS_SERIALIZED_BYTES = 512;
export const MAX_PARAMS_NESTING = 32;

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
}

// validateParams: reject null parameter values (CLC-v1 §5.2).  The offending
// key is carried as a ": <detail>" suffix (§9.4).
export function validateParams(params?: Record<string, unknown> | null): void {
    if (!params) {
        return;
    }
    for (const [k, v] of Object.entries(params)) {
        if (v === null) {
            throw new SemanticsError(`invalid_params_null: ${k}`);
        }
    }
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
        // caller positioned on the opening '"'
        let out = '';
        i++; // opening quote
        while (i < t.length) {
            const ch = t[i];
            if (ch === '"') {
                i++;
                return out;
            }
            if (ch === '\\') {
                // Keep the escape pair in the compact-length accounting
                // (Go re-marshals the string; Python counts raw in-string
                // bytes; equivalent for ASCII corpus inputs).
                compact += 2;
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
                        out += String.fromCharCode(parseInt(hex, 16));
                        i += 4;
                        break;
                    }
                    default: fail();
                }
                i += 2;
                continue;
            }
            out += ch;
            compact += 1;
            i++;
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
        compact += lit.length;
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
    if (grantParams == null) {
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

    // §6.3 step 3: grant params absent → true (unconstrained).
    if (grant.params == null) {
        return { entails: true };
    }

    // §9.3 layer 6 resolves before presence (layer 7): null values in either
    // side fail before an absent operation params object is judged
    // params_missing. (Go's Entails checks the op-absent case first; the
    // corpus does not exercise the conjunction.)
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
        const result: Record<string, unknown> = {};
        for (const k of Object.keys(a)) {
            if (k in b) {
                result[k] = intersectValue(a[k], b[k]);
            }
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

// validateConstraint checks if a constraint is known (§8.3 grammar:
// scheme:type[:params]; a known type is the second ':'-delimited segment).
export function validateConstraint(c: string): void {
    const parts = c.split(':');
    if (parts.length < 2) {
        throw new SemanticsError('unknown_constraint');
    }
    if (!KNOWN_CONSTRAINT_TYPES.has(parts[1])) {
        throw new SemanticsError('unknown_constraint');
    }
}

// checkConstraint evaluates a known constraint against an operation.
// §8.1 defines the v1 known types; only max_rows has an auth-side evaluator
// here (time/network are accepted as known but have no normative evaluator in
// §8.1 — the corpus only exercises max_rows and unknown types).
export function checkConstraint(c: string, op: Operation): string | null {
    const parts = c.split(':');
    const constraintType = parts[1];
    if (constraintType === 'max_rows' && parts.length >= 3) {
        const maxVal = parseFloat(parts[2]);
        if (!Number.isNaN(maxVal)) {
            const rows = op.params?.max_rows;
            if (typeof rows === 'number' && rows > maxVal) {
                return 'max_rows:violated';
            }
        }
    }
    return null;
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
    // Absent/empty grant: no capability to check → fail-closed (§9.3: drops
    // straight to layer 10, even when the operation is also absent; D15).
    if (effectiveGrant == null || !effectiveGrant.id) {
        return { verdict: 'deny', reason: 'capability_not_authorized' };
    }

    // Absent operation → fail-closed (layer 1).
    if (op == null || !op.id) {
        return { verdict: 'deny', reason: 'missing_capability_id' };
    }

    // Step 1: validate the operation. The specific layer-1 code is propagated
    // (missing / unsupported_wildcard / invalid_capability_id). NOTE: Go's
    // Authorize collapses every op-ID validation error to
    // invalid_capability_id; the corpus only exercises invalid_capability_id
    // in decide vectors. See ambiguities.md.
    try {
        validateCapabilityId(op.id);
    } catch (e) {
        return { verdict: 'deny', reason: (e as SemanticsError).message };
    }

    // Validate operation params for null (§9.3 layer 6).
    try {
        validateParams(op.params);
    } catch (e) {
        return { verdict: 'deny', reason: (e as SemanticsError).message };
    }

    // Step 2: check entailment.
    const result = entails(effectiveGrant, op);
    if (!result.entails) {
        const reason = result.reason ?? '';
        if (isParamsLevelReason(reason)) {
            return { verdict: 'deny', reason };
        }
        return { verdict: 'deny', reason: 'capability_not_authorized' };
    }

    // Step 3: evaluate constraints (layer 11).
    for (const c of effectiveGrant.constraints ?? []) {
        try {
            validateConstraint(c);
        } catch (e) {
            return { verdict: 'deny', reason: (e as SemanticsError).message };
        }
        const violation = checkConstraint(c, op);
        if (violation) {
            return { verdict: 'deny', reason: violation };
        }
    }

    return { verdict: 'allow' };
}