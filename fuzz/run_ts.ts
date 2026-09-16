// CLC differential fuzz: TypeScript runner (Node, zero deps).
//
// Reads the generator's JSONL and, for every case, evaluates BOTH paths with
// the *TypeScript* implementation, mirroring fuzz/run_py.py exactly:
//   - raw_path:     §6.2 raw-text normalization via validateRawParams, then
//                   authorizeSet.
//   - decoded_path: skip raw-text validation; JSON.parse the same text and
//                   authorizeSet directly (native parser collapses dup keys,
//                   accepts lone surrogate escapes, huge numbers -> Infinity).
//   - canonical_sha256: sha256 of canonicalJSON(decoded params value);
//                   "" when no value is producible.
//
// Emits result JSONL:
//   {"id":..., "impl":"ts", "raw_path":{...}, "decoded_path":{...},
//    "canonical_sha256":"..."}
// On an uncaught exception emits {"id":..., "impl":"ts", "error":"..."}.
//
// Usage: node --script=false --disable-warning=ExperimentalWarning \
//         --experimental-strip-types fuzz/run_ts.ts <cases.jsonl>
// (or: npx --yes tsx fuzz/run_ts.ts <cases.jsonl>)

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import {
    SemanticsError,
    authorizeSet,
    canonicalJSON,
    canonicalReason,
    validateRawParams,
} from '../ts/clc_semantics.ts';

function canon(reason?: string): string {
    return canonicalReason(reason ?? '');
}

// authorize runs the decision layer.  Only SemanticsError is a clean denial;
// any other exception (e.g. TypeError on non-object params) is a crash and is
// intentionally propagated so it is recorded as an "unstable" incident.
function authorize(grants: unknown[], op: unknown): { verdict: string; reason: string; unresolved?: string[] } {
    const d = authorizeSet(grants as never[], op as never);
    const out: { verdict: string; reason: string; unresolved?: string[] } = {
        verdict: d.verdict,
        reason: canon(d.reason),
    };
    if (d.unresolved && d.unresolved.length > 0) {
        out.unresolved = d.unresolved;
    }
    return out;
}

function decodeRaw(raw: string): unknown {
    return JSON.parse(raw);
}

// Mirror Python's surrogateescape so invalid UTF-8 bytes are preserved as
// lone surrogates (U+DC00+byte) rather than Latin-1 chars or U+FFFD.  This
// keeps the three runners comparing the same logical byte stream.
function decodeUtf8SurrogateEscape(buf: Buffer): string {
    const out: string[] = [];
    const n = buf.length;
    for (let i = 0; i < n; ) {
        const b = buf[i];
        if (b < 0x80) {
            out.push(String.fromCharCode(b));
            i++;
            continue;
        }
        let len = 0;
        let code = 0;
        if ((b & 0xe0) === 0xc0) { len = 2; code = b & 0x1f; }
        else if ((b & 0xf0) === 0xe0) { len = 3; code = b & 0x0f; }
        else if ((b & 0xf8) === 0xf0) { len = 4; code = b & 0x07; }
        if (len === 0 || i + len > n) {
            out.push(String.fromCharCode(0xdc00 + b));
            i++;
            continue;
        }
        let ok = true;
        for (let j = 1; j < len; j++) {
            const cb = buf[i + j];
            if ((cb & 0xc0) !== 0x80) { ok = false; break; }
            code = (code << 6) | (cb & 0x3f);
        }
        if (!ok) {
            out.push(String.fromCharCode(0xdc00 + b));
            i++;
            continue;
        }
        const min = len === 2 ? 0x80 : len === 3 ? 0x800 : 0x10000;
        if (code < min || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
            out.push(String.fromCharCode(0xdc00 + b));
            i++;
            continue;
        }
        if (code <= 0xffff) {
            out.push(String.fromCharCode(code));
        } else {
            const c = code - 0x10000;
            out.push(String.fromCharCode(0xd800 + (c >> 10), 0xdc00 + (c & 0x3ff)));
        }
        i += len;
    }
    return out.join('');
}

function effectiveGrants(caseObj: Record<string, unknown>): unknown[] {
    const g = caseObj['grants'];
    if (Array.isArray(g)) {
        return g as unknown[];
    }
    return [caseObj['grant']];
}

function evalCase(caseObj: Record<string, unknown>): Record<string, unknown> {
    const cid = String(caseObj['id']);
    const raw = caseObj['raw'] as string | undefined;
    const noParams = Boolean(caseObj['no_params']);
    const rawB64 = caseObj['raw_b64'] as string | undefined;
    let rawText = raw ?? '';
    if (rawB64 !== undefined) {
        rawText = decodeUtf8SurrogateEscape(Buffer.from(rawB64, 'base64'));
    }
    const opId = String(caseObj['op_id']);
    const grant = effectiveGrants(caseObj);

    const out: Record<string, unknown> = { id: cid, impl: 'ts' };

    // ---- raw text path -------------------------------------------------------
    if (noParams) {
        out['raw_path'] = authorize(grant, { id: opId });
    } else {
        let validated: unknown;
        let vOk = true;
        try {
            validated = validateRawParams(rawText) as unknown;
        } catch (e) {
            if (e instanceof SemanticsError) {
                out['raw_path'] = { verdict: 'deny', reason: canonicalReason(e.message) };
                vOk = false;
            } else {
                throw e; // crash, not a clean denial
            }
        }
        if (vOk) {
            out['raw_path'] = authorize(grant, { id: opId, params: validated });
        }
    }

    // ---- decoded object path ---------------------------------------------------
    let decodedParams: unknown = undefined;
    let decodedOk = false;
    if (noParams) {
        out['decoded_path'] = authorize(grant, { id: opId });
        decodedOk = true;
    } else {
        try {
            decodedParams = decodeRaw(rawText);
            out['decoded_path'] = authorize(grant, { id: opId, params: decodedParams });
            decodedOk = true;
        } catch (e) {
            if (e instanceof SyntaxError) {
                out['decoded_path'] = { verdict: 'deny', reason: 'invalid_params_number' };
            } else if (e instanceof SemanticsError) {
                out['decoded_path'] = { verdict: 'deny', reason: canonicalReason(e.message) };
            } else {
                throw e; // crash, not a clean denial
            }
        }
    }

    // ---- value-layer canonical digest ------------------------------------------
    try {
        let sha = '';
        if (noParams) {
            sha = createHash('sha256').update(canonicalJSON(null)).digest('hex');
        } else if (decodedOk && decodedParams !== null && typeof decodedParams === 'object' && !Array.isArray(decodedParams)) {
            sha = createHash('sha256').update(canonicalJSON(decodedParams)).digest('hex');
        }
        out['canonical_sha256'] = sha;
    } catch {
        out['canonical_sha256'] = '';
    }
    return out;
}

function main(): number {
    const args = process.argv.slice(2);
    if (args.length < 1) {
        process.stderr.write('usage: run_ts.ts <cases.jsonl>\n');
        return 2;
    }
    const src = args[0];
    const lines = fs.readFileSync(src, 'utf8').split('\n');
    for (const line of lines) {
        const t = line.trim();
        if (t === '') continue;
        let res: Record<string, unknown>;
        try {
            const caseObj = JSON.parse(t) as Record<string, unknown>;
            res = evalCase(caseObj);
        } catch (e) {
            let cid = '?';
            try {
                cid = String((JSON.parse(t) as Record<string, unknown>)['id']);
            } catch { /* keep '?' */ }
            res = { id: cid, impl: 'ts', error: e instanceof Error ? e.message : String(e) };
        }
        process.stdout.write(JSON.stringify(res) + '\n');
    }
    return 0;
}

process.exit(main());