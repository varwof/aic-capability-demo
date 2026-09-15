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
function authorize(grant: unknown, op: unknown): { verdict: string; reason: string } {
    const d = authorizeSet([grant as never], op as never);
    return { verdict: d.verdict, reason: canon(d.reason) };
}

function decodeRaw(raw: string): unknown {
    return JSON.parse(raw);
}

function evalCase(caseObj: Record<string, unknown>): Record<string, unknown> {
    const cid = String(caseObj['id']);
    const raw = caseObj['raw'] as string | undefined;
    const noParams = Boolean(caseObj['no_params']);
    const rawB64 = caseObj['raw_b64'] as string | undefined;
    let rawText = raw ?? '';
    if (rawB64 !== undefined) {
        rawText = Buffer.from(rawB64, 'base64').toString('ascii');
    }
    const opId = String(caseObj['op_id']);
    const grant = caseObj['grant'] as unknown;

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