// CLC-v1 vectors runner (TypeScript) — reads vectors.json and runs it against
// the TS semantics implementation.
//
// Asserts BOTH verdict and reason (canonical code, CLC-v1 §9.4: the code is
// everything before the first ':').
//
// The table output mirrors vectors-run.py byte-for-byte so a cross-language
// parity diff of the two runner outputs is a meaningful conformance check.

import {
    authorize,
    canonicalReason,
    canonicalStringify,
    entails,
    intersect,
    revisionCompatible,
    SemanticsError,
    validateCapabilityId,
    validateRawParams,
} from './clc_semantics.ts';

import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

interface Vector {
    id: string;
    kind: string;
    spec_clause?: string;
    clc_revision?: string;
    conformance_class?: string;
    grant?: Record<string, unknown> | null;
    request?: Record<string, unknown> | null;
    others?: Record<string, unknown>[];
    raw_params?: string;
    expect: { verdict: string; reason?: string };
    derivation?: string;
}

interface Result {
    pass: boolean;
    id: string;
    kind: string;
    got: string;
    expect: string;
    expReason: string;
    reason: string;
    note: string;
}

function checkResult(expect: Vector['expect'], got: Record<string, unknown>): string {
    if ('result_params' in expect) {
        const want = (expect as Record<string, unknown>)['result_params'] ?? {};
        const have = (got.params ?? {}) as Record<string, unknown>;
        if (canonicalStringify(want) !== canonicalStringify(have)) {
            return `result_params want=${canonicalStringify(want)} got=${canonicalStringify(have)}`;
        }
    }
    if ('result_constraints' in expect) {
        const want = [...(((expect as Record<string, unknown>)['result_constraints'] as string[]) ?? [])].sort();
        const have = [...((got.constraints as string[]) ?? [])].sort();
        if (JSON.stringify(want) !== JSON.stringify(have)) {
            return `result_constraints want=${JSON.stringify(want)} got=${JSON.stringify(have)}`;
        }
    }
    return '';
}

function runVector(v: Vector): Result {
    const r: Result = {
        pass: false,
        id: v.id,
        kind: v.kind,
        got: '',
        expect: v.expect.verdict,
        expReason: canonicalReason(v.expect.reason),
        reason: '',
        note: '',
    };

    // Input-boundary pre-checks. Language revision (§12.1) and raw params
    // normalization (§6.2) resolve before any §9.3 layer, so they short-circuit
    // the whole evaluation when they fail.
    if (v.kind === 'entail' || v.kind === 'decide') {
        const revision = v.clc_revision ?? '';
        if (revision && !revisionCompatible(revision)) {
            r.got = 'deny';
            r.reason = canonicalReason('unsupported_language_revision');
            r.pass = r.got === r.expect && r.reason === r.expReason;
            return r;
        }
        const raw = v.raw_params ?? '';
        if (raw) {
            try {
                validateRawParams(raw);
            } catch (e) {
                r.got = 'deny';
                r.reason = canonicalReason((e as SemanticsError).message);
                r.pass = r.got === r.expect && r.reason === r.expReason;
                return r;
            }
        }
    }

    if (v.kind === 'syntax') {
        try {
            validateCapabilityId((v.request ?? {}).id as string);
            r.got = 'valid';
        } catch (e) {
            r.got = 'invalid';
            r.reason = canonicalReason((e as SemanticsError).message);
        }
        r.pass = r.got === r.expect && r.reason === r.expReason;
        return r;
    }

    if (v.kind === 'entail') {
        const result = entails(v.grant as Grant, v.request as Operation);
        r.got = result.entails ? 'allow' : 'deny';
        r.reason = canonicalReason(result.reason ?? '');
        r.pass = r.got === r.expect && r.reason === r.expReason;
        return r;
    }

    if (v.kind === 'intersect') {
        // A null grant with no `others` is the zero-source intersection
        // (§7 rule 5 -> absent_source), so the grant is only collected when it
        // is actually present.
        const grants: Grant[] = [
            ...(v.grant == null ? [] : [v.grant as Grant]),
            ...((v.others ?? []) as Grant[]),
        ];
        let merged: Grant | null = null;
        try {
            merged = intersect(grants);
            r.got = 'allow';
        } catch (e) {
            r.got = 'deny';
            r.reason = canonicalReason((e as SemanticsError).message);
        }
        const note = merged == null ? '' : checkResult(v.expect, merged as Record<string, unknown>);
        r.note = note;
        r.pass = note === '' && r.got === r.expect && r.reason === r.expReason;
        return r;
    }

    if (v.kind === 'decide') {
        let grant = v.grant as Grant | null | undefined;
        const op = v.request as Operation | null | undefined;

        const others = (v.others ?? []) as Grant[];
        if (others.length > 0) {
            try {
                grant = intersect([grant ?? ({ id: '' } as Grant), ...others]);
            } catch (e) {
                r.got = 'deny';
                r.reason = canonicalReason((e as SemanticsError).message);
                r.pass = r.got === r.expect && r.reason === r.expReason;
                return r;
            }
        }

        // authorize() is fail-closed on absent/empty grant (§9 layer 10).
        const result = authorize(grant, op);
        r.got = result.verdict;
        r.reason = canonicalReason(result.reason ?? '');
        r.pass = r.got === r.expect && r.reason === r.expReason;
        return r;
    }

    r.got = 'error';
    r.pass = false;
    return r;
}

// Referenced only for types in the runner above.
type Grant = import('./clc_semantics.ts').Grant;
type Operation = import('./clc_semantics.ts').Operation;

function main(): void {
    const envPath = process.env.CLC_VECTORS;
    const here = dirname(fileURLToPath(import.meta.url));
    const path = envPath || join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-v1', 'vectors.json');

    const vectors = JSON.parse(readFileSync(path, 'utf8')) as Vector[];

    let passCount = 0;
    let failCount = 0;
    let reasonFailCount = 0;
    const results: Result[] = [];

    for (const v of vectors) {
        const r = runVector(v);
        results.push(r);
        if (r.pass) {
            passCount++;
        } else {
            if (r.reason !== r.expReason) {
                reasonFailCount++;
            }
            failCount++;
        }
    }

    // Column layout mirrors vectors-run.py's f-string format exactly (every
    // column is a padded field followed by a literal space, last column bare,
    // separator = 150 dashes) so a plain diff proves cross-language parity.
    const pad = (s: string | number, w: number): string => {
        const v = String(s);
        return v.length >= w ? v : v + ' '.repeat(w - v.length);
    };
    const S = ' ';
    console.log(
        pad('ID', 20) + S + pad('KIND', 8) + S + pad('GOT', 12) + S + pad('EXP-VERDICT', 19) + S +
        pad('EXP-REASON', 22) + S + pad('GOT-REASON', 22) + S + pad('NOTE', 30) + S + 'RESULT',
    );
    console.log('-'.repeat(150));
    for (const r of results) {
        const status = r.pass ? 'PASS' : 'FAIL';
        console.log(
            pad(r.id, 20) + S + pad(r.kind, 8) + S + pad(r.got, 12) + S + pad(r.expect, 19) + S +
            pad(r.expReason, 22) + S + pad(r.reason, 22) + S + pad(r.note, 30) + S + status,
        );
    }
    console.log('-'.repeat(150));
    console.log(`Total: ${results.length} | Pass: ${passCount} | Fail: ${failCount} | Reason-fail: ${reasonFailCount}`);

    if (failCount > 0) {
        process.exitCode = 1;
    }
}

main();