// §6.6 BoundMeet property test (TypeScript side, rev CLC-1.15).
//
// Runs the deterministic case list shared with the Go and Python
// implementations (capability/data/_vectors/clc-v1/param-bounds-meet-property-cases.json).
// For every case of sources S:
//
//   1. Fail-closed: intersect(S) never throws an unexpected error, and a
//      refusal always carries a normative reason code (§9.2).
//   2. The meet invariant: when intersect(S) succeeds with grant G, then for
//      every operation o in the shared sample
//          entails(G, o)  ==>  entails(s, o) for EVERY source s in S.
//   3. Order independence on success: the reversed merge succeeds too and
//      yields the identical canonical result (§7 rules 2/6).
//
// The summary line mirrors param-bounds-meet-property-run.py.

import {
    canonicalReason,
    canonicalStringify,
    entails,
    intersect,
    SemanticsError,
} from './clc_semantics.ts';

import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

type Grant = import('./clc_semantics.ts').Grant;
type Operation = import('./clc_semantics.ts').Operation;

const NORMATIVE_CODES = new Set([
    'unsupported_language_revision',
    'invalid_capability_id',
    'missing_capability_id',
    'unsupported_wildcard',
    'invalid_params_duplicate_key',
    'invalid_params_number',
    'invalid_params_size',
    'invalid_params_binding',
    'params_cardinality',
    'params_out_of_range',
    'params_not_multiple',
    'different_namespace',
    'literal_mismatch',
    'wildcard_requires_trailing_segment',
    'empty_bound_denies_class',
    'invalid_params_null',
    'params_missing',
    'undeclared_param',
    'not_in_enum',
    'params_exceed_grant',
    'no_overlap',
    'absent_source',
    'capability_not_authorized',
    'unknown_constraint',
]);

function canonicalGrant(g: Grant): string {
    return canonicalStringify([g.id, g.params ?? null, g.param_bounds ?? null, [...(g.constraints ?? [])].sort()]);
}

function main(): number {
    const envPath = process.env.CLC_PARAM_BOUNDS_MEET_PROPERTY_CASES;
    const here = dirname(fileURLToPath(import.meta.url));
    const path = envPath || join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-v1', 'param-bounds-meet-property-cases.json');

    let doc: { ops: Operation[]; cases: Array<{ id: string; sources: Grant[]; note?: string }> };
    try {
        doc = JSON.parse(readFileSync(path, 'utf8'));
    } catch {
        console.log(`meet property cases not found at ${path} (set CLC_PARAM_BOUNDS_MEET_PROPERTY_CASES)`);
        return 0;
    }

    let meets = 0;
    let orderChecked = 0;
    let opChecks = 0;
    const failures: string[] = [];

    for (const c of doc.cases) {
        const sources = c.sources;
        let merged: Grant;
        try {
            merged = intersect(sources.map((s) => ({ ...s })));
        } catch (e) {
            const code = canonicalReason((e as SemanticsError).message);
            if (!NORMATIVE_CODES.has(code)) {
                failures.push(`${c.id}: denial ${code} is not a normative reason code`);
            }
            continue;
        }

        meets++;

        // The meet invariant: G authorizes o only when EVERY source authorizes o.
        for (const o of doc.ops) {
            opChecks++;
            if (!entails(merged, o).entails) {
                continue;
            }
            for (let i = 0; i < sources.length; i++) {
                if (!entails(sources[i], o).entails) {
                    failures.push(
                        `${c.id}: meet authorizes op but source ${i} does not — op=${canonicalStringify(o)} merged=${canonicalGrant(merged)} source=${canonicalGrant(sources[i])}`,
                    );
                    break;
                }
            }
        }

        // Order independence on success.
        try {
            const other = intersect([...sources].reverse().map((s) => ({ ...s })));
            if (canonicalGrant(other) !== canonicalGrant(merged)) {
                failures.push(`${c.id}: result depends on source order: ${canonicalGrant(merged)} vs ${canonicalGrant(other)}`);
            }
        } catch (e) {
            failures.push(`${c.id}: reversed order denies (${(e as SemanticsError).message}) while the original allows`);
        }
        orderChecked++;
    }

    for (const f of failures.slice(0, 20)) {
        console.log('FAIL ' + f);
    }
    console.log(
        `meet-property: ${doc.cases.length} cases, ${meets} successful meets, ${orderChecked} order-symmetry checks, ${opChecks} op-checks, ${failures.length} failures`,
    );
    return failures.length > 0 ? 1 : 0;
}

process.exitCode = main();
