// P11 property test (TypeScript side) — "composition narrows only" (CLC-v1 §7).
//
// Runs the deterministic case list shared with the Go and Python
// implementations (capability/data/_vectors/clc-v1/property-cases.json). For
// every case of sources S:
//
//   1. Source coverage (⊑, §7 rule 2).
//   2. Order independence (merging in reverse yields the same grant or denies).
//   3. Closure belongs to the effective grant (§9.3 layer 7).
//   4. Fail-closed: a denial always carries a normative reason code (§9.4).
//
// Verifying these alongside the corpus is the v1 conformance bar
// (principles P11/P12). The summary line mirrors property_test.py.

import {
    authorize,
    canonicalReason,
    canonicalStringify,
    entails,
    intersect,
    paramsSubset,
    SemanticsError,
} from './clc_semantics.ts';

import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

type Grant = import('./clc_semantics.ts').Grant;

const NORMATIVE_CODES = new Set([
    'unsupported_language_revision',
    'invalid_capability_id',
    'missing_capability_id',
    'unsupported_wildcard',
    'invalid_params_duplicate_key',
    'invalid_params_number',
    'invalid_params_size',
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

// ⊑: the merged grant stays inside the source on the source's own keys.
function coveredBySource(merged: Grant, src: Grant): boolean {
    // Identifier coverage, deliberately params-free: entails() fails closed
    // when a bounded grant meets an operation with no params (§6.3 step 4).
    if (!entails({ id: src.id }, { id: merged.id }).entails) {
        return false;
    }
    if (src.params == null) {
        return true;
    }
    for (const [key, bound] of Object.entries(src.params)) {
        if (!(key in (merged.params ?? {}))) {
            return false;
        }
        const [ok] = paramsSubset(
            { [key]: merged.params![key] },
            { [key]: bound },
        );
        if (!ok) {
            return false;
        }
    }
    for (const con of src.constraints ?? []) {
        if (!(merged.constraints ?? []).includes(con)) {
            return false;
        }
    }
    return true;
}

function main(): number {
    const envPath = process.env.CLC_PROPERTY_CASES;
    const here = dirname(fileURLToPath(import.meta.url));
    const path = envPath || join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-v1', 'property-cases.json');

    let cases: Array<{ id: string; sources: Grant[]; note?: string }>;
    try {
        cases = (JSON.parse(readFileSync(path, 'utf8')) as {
            cases: Array<{ id: string; sources: Grant[]; note?: string }>;
        }).cases;
    } catch {
        console.log(`property cases not found at ${path} (set CLC_PROPERTY_CASES)`);
        return 0;
    }

    let orderChecked = 0;
    let closureChecked = 0;
    const failures: string[] = [];

    for (const c of cases) {
        const sources = c.sources;
        if (sources.length === 0) {
            continue;
        }

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

        sources.forEach((src, i) => {
            if (!coveredBySource(merged, src)) {
                failures.push(
                    `${c.id}: result ${canonicalStringify(merged)} is NOT covered by source ${i} ${canonicalStringify(src)}`,
                );
            }
        });

        // Closure applies to the effective grant only.
        if (merged.id && merged.params != null) {
            const probe: Grant = { id: merged.id, params: { ...merged.params, clc_undeclared_probe: 'x' } };
            const decision = authorize(merged, probe);
            if (canonicalReason(decision.reason ?? '') !== 'undeclared_param') {
                failures.push(
                    `${c.id}: operation with an undeclared key resolved to ${decision.reason}, want undeclared_param`,
                );
            }
            closureChecked++;
        }

        if (sources.length > 1) {
            try {
                const other = intersect([...sources].reverse().map((s) => ({ ...s })));
                const a = canonicalStringify([merged.id, merged.params, merged.constraints ?? []]);
                const b = canonicalStringify([other.id, other.params, other.constraints ?? []]);
                if (a !== b) {
                    failures.push(`${c.id}: result depends on source order: ${a} vs ${b}`);
                }
            } catch (e) {
                failures.push(`${c.id}: reversed order denies (${(e as SemanticsError).message}) while the original allows`);
            }
            orderChecked++;
        }
    }

    for (const f of failures.slice(0, 20)) {
        console.log('FAIL ' + f);
    }
    console.log(
        `property: ${cases.length} cases, ${orderChecked} order-symmetry checks, ${closureChecked} closure probes, ${failures.length} failures`,
    );
    return failures.length > 0 ? 1 : 0;
}

process.exitCode = main();