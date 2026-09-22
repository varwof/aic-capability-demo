// CLC-v1 §8.5 Resolve vectors runner (rev CLC-1.11).
// Reads resolve-vectors.json, runs resolve() on the input decision and asserts
// the resulting verdict, resolved reason and (when present) the obligation set.
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolve as resolveObligations } from './clc_semantics.ts';
import type { Decision, Resolution } from './clc_semantics.ts';

interface Expectation {
    verdict: string;
    reason?: string | null;
    unresolved?: string[];
}
interface Vector {
    id: string;
    decision: Decision;
    resolutions?: Resolution[];
    now?: string;
    expect: Expectation;
}
function canonicalReason(s?: string | null): string {
    if (!s) return '';
    const i = s.indexOf(':');
    return i >= 0 ? s.slice(0, i) : s;
}
const here = dirname(fileURLToPath(import.meta.url));
const path = process.env.CLC_RESOLVE_VECTORS
    || resolve(join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-v1', 'resolve-vectors.json'));
const vectors: Vector[] = JSON.parse(readFileSync(path, 'utf8'));
let pass = 0;
let fail = 0;
for (const v of vectors) {
    const got = resolveObligations(v.decision, v.resolutions ?? [], v.now);
    const gotReason = canonicalReason(got.reason);
    const wantReason = canonicalReason(v.expect.reason);
    let ok = got.verdict === v.expect.verdict && gotReason === wantReason;
    if (ok && v.expect.unresolved !== undefined) {
        const gotU = [...(got.unresolved ?? [])].sort();
        const wantU = [...v.expect.unresolved].sort();
        ok = gotU.length === wantU.length && gotU.every((x, i) => x === wantU[i]);
    }
    if (ok) {
        pass++;
    } else {
        fail++;
        console.log(`${v.id} FAIL want=${v.expect.verdict}/${wantReason} got=${got.verdict}/${gotReason} unresolved=${JSON.stringify(got.unresolved ?? [])}`);
    }
}
console.log(`Total: ${vectors.length} | Pass: ${pass} | Fail: ${fail}`);
if (fail) process.exit(1);
