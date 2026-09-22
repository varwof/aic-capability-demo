// CLC-v1 §6.5 extended parameter-bound vectors runner (rev CLC-1.10).
// Reads param-bounds-vectors.json and runs them against entails(); asserts the
// verdict and the resolved reason.  kind=param-defaults applies defaults first.
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { entails, materializeDefaults } from './clc_semantics.ts';
import type { Grant, Operation } from './clc_semantics.ts';

interface Expectation { verdict: string; reason?: string }
interface Vector {
    id: string;
    kind: string;
    grant?: Grant;
    request?: Operation;
    scheme_defaults?: Record<string, unknown>;
    expect: Expectation;
    derivation: string;
}
function canonicalReason(s?: string): string {
    if (!s) return '';
    const i = s.indexOf(':');
    return i >= 0 ? s.slice(0, i) : s;
}
const here = dirname(fileURLToPath(import.meta.url));
const path = process.env.CLC_PARAM_BOUNDS_VECTORS
    || resolve(join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-v1', 'param-bounds-vectors.json'));
const vectors: Vector[] = JSON.parse(readFileSync(path, 'utf8'));
let pass = 0;
let fail = 0;
for (const v of vectors) {
    const grant = v.grant ?? { id: '' };
    let op = v.request ?? { id: '' };
    if (v.kind === 'param-defaults') {
        op = materializeDefaults(grant, op, v.scheme_defaults);
    }
    const r = entails(grant, op);
    const got = r.entails ? 'allow' : 'deny';
    const gotReason = canonicalReason(r.reason);
    const wantReason = v.expect.reason ?? '';
    if (got === v.expect.verdict && gotReason === wantReason) {
        pass++;
    } else {
        fail++;
        console.log(`${v.id} FAIL want=${v.expect.verdict}/${wantReason} got=${got}/${gotReason} ${v.derivation}`);
    }
}
console.log(`Total: ${vectors.length} | Pass: ${pass} | Fail: ${fail}`);
if (fail) process.exit(1);
