// CLC-v1 §6.6 BoundMeet vectors runner (rev CLC-1.14).
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { intersect } from './clc_semantics.ts';
import type { Grant } from './clc_semantics.ts';

interface Expectation {
    params?: Record<string, unknown>;
    param_bounds?: Record<string, unknown>;
    reason?: string;
}
interface Vector { id: string; sources: Grant[]; expect: Expectation }
const here = dirname(fileURLToPath(import.meta.url));
const path = process.env.CLC_PARAM_BOUNDS_MEET_VECTORS
    || resolve(join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-v1', 'param-bounds-meet-vectors.json'));
const vectors: Vector[] = JSON.parse(readFileSync(path, 'utf8'));

function jsonEqual(a: unknown, b: unknown): boolean {
    return JSON.stringify(canon(a)) === JSON.stringify(canon(b));
}
function canon(v: unknown): unknown {
    if (Array.isArray(v)) return v.map(canon);
    if (v && typeof v === 'object') {
        const out: Record<string, unknown> = {};
        for (const k of Object.keys(v as Record<string, unknown>).sort()) {
            out[k] = canon((v as Record<string, unknown>)[k]);
        }
        return out;
    }
    return v;
}

let pass = 0;
let fail = 0;
for (const v of vectors) {
    let got: Grant | null = null;
    let err: string | null = null;
    try {
        got = intersect(v.sources);
    } catch (e) {
        err = (e as Error).message;
    }
    let ok: boolean;
    if (v.expect.reason) {
        ok = err !== null && err.split(':', 1)[0] === v.expect.reason;
    } else {
        ok = err === null && got !== null
            && jsonEqual(got.param_bounds ?? {}, v.expect.param_bounds ?? {})
            && jsonEqual(got.params ?? {}, v.expect.params ?? {});
    }
    if (ok) pass++;
    else { fail++; console.log(`${v.id} FAIL want=${JSON.stringify(v.expect)} got=${JSON.stringify(got)} err=${err}`); }
}
console.log(`Total: ${vectors.length} | Pass: ${pass} | Fail: ${fail}`);
if (fail) process.exit(1);
