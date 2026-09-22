// CLC-v1 §7.1 ConstraintUnion vectors runner (rev CLC-1.12).
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { constraintUnion } from './clc_semantics.ts';
import type { Grant } from './clc_semantics.ts';

interface Expectation { union?: string[]; reason?: string }
interface Vector { id: string; chain: Grant[]; expect: Expectation }
const here = dirname(fileURLToPath(import.meta.url));
const path = process.env.CLC_CONSTRAINT_UNION_VECTORS
    || resolve(join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-v1', 'constraint-union-vectors.json'));
const vectors: Vector[] = JSON.parse(readFileSync(path, 'utf8'));
let pass = 0;
let fail = 0;
for (const v of vectors) {
    let got: string[] | null = null;
    let err: string | null = null;
    try {
        got = constraintUnion(v.chain);
    } catch (e) {
        err = (e as Error).message;
    }
    let ok: boolean;
    if (v.expect.reason) {
        ok = err !== null && err.split(':', 1)[0] === v.expect.reason;
    } else {
        const want = v.expect.union ?? [];
        ok = err === null && got !== null && got.length === want.length && got.every((x, i) => x === want[i]);
    }
    if (ok) pass++;
    else { fail++; console.log(`${v.id} FAIL want=${JSON.stringify(v.expect)} got=${JSON.stringify(got)} err=${err}`); }
}
console.log(`Total: ${vectors.length} | Pass: ${pass} | Fail: ${fail}`);
if (fail) process.exit(1);
