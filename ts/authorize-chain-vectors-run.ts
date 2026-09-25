// CLC-D §13.11 AuthorizeWithChain vectors runner (rev CLC-1.13).
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { authorizeWithChain } from './clc_semantics.ts';
import type { Grant, Operation } from './clc_semantics.ts';

interface Expectation { verdict: string; reason?: string | null; unresolved?: string[] }
interface Vector { id: string; chain: Grant[]; request: Operation; expect: Expectation }
function canonicalReason(s?: string | null): string {
    if (!s) return '';
    const i = s.indexOf(':');
    return i >= 0 ? s.slice(0, i) : s;
}
const here = dirname(fileURLToPath(import.meta.url));
const path = process.env.CLC_AUTHORIZE_CHAIN_VECTORS
    || resolve(join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-d', 'authorize-chain-vectors.json'));
const vectors: Vector[] = JSON.parse(readFileSync(path, 'utf8'));
let pass = 0;
let fail = 0;
for (const v of vectors) {
    const got = authorizeWithChain(v.chain, v.request);
    const gotReason = canonicalReason(got.reason);
    const wantReason = canonicalReason(v.expect.reason);
    let ok = got.verdict === v.expect.verdict && gotReason === wantReason;
    if (ok && v.expect.unresolved !== undefined) {
        // exact manifest order (UTF-8 byte sequence, §7.1/§8.4; CLC-1.15)
        const gotU = [...(got.unresolved ?? [])];
        const wantU = [...v.expect.unresolved];
        ok = gotU.length === wantU.length && gotU.every((x, i) => x === wantU[i]);
    }
    if (ok) pass++;
    else { fail++; console.log(`${v.id} FAIL want=${v.expect.verdict}/${wantReason} got=${got.verdict}/${gotReason}/${JSON.stringify(got.unresolved ?? [])}`); }
}
console.log(`Total: ${vectors.length} | Pass: ${pass} | Fail: ${fail}`);
if (fail) process.exit(1);
