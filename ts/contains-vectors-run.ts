// CLC-D containment vectors runner (TypeScript) — reads
// containment-vectors.json (draft-wei-clc-ext-00 §7) and runs it against the
// TS contains().  Asserts BOTH contains and the resolved reason code
// (canonical, code before the first ':').
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { contains } from './clc_semantics.ts';

const here = dirname(fileURLToPath(import.meta.url));

function canonicalReason(s: string): string {
    if (!s) return '';
    const i = s.indexOf(':');
    return i >= 0 ? s.slice(0, i) : s;
}

interface Vector {
    id: string;
    parent: { id: string; params?: Record<string, unknown> | null; constraints?: string[] };
    child: { id: string; params?: Record<string, unknown> | null; constraints?: string[] };
    expect: { contains: boolean; reason?: string };
    derivation: string;
}

const path = process.env.CLC_D_VECTORS
    || join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-d', 'containment-vectors.json');
const vectors = JSON.parse(readFileSync(path, 'utf8')) as Vector[];

const showAll = process.argv.includes('--all');
let passCount = 0;
let failCount = 0;
for (const v of vectors) {
    const r = contains(v.parent, v.child);
    // No translation: contains() returns the §13.3 shape {contains, reason}
    // (rev CLC-1.15), so the runner asserts on the relation's own fields.
    const gotContains = r.contains;
    const gotReason = canonicalReason(r.reason ?? '');
    const wantReason = v.expect.reason ?? '';
    const ok = gotContains === v.expect.contains
        && (gotContains || !wantReason || gotReason === wantReason);
    if (ok) {
        passCount++;
        if (showAll) {
            console.log(`${v.id.padEnd(14)} contains=${String(gotContains).padEnd(5)} reason=${gotReason.padEnd(24)} derivation=${v.derivation}`);
        }
    } else {
        failCount++;
        console.log(`${v.id.padEnd(14)} FAIL  want.contains=${String(v.expect.contains).padEnd(5)} want.reason=${wantReason} got.contains=${String(gotContains).padEnd(5)} got.reason=${gotReason} derivation=${v.derivation}`);
    }
}
console.log(`Total: ${vectors.length} | Pass: ${passCount} | Fail: ${failCount}`);
process.exit(failCount ? 1 : 0);