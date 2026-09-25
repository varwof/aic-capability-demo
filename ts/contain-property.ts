// CLC-D containment forward-closure property runner (TypeScript).
//
// For each case (parent P, child C) and every operation o in the shared `ops`
// sample: Contains(P, C) MUST NOT raise, and
// Contains(P, C) true AND Entails(C, o) true ==> Entails(P, o) true.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { contains, entails } from './clc_semantics.ts';

const here = dirname(fileURLToPath(import.meta.url));
const path = process.env.CLC_D_PROPERTY_CASES
    || join(here, '..', '..', 'capability', 'data', '_vectors', 'clc-d', 'containment-property-cases.json');
const doc = JSON.parse(readFileSync(path, 'utf8')) as {
    ops: { id: string; params?: Record<string, unknown> | null }[];
    cases: {
        id: string;
        parent: { id: string; params?: Record<string, unknown> | null; constraints?: string[] };
        child: { id: string; params?: Record<string, unknown> | null; constraints?: string[] };
    }[];
};

let containedPairs = 0;
let opChecks = 0;
let violations = 0;
let raised = 0;
for (const c of doc.cases) {
    let r: { contains: boolean; reason?: string };
    try {
        r = contains(c.parent, c.child);
    } catch (e) {
        raised++;
        console.log(`RAISED ${c.id}: ${String(e)}`);
        continue;
    }
    if (r.contains) containedPairs++;
    for (const o of doc.ops) {
        opChecks++;
        if (!entails(c.child, o).entails) continue;
        if (r.contains && !entails(c.parent, o).entails) {
            violations++;
            if (violations <= 5) {
                console.log(`VIOLATION ${c.id} parent=${JSON.stringify(c.parent)} child=${JSON.stringify(c.child)} op=${JSON.stringify(o)}`);
            }
        }
    }
}

console.log(`property: ${doc.cases.length} cases, ${containedPairs} contained pairs, ${opChecks} op-checks, ${raised} raises, ${violations} violations`);
process.exit(violations || raised ? 1 : 0);