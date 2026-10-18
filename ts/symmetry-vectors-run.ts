// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Run the symmetry corpus (authorization + action identity) in TypeScript.
// Evidence-block vectors are evaluated with evidence_semantics.ts.

import * as fs from 'node:fs';
import * as path from 'node:path';

import {
  authorizeSet,
  authorizeWithChain,
  computeActionId,
} from './clc_semantics.ts';
import { evaluateConstraint, evaluateRequirement } from './evidence_semantics.ts';
import type { Grant, Operation } from './clc_semantics.ts';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const CAP = process.env.CLC_CAPABILITY_DIR ?? path.join(HERE, '..', '..', 'capability');
const VECTORS = process.env.CLC_SYMMETRY_VECTORS
  ?? path.join(CAP, 'data', '_vectors', 'clc-v1', 'symmetry-vectors.json');

interface SymVector {
  id: string;
  type: { name: string; material: string[] };
  suite: string;
  authorization: { chain?: boolean; grants: Grant[]; operation: Operation; verdict: string; reason?: string };
  observed?: Record<string, unknown>;
  observed_type?: string;
  observed_suite?: string;
  no_evidence?: boolean;
  evidence?: unknown;
  expect: { match: string };
}

function actionMatch(v: SymVector, opParams: Record<string, unknown>): string {
  if (v.observed_type && v.observed_type !== v.type.name) return 'INDETERMINATE';
  if (v.observed_suite && v.observed_suite !== v.suite) return 'INDETERMINATE';
  try {
    const opId = computeActionId(v.type.name, v.type.material, v.suite, opParams);
    const obsId = computeActionId(v.type.name, v.type.material, v.suite, v.observed ?? {});
    return opId === obsId ? 'MATCH' : 'NOT_EQUIVALENT';
  } catch {
    return 'action_not_matchable';
  }
}

function main(): number {
  const vectors = JSON.parse(fs.readFileSync(VECTORS, 'utf8')) as SymVector[];
  let ran = 0, skipped = 0, failures = 0;
  console.log('CLC symmetry corpus');
  console.log('-'.repeat(96));
  for (const v of vectors) {
    ran++;
    const a = v.authorization;
    const dec = a.chain ? authorizeWithChain(a.grants, a.operation) : authorizeSet(a.grants, a.operation);
    let ok = dec.verdict === a.verdict && (!a.reason || (dec.reason ?? '').startsWith(a.reason));
    const got = v.no_evidence
      ? 'NO_EVIDENCE'
      : actionMatch(v, (a.operation.params ?? {}) as Record<string, unknown>);
    ok = ok && got === v.expect.match;
    let shown = got;
    if (v.evidence) {
      const e = v.evidence as Record<string, any>;
      const ctx = e.context ?? {};
      const facts = e.facts ?? [];
      try {
        const [verdict, reason] = e.requirement
          ? evaluateRequirement(e.requirement, facts, ctx)
          : evaluateConstraint(e.constraint, facts, ctx);
        ok = ok && verdict === e.verdict && (!e.reason || reason.startsWith(e.reason));
        shown += ` / ${verdict}`;
      } catch (ex) {
        ok = ok && !!e.error && String((ex as Error).message).startsWith(e.error);
        shown += ' / error';
      }
    }
    if (!ok) failures++;
    console.log(`${v.id.padEnd(7)} auth=${dec.verdict.padEnd(16)} match=${shown.padEnd(28)} ${ok ? 'PASS' : 'FAIL'}`);
  }
  console.log('-'.repeat(96));
  console.log(`Ran: ${ran} | Skipped (evidence side): ${skipped} | Fail: ${failures}`);
  return failures === 0 ? 0 : 1;
}

process.exit(main());
