// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Validate §13.8.1 obligations 6/7 declarations (TypeScript mirror).

import * as fs from 'node:fs';
import * as path from 'node:path';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const CAP = process.env.CLC_CAPABILITY_DIR ?? path.join(HERE, '..', '..', 'capability');
const DECLS = process.env.CLC_PROFILE_DECLARATIONS
  ?? path.join(CAP, 'data', '_vectors', 'clc-v1', 'profile-declarations.json');
const CORPORA = [
  path.join(CAP, 'data', '_vectors', 'clc-v1', 'crosswalk-vectors.json'),
  path.join(CAP, 'data', '_vectors', 'clc-d', 'containment-crosswalk-vectors.json'),
];
const BASES = new Set(['definition-derived', 'mechanically-checkable', 'asserted']);

function issues(d: any): string[] {
  const out: string[] = [];
  const cc = d.chain_check ?? {};
  const basis = cc.basis ?? '';
  if (cc.relies_on_transitivity) {
    if (!cc.iterates_hops) out.push('transitivity-without-iteration');
    if (!basis) out.push('basis-missing');
    else if (!BASES.has(basis)) out.push('unknown-basis');
    else if (basis === 'definition-derived' && !(cc.domain && cc.argument)) out.push('domain-or-argument-missing');
    else if (basis === 'mechanically-checkable' && !(cc.domain && cc.procedure)) out.push('domain-or-procedure-missing');
  } else if (basis) {
    out.push('basis-without-claim');
  }
  const ua = d.union_axis ?? {};
  const routed = ua.routed_to;
  const fields = ua.fields ?? [];
  if (routed === 'constraint-union' || routed === 'carrier-enforced') {
    if (fields.length === 0) out.push('union-axis-fields-mismatch');
  } else if (routed === 'not-applicable') {
    if (fields.length > 0) out.push('union-axis-fields-mismatch');
  } else {
    out.push('union-axis-misrouted');
  }
  return out;
}

function main(): number {
  const doc = JSON.parse(fs.readFileSync(DECLS, 'utf8'));
  let failures = 0;
  console.log('CLC profile declarations (TypeScript)');
  console.log('-'.repeat(96));
  if (doc.schema !== 'clc-profile-declarations-v1') {
    console.log('schema mismatch');
    return 1;
  }
  for (const d of doc.declarations ?? []) {
    const got = issues(d);
    const ok = got.length === 0;
    if (!ok) failures++;
    console.log(`${String(d.profile ?? '?').padEnd(40)} ${ok ? 'PASS' : 'FAIL ' + got.join(',')}`);
  }
  const used = new Set<string>();
  for (const p of CORPORA) {
    for (const e of JSON.parse(fs.readFileSync(p, 'utf8'))) {
      if (e.profile) used.add(e.profile);
    }
  }
  const declared = new Set<string>((doc.declarations ?? []).map((d: any) => d.profile));
  const cov = used.size === declared.size && [...used].every((x) => declared.has(x));
  if (!cov) failures++;
  console.log(`coverage: used=${used.size} declared=${declared.size} ${cov ? 'PASS' : 'FAIL'}`);
  for (const ex of doc.examples ?? []) {
    const got = issues(ex);
    const ok = got.length === 0;
    if (!ok) failures++;
    console.log(`example ${String(ex.profile ?? '?').padEnd(32)} ${ok ? 'PASS' : 'FAIL ' + got.join(',')}`);
  }
  for (const nc of doc.negative_cases ?? []) {
    const got = issues(nc.declaration ?? {});
    const ok = got.includes(nc.want);
    if (!ok) failures++;
    console.log(`${String(nc.id ?? '?').padEnd(40)} want ${String(nc.want).padEnd(32)} ${ok ? 'PASS' : 'FAIL ' + JSON.stringify(got)}`);
  }
  console.log('-'.repeat(96));
  console.log(`Failures: ${failures}`);
  return failures === 0 ? 0 : 1;
}

process.exit(main());
