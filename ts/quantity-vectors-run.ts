// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Run the CLC-1.19 quantity corpus against the sample scheme declaration.

import * as fs from 'node:fs';
import * as path from 'node:path';

import type { Grant, Operation } from './clc_semantics.ts';
import {
  DeclarationError,
  authorizeWithDeclaration,
  containsWithDeclaration,
  load,
} from './scheme_decl.ts';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const CAP = process.env.CLC_CAPABILITY_DIR ?? path.join(HERE, '..', '..', 'capability');
const DECL = process.env.CLC_SCHEME_DECLARATION
  ?? path.join(CAP, 'data', 'std', 'payments-v1', 'clc-declaration.json');
const VECTORS = process.env.CLC_QUANTITY_VECTORS
  ?? path.join(CAP, 'data', '_vectors', 'clc-v1', 'quantity-vectors.json');

interface Vector {
  id: string;
  kind: string;
  capability: string;
  grants?: Grant[];
  operation?: Operation;
  parent?: Grant;
  child?: Grant;
  expect: { verdict?: string; reason?: string; contains?: boolean };
}

function main(): number {
  let decl;
  try {
    decl = load(DECL);
  } catch (e) {
    const err = e as DeclarationError;
    console.log(`declaration: ${err.code ?? err.message}`);
    return 2;
  }
  const vectors = JSON.parse(fs.readFileSync(VECTORS, 'utf8')) as Vector[];
  console.log('CLC-1.19 quantity domain');
  console.log(`declaration: ${decl.declaration_id}`);
  console.log('-'.repeat(96));
  let failures = 0;
  for (const v of vectors) {
    let ok: boolean;
    let shown: string;
    let want: string;
    if (v.kind === 'authorize') {
      const got = authorizeWithDeclaration(decl, v.capability, v.grants ?? [], v.operation as Operation);
      ok = got.verdict === v.expect.verdict
        && (!v.expect.reason || (got.reason ?? '').startsWith(v.expect.reason));
      shown = got.verdict + (got.reason ? `/${got.reason}` : '');
      want = (v.expect.verdict ?? '') + (v.expect.reason ? `/${v.expect.reason}` : '');
    } else {
      const got = containsWithDeclaration(decl, v.capability, v.parent as Grant, v.child as Grant);
      ok = Boolean(got.contains) === Boolean(v.expect.contains)
        && (v.expect.contains || !v.expect.reason || (got.reason ?? '').startsWith(v.expect.reason));
      shown = `contains=${Boolean(got.contains)}` + (got.reason ? `/${got.reason}` : '');
      want = `contains=${Boolean(v.expect.contains)}` + (v.expect.reason ? `/${v.expect.reason}` : '');
    }
    if (!ok) failures++;
    console.log(`${v.id.padEnd(7)} ${v.kind.padEnd(10)} want ${want.padEnd(32)} got ${shown.padEnd(32)} ${ok ? 'PASS' : 'FAIL'}`);
  }
  // Fail-closed path: a declared-but-unimplemented domain.
  const decl2 = JSON.parse(JSON.stringify(decl));
  decl2.capabilities.transfer.params.amount = { domain: 'money' };
  const u = authorizeWithDeclaration(decl2, 'transfer',
    [{ id: 'std/payments-v1:transfer', params: { amount: 100 } }],
    { id: 'std/payments-v1:transfer', params: { amount: 50 } });
  const uok = u.verdict === 'deny' && u.reason === 'unsupported_domain';
  if (!uok) failures++;
  console.log(`${'u-001'.padEnd(7)} ${'domain'.padEnd(10)} want ${'deny/unsupported_domain'.padEnd(32)} got ${(`${u.verdict}/${u.reason ?? ''}`).padEnd(32)} ${uok ? 'PASS' : 'FAIL'}`);
  // A declared-domain key must not also carry a param_bounds family.
  const p = authorizeWithDeclaration(decl, 'transfer',
    [{ id: 'std/payments-v1:transfer', param_bounds: { amount: { min: 1, max: 10 } } }],
    { id: 'std/payments-v1:transfer', params: { amount: { value: 5, unit: 'CNY' } } });
  const pok = p.verdict === 'deny' && p.reason === 'invalid_params_binding';
  if (!pok) failures++;
  console.log(`${'p-001'.padEnd(7)} ${'domain'.padEnd(10)} want ${'deny/invalid_params_binding'.padEnd(32)} got ${(`${p.verdict}/${p.reason ?? ''}`).padEnd(32)} ${pok ? 'PASS' : 'FAIL'}`);
  // String-shaped domains (shared corpus).
  const svPath = process.env.CLC_STRING_DOMAIN_VECTORS
    ?? path.join(CAP, 'data', '_vectors', 'clc-v1', 'string-domain-vectors.json');
  const sv = JSON.parse(fs.readFileSync(svPath, 'utf8')) as Array<{
    id: string; domain: string; param: string; grant: unknown; op: unknown;
    expect: { verdict: string; reason?: string };
  }>;
  let nString = 0;
  for (const v of sv) {
    nString++;
    const d = JSON.parse(JSON.stringify(decl));
    d.capabilities.transfer.params = { [v.param]: { domain: v.domain } };
    const got = authorizeWithDeclaration(d, 'transfer',
      [{ id: 'std/payments-v1:transfer', params: { [v.param]: v.grant } }],
      { id: 'std/payments-v1:transfer', params: { [v.param]: v.op } });
    const ok = got.verdict === v.expect.verdict
      && (!v.expect.reason || (got.reason ?? '').startsWith(v.expect.reason));
    if (!ok) failures++;
    const shown = got.verdict + (got.reason ? `/${got.reason}` : '');
    const want = v.expect.verdict + (v.expect.reason ? `/${v.expect.reason}` : '');
    console.log(`${v.id.padEnd(7)} ${v.domain.padEnd(10)} want ${want.padEnd(32)} got ${shown.padEnd(32)} ${ok ? 'PASS' : 'FAIL'}`);
  }
  console.log('-'.repeat(96));
  const total = vectors.length + 2 + nString;
  console.log(`Total: ${total} | Pass: ${total - failures} | Fail: ${failures}`);
  return failures === 0 ? 0 : 1;
}

process.exit(main());
