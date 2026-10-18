// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Run the shared valid/invalid scheme-declaration corpus.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { DeclarationError, validate } from './scheme_decl.ts';
import type { Declaration } from './scheme_decl.ts';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const CAP = process.env.CLC_CAPABILITY_DIR ?? path.join(HERE, '..', '..', 'capability');
const VECTORS = process.env.CLC_SCHEME_DECLARATION_VECTORS
  ?? path.join(CAP, 'data', '_vectors', 'clc-v1', 'scheme-declaration-vectors.json');

interface Case { id: string; expect: string; code?: string; declaration: Declaration }

function main(): number {
  const cases = JSON.parse(fs.readFileSync(VECTORS, 'utf8')) as Case[];
  let failures = 0;
  console.log('CLC scheme declaration corpus');
  console.log('-'.repeat(96));
  for (const c of cases) {
    let got = 'accept';
    let code = '';
    try {
      validate(c.declaration);
    } catch (e) {
      got = 'reject';
      code = (e as DeclarationError).code ?? '';
    }
    const ok = got === c.expect && (got === 'accept' || !c.code || code === c.code);
    if (!ok) failures++;
    console.log(`${c.id.padEnd(7)} want ${c.expect.padEnd(7)} got ${got.padEnd(7)} ${code.padEnd(28)} ${ok ? 'PASS' : 'FAIL'}`);
  }
  console.log('-'.repeat(96));
  console.log(`Total: ${cases.length} | Pass: ${cases.length - failures} | Fail: ${failures}`);
  return failures === 0 ? 0 : 1;
}

process.exit(main());
