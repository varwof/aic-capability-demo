// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Run the structured OCMP offline corpus (12 vectors).

import * as fs from 'node:fs';
import * as path from 'node:path';

import { evaluate } from './ocmp.ts';
import type { OcInputs } from './ocmp.ts';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const CAP = process.env.CLC_CAPABILITY_DIR ?? path.join(HERE, '..', '..', 'capability');
const VECTORS = process.env.CLC_OCMP_VECTORS
  ?? path.join(CAP, 'data', '_vectors', 'clc-v1', 'offline-vectors.json');

interface Vector {
  id: string;
  inputs: OcInputs;
  expect: { verdict: string; reason: string };
}

function main(): number {
  const doc = JSON.parse(fs.readFileSync(VECTORS, 'utf8')) as { vectors: Vector[] };
  let failures = 0;
  console.log('OCMP offline profile');
  console.log('-'.repeat(96));
  for (const v of doc.vectors) {
    const [verdict, reason] = evaluate(v.inputs);
    const ok = verdict === v.expect.verdict && reason === v.expect.reason;
    if (!ok) failures++;
    const want = `${v.expect.verdict}/${v.expect.reason}`.padEnd(28);
    const got = `${verdict}/${reason}`.padEnd(28);
    console.log(`${v.id.padEnd(12)} want ${want} got ${got} ${ok ? 'PASS' : 'FAIL'}`);
  }
  console.log('-'.repeat(96));
  console.log(`Total: ${doc.vectors.length} | Pass: ${doc.vectors.length - failures} | Fail: ${failures}`);
  return failures === 0 ? 0 : 1;
}

process.exit(main());
