// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// CLC-1.19 scheme declaration pilot: the `quantity` domain.
// Mirrors register/internal/schemedecl and the Python scheme_decl.py: validate
// the declaration, then apply it as a normalization layer before the ordinary
// CLC relations run.

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';

import {
  authorizeSetWithDomains,
  canonicalJSON,
  containsWithDomains,
} from './clc_semantics.ts';
import type { DomainMap } from './clc_semantics.ts';
import type { ContainmentResult, Decision, Grant, Operation } from './clc_semantics.ts';

const KNOWN_DOMAINS = new Set([
  'bound', 'enum', 'exact',
  'quantity', 'decimal-string', 'subdomain', 'path-prefix',
]);

export interface Param {
  domain: string;
  unit?: string;
  optional?: boolean;
}

export interface Declaration {
  '@version': string;
  scheme: string;
  declaration_id: string;
  clc_revision: string;
  digest?: string;
  capabilities: Record<string, { params: Record<string, Param> }>;
  constraint_types?: string[];
}

export class DeclarationError extends Error {
  code: string;
  constructor(code: string, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}

function digestOf(decl: Declaration): string {
  const body: Record<string, unknown> = { ...decl };
  delete body.digest;
  const h = createHash('sha256').update(canonicalJSON(body), 'utf8').digest('base64url');
  return `sha256:${h}`;
}

export function validate(decl: Declaration): void {
  if (decl['@version'] !== 'CLC-SCHEME-v1') {
    throw new DeclarationError('unsupported_declaration', String(decl['@version']));
  }
  for (const m of ['scheme', 'declaration_id', 'clc_revision'] as const) {
    if (!decl[m]) throw new DeclarationError('invalid_declaration', `missing ${m}`);
  }
  const caps = decl.capabilities;
  if (!caps || Object.keys(caps).length === 0) {
    throw new DeclarationError('invalid_declaration', 'no capabilities');
  }
  for (const [capName, cap] of Object.entries(caps)) {
    if (!cap || !cap.params) throw new DeclarationError('invalid_declaration', `${capName}: no params`);
    for (const [pName, p] of Object.entries(cap.params)) {
      if (!KNOWN_DOMAINS.has(p.domain)) {
        throw new DeclarationError('unsupported_domain', `${capName}.${pName} = ${p.domain}`);
      }
      if (p.domain === 'quantity' && !p.unit) {
        throw new DeclarationError('invalid_declaration', `${capName}.${pName} is quantity without unit`);
      }
      if (p.domain !== 'quantity' && p.unit) {
        throw new DeclarationError('invalid_declaration', `${capName}.${pName} has unit outside quantity`);
      }
    }
  }
  if (decl.digest) {
    const want = digestOf(decl);
    if (want !== decl.digest) {
      throw new DeclarationError('declaration_digest_mismatch', `want ${want}, got ${decl.digest}`);
    }
  }
}

export function load(path: string): Declaration {
  const decl = JSON.parse(fs.readFileSync(path, 'utf8')) as Declaration;
  validate(decl);
  return decl;
}

function domainMap(decl: Declaration, capability: string): DomainMap {
  const params = decl.capabilities?.[capability]?.params ?? {};
  const dm: DomainMap = {};
  for (const [name, p] of Object.entries(params)) {
    dm[name] = { domain: p.domain, unit: p.unit };
  }
  return dm;
}

export function authorizeWithDeclaration(
  decl: Declaration,
  capability: string,
  grants: Grant[],
  op: Operation,
): Decision {
  return authorizeSetWithDomains(grants, op, domainMap(decl, capability));
}

export function containsWithDeclaration(
  decl: Declaration,
  capability: string,
  parent: Grant,
  child: Grant,
): ContainmentResult {
  const dm = domainMap(decl, capability);
  return containsWithDomains(parent, child, dm, dm);
}
