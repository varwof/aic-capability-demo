// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Minimal evidence-side evaluator (CLC §8.2 / §10): the four core constraint
// types and the bounded AND/OR requirement grammar.

export interface Fact {
  type: string;
  subject?: string;
  verified?: boolean;
  issued_at?: string;
}

export interface EvidenceContext {
  now?: string;
  initiator?: string;
  executor?: string;
}

export interface Requirement {
  '@version': string;
  requirement_id?: string;
  expression: string;
  constraints?: Array<{ role: string; constraint: string }>;
}

function eligible(facts: Fact[]): Fact[] {
  return facts.filter((f) => f.verified === true);
}

function parseTime(s?: string): number | null {
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

export function evaluateConstraint(
  c: string,
  facts: Fact[],
  ctx: EvidenceContext,
): [string, string] {
  if (!c.startsWith('varwof/evidence-v1:')) {
    throw new Error(`invalid_evidence_constraint: ${c}`);
  }
  const parts = c.split(':');
  const kind = parts[1];
  const now = parseTime(ctx.now) ?? Date.now();
  if (kind === 'freshness') {
    const sec = Number(parts[3]) * 1000;
    const fs = eligible(facts);
    if (fs.length === 0) return ['violated', 'freshness:no_eligible_fact'];
    for (const f of fs) {
      const t = parseTime(f.issued_at);
      if (t === null) return ['violated', 'freshness:no_issuance_time'];
      if (t > now) return ['violated', 'freshness:future_issued'];
      if (now - t > sec) return ['violated', 'freshness:stale'];
    }
    return ['satisfied', ''];
  }
  if (kind === 'quorum') {
    const threshold = Number(parts[3]);
    const distinct = new Set(eligible(facts).map((f) => f.subject).filter(Boolean));
    if (distinct.size < threshold) {
      return ['violated', `quorum:distinct_subjects=${distinct.size}<threshold=${threshold}`];
    }
    return ['satisfied', ''];
  }
  if (kind === 'exclusion') {
    const who = parts[2];
    const ident = who === 'initiator' ? ctx.initiator : ctx.executor;
    if (!ident) return ['unknown', 'exclusion:identity_not_supplied'];
    for (const f of eligible(facts)) {
      if (f.subject === ident) return ['violated', `exclusion:${who}_is_approver`];
    }
    return ['satisfied', ''];
  }
  if (kind === 'consumption') return ['unknown', 'evidence_not_core_evaluated'];
  throw new Error(`invalid_evidence_constraint: ${c}`);
}

export function evaluateRequirement(
  req: Requirement,
  facts: Fact[],
  ctx: EvidenceContext,
): [string, string] {
  const constraints: Record<string, string[]> = {};
  for (const c of req.constraints ?? []) {
    (constraints[c.role] ??= []).push(c.constraint);
  }
  const roleTrue = (role: string): boolean => {
    const fs = eligible(facts).filter((f) => f.type === role);
    if (fs.length === 0) return false;
    for (const c of constraints[role] ?? []) {
      if (evaluateConstraint(c, fs, ctx)[0] !== 'satisfied') return false;
    }
    return true;
  };
  const tokens = req.expression.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return ['UNSATISFIED', 'requirement:expression_false'];
  let value = roleTrue(tokens[0]);
  for (let i = 1; i + 1 < tokens.length; i += 2) {
    const op = tokens[i];
    const role = tokens[i + 1];
    if (op === 'AND') value = value && roleTrue(role);
    else if (op === 'OR') value = value || roleTrue(role);
    else return ['UNSATISFIED', 'requirement:expression_false'];
  }
  return value ? ['SATISFIED', ''] : ['UNSATISFIED', 'requirement:expression_false'];
}
