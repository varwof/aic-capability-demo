// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// Compatibility wrappers for the evidence-side evaluator.
//
// The normative implementation now lives in clc_semantics.ts. The symmetry
// runner keeps its original tuple-returning API here; delegating to the core
// implementation prevents the two evidence evaluators from drifting.

import {
    evaluateEvidenceConstraint,
    evaluateRequirement as evaluateCLCRequirement,
    requirementSatisfaction,
} from './clc_semantics.ts';
import type {
    EvidenceFact,
    GoEvidenceContext,
    Requirement as CLCRequirement,
} from './clc_semantics.ts';

export type Fact = EvidenceFact;
export type EvidenceContext = GoEvidenceContext;

export interface Requirement {
    '@version': string;
    requirement_id?: string;
    expression: string;
    constraints?: Array<{ role: string; constraint: string }>;
}

export function evaluateConstraint(
    c: string,
    facts: Fact[],
    ctx: EvidenceContext = {},
): [string, string] {
    const result = evaluateEvidenceConstraint(c, facts, ctx);
    return [result.verdict, result.reason ?? ''];
}

export function evaluateRequirement(
    req: Requirement,
    facts: Fact[],
    ctx: EvidenceContext = {},
): [string, string] {
    const result = requirementSatisfaction(
        evaluateCLCRequirement(req as CLCRequirement, facts, ctx),
    );
    return [result.verdict, result.reason ?? ''];
}
