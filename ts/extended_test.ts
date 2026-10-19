// Positive/negative checks for the CLC extensions ported to Python/TS.
// Run: node --experimental-strip-types ts/extended_test.ts

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as clc from './clc_semantics.ts';
import * as legacy from './evidence_semantics.ts';
import * as ocmp from './ocmp.ts';
import * as scheme from './scheme_decl.ts';

const GID = 'std/database-v1:query:SELECT';
const GRANT: clc.Grant = { id: GID, params: { limit: 100 } };
const OP: clc.Operation = { id: GID, params: { limit: 50 } };
const TIME_OBLIGATION = 'varwof/constraint-v1:time:window:[{"start":"00:00","end":"01:00"}]';

const fails: string[] = [];
let COUNT = 0;

function stable(v: unknown): string {
    return JSON.stringify(v);
}

function check(label: string, got: unknown, want: unknown): void {
    COUNT++;
    if (stable(got) !== stable(want)) {
        fails.push(`${label}: got ${stable(got)}, want ${stable(want)}`);
    }
}

function expectError(label: string, prefix: string, fn: () => unknown): void {
    COUNT++;
    try {
        fn();
    } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        if (!msg.includes(prefix)) {
            fails.push(`${label}: got error ${msg}, want prefix ${JSON.stringify(prefix)}`);
        }
        return;
    }
    fails.push(`${label}: expected error prefix ${JSON.stringify(prefix)}, got success`);
}

function expectOk(label: string, fn: () => unknown): void {
    COUNT++;
    try {
        fn();
    } catch (e: unknown) {
        fails.push(`${label}: unexpected error: ${e instanceof Error ? e.message : String(e)}`);
    }
}

function fact(type: string, subject: string, issuedAt = '', verified = false) {
    return { type, subject, issued_at: issuedAt, verified };
}

function clone<T>(v: T): T {
    return JSON.parse(JSON.stringify(v)) as T;
}


// Combining and obligations

const allow: clc.Decision = { verdict: clc.VERDICT_ALLOW };
const deny: clc.Decision = {
    verdict: clc.VERDICT_DENY,
    reason: 'capability_not_authorized',
};
const pending: clc.Decision = {
    verdict: clc.VERDICT_ALLOW_UNRESOLVED,
    unresolved: [TIME_OBLIGATION],
};

check('deny-overrides chooses deny',
    clc.combine(clc.COMBINING_DENY_OVERRIDES, [pending, deny]), deny);
check('first-applicable keeps first decision',
    clc.combine(clc.COMBINING_FIRST_APPLICABLE, [pending, deny]), pending);
expectError('empty combine refuses',
    'no_decisions', () => clc.combine(clc.COMBINING_DENY_OVERRIDES, []));
expectError('unknown combine algorithm refuses',
    'unknown_combining_algorithm', () => clc.combine('majority', [allow]));
expectError('allow cannot carry obligations',
    'obligation_shape',
    () => clc.checkDecisionShape({ ...allow, unresolved: [TIME_OBLIGATION] }));
expectOk('discharge accepts a declared obligation',
    () => clc.discharge(pending, ['varwof/constraint-v1:time']));
expectError('discharge refuses an unknown obligation',
    'obligation_unknown', () => clc.discharge(pending, []));
expectError('permit-overrides cannot drop later obligations',
    'combining_would_drop_obligations',
    () => clc.combine(clc.COMBINING_PERMIT_OVERRIDES, [allow, pending]));


// Parameter bounds, defaults and public boundary helpers

check('absent param bounds are unconstrained',
    clc.validateParamBounds(null, null), '');
check('valid nested param bounds are accepted',
    clc.validateParamBounds({
        profile: {
            nested: {
                tier: { enum: ['gold'] },
                note: { optional: true },
            },
        },
    }, {}),
    '');

const boundErrors: Array<[string, Record<string, unknown>, string]> = [
    ['non-object bound', { x: 1 },
        'invalid_params_binding: bound is not an object'],
    ['unknown bound member', { x: { minimum: 1 } },
        'invalid_params_binding: unknown Bound member minimum'],
    ['mixed bound families', { x: { min: 1, enum: [1] } },
        'invalid_params_binding: mixed bound families'],
    ['non-boolean optional', { x: { min: 1, optional: 'yes' } },
        'invalid_params_binding: optional is not a boolean'],
    ['non-positive step', { x: { step: 0 } },
        'invalid_params_binding: step must be positive'],
    ['inverted numeric range', { x: { min: 2, max: 1 } },
        'invalid_params_binding: min > max'],
    ['non-array enum', { x: { enum: 1 } },
        'invalid_params_binding: enum is not an array'],
    ['fractional item count', { x: { min_items: 1.5 } },
        'invalid_params_binding: min_items is not a non-negative integer'],
    ['inverted item range', { x: { min_items: 2, max_items: 1 } },
        'invalid_params_binding: min_items > max_items'],
    ['non-object nested bound', { x: { nested: [] } },
        'invalid_params_binding: nested is not an object'],
    ['invalid nested member', { x: { nested: { y: { step: -1 } } } },
        'invalid_params_binding: step must be positive'],
    ['empty bound key', { '': { min: 0 } },
        'invalid_params_binding: empty key'],
];
for (const [label, bounds, reason] of boundErrors) {
    check(`param bounds reject ${label}`,
        clc.validateParamBounds(bounds, {}), reason);
}
check('bound key may not move between representations',
    clc.validateParamBounds({ limit: { min: 0 } }, { limit: 50 }),
    'invalid_params_binding: limit in both params and param_bounds');

const defaulted = clc.materializeDefaults(
    {
        id: GID,
        params: { limit: 100 },
        param_bounds: { mode: { enum: ['fast', 'slow'] } },
    },
    { id: GID },
    { limit: 50, mode: 'slow', extra: 1 });
check('declared defaults are materialized', defaulted,
    { id: GID, params: { limit: 50, mode: 'slow' } });
check('explicit operation values override defaults',
    clc.materializeDefaults(
        { id: GID, params: { limit: 100 } },
        { id: GID, params: { limit: 10 } },
        { limit: 50 }),
    { id: GID, params: { limit: 10 } });

check('authorizeJSONText allows valid raw parameters',
    clc.authorizeJSONText([GRANT], GID, '{"limit":50}').verdict,
    clc.VERDICT_ALLOW);
check('authorizeJSONText keeps an absent params object',
    clc.authorizeJSONText([{ id: GID }], GID).verdict,
    clc.VERDICT_ALLOW);
check('authorizeJSONText refuses duplicate object members',
    clc.authorizeJSONText([GRANT], GID, '{"limit":1,"limit":2}').reason,
    'invalid_params_duplicate_key: "limit"');

expectOk('constraintWithin accepts a narrower value',
    () => clc.constraintWithin(5, 10));
expectOk('constraintWithin accepts an absent bound',
    () => clc.constraintWithin(5, null));
expectError('constraintWithin rejects a wider value',
    'params_exceed_grant', () => clc.constraintWithin(11, 10));
expectError('constraintWithin rejects a null value',
    'invalid_params_null', () => clc.constraintWithin(null, 10));
expectOk('grant and operation params share the same accepted shape',
    () => {
        clc.validateGrantParams({ limit: 1 });
        clc.validateOperationParams({ cursor: 'next' });
    });
expectError('grant params reject null values',
    'invalid_params_null', () => clc.validateGrantParams({ limit: null }));


// Resolve and time-window discharge

const resolveNow = '2026-10-19T00:30:00Z';
check('terminal deny passes through resolve',
    clc.resolve(deny, [{
        constraint: TIME_OBLIGATION, status: 'satisfied',
    }] as clc.Resolution[]),
    deny);
check('terminal allow passes through resolve', clc.resolve(allow), allow);
check('invalid decision verdict denies',
    clc.resolve({ verdict: 'maybe' } as unknown as clc.Decision),
    { verdict: clc.VERDICT_DENY, reason: 'invalid_resolution' });
check('malformed resolution denies',
    clc.resolve(pending, [{
        constraint: '', status: 'satisfied',
    }] as clc.Resolution[]),
    { verdict: clc.VERDICT_DENY, reason: 'invalid_resolution' });
check('invalid resolution status denies',
    clc.resolve(pending, [{
        constraint: TIME_OBLIGATION, status: 'maybe',
    }] as unknown as clc.Resolution[]),
    { verdict: clc.VERDICT_DENY, reason: 'invalid_resolution' });
check('invalid resolve timestamp denies',
    clc.resolve(pending, [], 'not-a-time'),
    { verdict: clc.VERDICT_DENY, reason: 'invalid_timestamp' });
check('satisfied resolution discharges the obligation',
    clc.resolve(pending, [{
        constraint: TIME_OBLIGATION, status: 'satisfied',
    }] as clc.Resolution[]),
    { verdict: clc.VERDICT_ALLOW });
check('unknown resolution keeps the obligation',
    clc.resolve(pending, [{
        constraint: TIME_OBLIGATION, status: 'unknown',
    }] as clc.Resolution[]),
    { verdict: clc.VERDICT_ALLOW_UNRESOLVED, unresolved: [TIME_OBLIGATION] });
check('violated resolution dominates satisfied',
    clc.resolve(pending, [
        { constraint: TIME_OBLIGATION, status: 'satisfied' },
        { constraint: TIME_OBLIGATION, status: 'violated' },
    ] as clc.Resolution[]),
    { verdict: clc.VERDICT_DENY, reason: 'time:violated' });
check('time window inside discharges',
    clc.resolve(pending, [], resolveNow),
    { verdict: clc.VERDICT_ALLOW });
check('time window outside denies',
    clc.resolve(pending, [], '2026-10-19T02:00:00Z'),
    { verdict: clc.VERDICT_DENY, reason: 'time:violated' });
check('violated report dominates lenient clock',
    clc.resolve(pending, [{
        constraint: TIME_OBLIGATION, status: 'violated',
    }] as clc.Resolution[], resolveNow),
    { verdict: clc.VERDICT_DENY, reason: 'time:violated' });


// Evidence constraints

const now = '2026-10-19T12:00:00Z';
const fresh = fact('approver', 'alice', '2026-10-19T11:59:00Z', true);
const stale = fact('approver', 'alice', '2026-10-19T10:00:00Z', true);
const future = fact('approver', 'alice', '2026-10-19T13:00:00Z', true);

check('freshness accepts a fresh eligible fact',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:freshness:sec:60', [fresh], { now }).verdict,
    clc.EVIDENCE_SATISFIED);
check('freshness rejects a stale fact',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:freshness:sec:60', [stale], { now }).reason,
    'freshness:stale');
check('freshness rejects a future issuance',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:freshness:sec:60', [future], { now }).reason,
    'freshness:future_issued');
check('freshness rejects an invalid issuance time',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:freshness:sec:60',
        [fact('approver', 'alice', 'not-a-time', true)],
        { now }).reason,
    'freshness:no_issuance_time');
check('freshness fails closed without an eligible fact',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:freshness:sec:60',
        [fact('approver', 'alice', '2026-10-19T11:59:00Z', false)],
        { now }).reason,
    'freshness:no_eligible_fact');

const quorumFacts = [
    fact('approver', 'alice', '', true),
    fact('approver', 'bob', '', true),
];
check('quorum accepts distinct verified subjects',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:quorum:distinct:2', quorumFacts).verdict,
    clc.EVIDENCE_SATISFIED);
check('quorum rejects duplicate subjects',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:quorum:distinct:2',
        [quorumFacts[0], clone(quorumFacts[0])]).verdict,
    clc.EVIDENCE_VIOLATED);
check('exclusion accepts a different initiator',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:exclusion:initiator',
        [fact('executor', 'bob', '', true)],
        { initiator: 'alice' }).verdict,
    clc.EVIDENCE_SATISFIED);
check('exclusion rejects the initiator',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:exclusion:initiator',
        [fact('executor', 'alice', '', true)],
        { initiator: 'alice' }).reason,
    'exclusion:initiator_is_approver');
check('exclusion is unknown without boundary identity',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:exclusion:initiator',
        [fact('executor', 'bob', '', true)]).verdict,
    clc.EVIDENCE_UNKNOWN);
check('consumption remains residual',
    clc.evaluateEvidenceConstraint(
        'varwof/evidence-v1:consumption:once', []).verdict,
    clc.EVIDENCE_UNKNOWN);
const coreEval = clc.evaluateEvidenceConstraint(
    'varwof/evidence-v1:freshness:sec:60', [fresh], {});
check('compatibility evidence evaluator remains aligned',
    legacy.evaluateConstraint(
        'varwof/evidence-v1:freshness:sec:60', [fresh], {}),
    [coreEval.verdict, coreEval.reason ?? '']);
expectError('malformed evidence constraint refuses',
    'invalid_evidence_constraint',
    () => clc.validateEvidenceConstraint('varwof/evidence-v1:quorum:distinct:1'));


// Context and source chain

const ctx = clc.decisionContext('2026-10-19T12:00:00Z', 60, 'context-1');
expectOk('fresh context is accepted',
    () => clc.freshContext(ctx, '2026-10-19T12:00:30Z'));
expectError('stale context is refused',
    'context_stale', () => clc.freshContext(ctx, '2026-10-19T12:02:00Z'));
expectError('future context is refused',
    'context_future', () => clc.freshContext(ctx, '2026-10-19T11:59:00Z'));
expectError('zero context is refused',
    'context_missing', () => clc.validateDecisionContext(clc.decisionContext()));
expectError('offset timestamp is not accepted as UTC',
    'context_not_utc',
    () => clc.validateDecisionContext(
        clc.decisionContext('2026-10-19T12:00:00+00:00', 60, 'context-1')));
expectError('oversized context nonce is refused',
    'nonce longer than',
    () => clc.validateDecisionContext(
        clc.decisionContext(
            '2026-10-19T12:00:00Z', 60,
            'x'.repeat(clc.MAX_CONTEXT_NONCE_BYTES + 1))));
check('context digest is stable',
    clc.contextDigest(ctx), clc.contextDigest(clone(ctx)));

const authorityDigest = clc.digestOf({ source: 'authority' });
const artifactDigest = clc.digestOf({ source: 'artifact' });
const chain: clc.SourceChain = {
    sources: [
        { kind: 'authority', id: 'root', digest: authorityDigest },
        {
            kind: 'artifact', id: 'child', digest: artifactDigest,
            references: [authorityDigest],
        },
    ],
    links: [{ from: artifactDigest, to: authorityDigest }],
};
expectOk('source chain validates', () => clc.validateSourceChain(chain));
check('standing-on returns child then authority',
    clc.standingOn(chain, artifactDigest).map((s) => s.id),
    ['child', 'root']);
check('source chain digest is stable',
    clc.sourceChainDigest(chain),
    clc.sourceChainDigest(clone(chain)));

const unbacked = clone(chain);
delete unbacked.sources[1].references;
expectError('unbacked source edge is refused',
    'source_edge_unbacked', () => clc.validateSourceChain(unbacked));
expectError('empty source chain is refused',
    'source_chain_empty', () => clc.validateSourceChain({ sources: [] }));
const dangling = clone(chain);
dangling.links = [
    ...(dangling.links ?? []),
    { from: artifactDigest, to: clc.digestOf({ source: 'missing' }) },
];
expectError('dangling source link is refused',
    'source_dangling_link', () => clc.validateSourceChain(dangling));

const secondAuthority = clc.digestOf({ source: 'authority-2' });
const branch: clc.SourceChain = {
    sources: [
        { kind: 'authority', id: 'root-1', digest: authorityDigest },
        { kind: 'authority', id: 'root-2', digest: secondAuthority },
        {
            kind: 'artifact', id: 'child', digest: artifactDigest,
            references: [authorityDigest, secondAuthority],
        },
    ],
    links: [
        { from: artifactDigest, to: authorityDigest },
        { from: artifactDigest, to: secondAuthority },
    ],
};
expectOk('branching source chain is structurally valid',
    () => clc.validateSourceChain(branch));
expectError('branching standing path is indeterminate',
    'source_chain_branch',
    () => clc.standingOn(branch, artifactDigest));

const cycle: clc.SourceChain = {
    sources: [
        { kind: 'a', id: 'a', digest: authorityDigest, references: [artifactDigest] },
        { kind: 'b', id: 'b', digest: artifactDigest, references: [authorityDigest] },
    ],
    links: [
        { from: authorityDigest, to: artifactDigest },
        { from: artifactDigest, to: authorityDigest },
    ],
};
expectError('source cycle is refused',
    'source_chain_cycle', () => clc.validateSourceChain(cycle));


// Decision records

const rec = clc.record([GRANT], OP);
expectOk('decision record verifies', () => clc.recordVerify(rec));
check('decision record recomputes allow',
    clc.recordRecompute(rec).verdict, clc.VERDICT_ALLOW);

const badInputs = clone(rec);
((badInputs.inputs.operations[0].params as Record<string, unknown>).limit) = 150;
expectError('tampered record inputs are refused',
    'record_input_digest_mismatch', () => clc.recordVerify(badInputs));
const badVerdict = clone(rec);
badVerdict.verdict = clc.VERDICT_DENY;
expectError('tampered record verdict is refused',
    'record_verdict_mismatch', () => clc.recordVerify(badVerdict));
const badRevision = clone(rec);
badRevision.ver = 'CLC-2.0';
expectError('unsupported record revision is refused',
    'record_unsupported_revision', () => clc.recordRecompute(badRevision));
const noOp = clone(rec);
noOp.inputs.operations = [];
expectError('record with wrong operation count is refused',
    'record_operation_count', () => clc.recordRecompute(noOp));
const missingDigest = clone(rec);
Reflect.deleteProperty(missingDigest, 'input_digest');
expectError('record without input digest fails closed',
    'record_input_digest_mismatch',
    () => clc.recordVerify(missingDigest));

const recCtx = clc.recordWithContext([GRANT], OP, ctx);
expectOk('record with context verifies as fresh',
    () => clc.recordVerifyAsOf(recCtx, '2026-10-19T12:00:30Z'));
expectError('record with stale context is refused',
    'context_stale',
    () => clc.recordVerifyAsOf(recCtx, '2026-10-19T12:02:00Z'));


// Requirements

const req = {
    '@version': clc.REQUIREMENT_VERSION,
    requirement_id: 'req-1',
    expression: '(approver AND executor) OR passkey',
    constraints: [
        { role: 'approver', constraint: 'varwof/evidence-v1:quorum:distinct:2' },
        { role: 'executor', constraint: 'varwof/evidence-v1:exclusion:initiator' },
    ],
};
const reqFacts = [
    fact('approver', 'alice', '', true),
    fact('approver', 'bob', '', true),
    fact('executor', 'carol', '', true),
];
const result = clc.evaluateRequirement(req, reqFacts, { initiator: 'alice' });
check('requirement is satisfied', result.verdict, clc.EVIDENCE_SATISFIED);
check('compatibility requirement evaluator keeps CLC precedence',
    legacy.evaluateRequirement(
        {
            '@version': clc.REQUIREMENT_VERSION,
            requirement_id: 'paren',
            expression: 'a AND (b OR c)',
            constraints: [],
        },
        [
            { type: 'a', subject: 'x', issued_at: '', verified: true },
            { type: 'c', subject: 'y', issued_at: '', verified: true },
        ],
        {}),
    [clc.SATISFACTION_SATISFIED, '']);
check('requirement roles are sorted',
    clc.requirementRoles(req), ['approver', 'executor', 'passkey']);
check('requirement satisfaction is binary',
    clc.requirementSatisfaction(result).verdict, clc.SATISFACTION_SATISFIED);
const missing = clc.evaluateRequirement(req, reqFacts.slice(0, 2), { initiator: 'alice' });
check('missing executor violates expression',
    missing.verdict, clc.EVIDENCE_VIOLATED);
check('missing executor is named',
    missing.missing_roles, ['executor', 'passkey']);
check('unknown evidence is not satisfied',
    clc.requirementSatisfied(clc.evaluateRequirement(req, reqFacts, {})), false);
expectError('wrong requirement version is refused',
    'requirement_version',
    () => clc.validateRequirement({ ...req, '@version': 'CLC-REQUIREMENT-v0' }));
expectError('malformed expression is refused',
    'requirement_expression',
    () => clc.validateRequirement({ ...req, expression: 'approver & executor' }));
expectError('duplicate role constraint is refused',
    'requirement_shape',
    () => clc.validateRequirement({
        ...req, constraints: [req.constraints[0], req.constraints[0]],
    }));
expectError('unknown requirement field is refused',
    'requirement_shape: json: unknown field "extra"',
    () => clc.parseRequirement({ ...req, extra: true }));
expectError('oversized requirement expression is refused',
    'expression longer',
    () => clc.validateRequirement({
        ...req, expression: 'a'.repeat(clc.MAX_REQUIREMENT_EXPRESSION_BYTES + 1),
    }));
expectError('too many requirement nodes are refused',
    'more than',
    () => clc.validateRequirement({
        ...req, expression: Array(66).fill('a').join(' OR '),
    }));
expectError('too-deep requirement expression is refused',
    'nesting deeper',
    () => clc.validateRequirement({
        ...req, expression: '('.repeat(9) + 'a' + ')'.repeat(9),
    }));
check('valid requirement parses',
    clc.parseRequirement(JSON.stringify(req)).requirement_id, 'req-1');


// Challenges

const actionDigest = clc.digestOf({ operation: 'shed' });
const challengeParams: clc.ChallengeParams = {
    id: 'challenge-1',
    nonce: '12345678',
    audience: 'agent.example',
    action_digest: actionDigest,
    now: '2026-10-19T12:00:00Z',
    ttl_sec: 300,
    retry_timing: { not_before: '2026-10-19T12:00:30Z', jitter_sec: 5 },
};
const challenge = clc.buildChallengeFromDecision(pending, challengeParams);
expectOk('challenge validates', () => clc.validateChallenge(challenge));
check('challenge never authorizes', clc.challengeAuthorizes(challenge), false);
expectOk('challenge is usable in retry window',
    () => clc.challengeUsable(challenge, '2026-10-19T12:01:00Z'));
expectError('challenge before retry time is refused',
    'challenge_retry_not_before',
    () => clc.challengeUsable(challenge, '2026-10-19T12:00:00Z'));
expectError('expired challenge is refused',
    'challenge_expired',
    () => clc.challengeUsable(challenge, '2026-10-19T12:05:00Z'));
check('challenge digest is stable',
    clc.challengeDigest(challenge), clc.challengeDigest(clone(challenge)));
const badNonce = clone(challenge);
badNonce.nonce = 'short';
expectError('short challenge nonce is refused',
    'nonce must be', () => clc.validateChallenge(badNonce));
expectError('allow decision produces no challenge',
    'challenge_not_outstanding',
    () => clc.buildChallengeFromDecision(allow, challengeParams));

const reqChallenge = {
    '@version': clc.REQUIREMENT_VERSION,
    requirement_id: 'req-challenge',
    expression: 'approver',
    constraints: [
        { role: 'approver', constraint: 'varwof/evidence-v1:freshness:sec:60' },
    ],
};
const reqResult = clc.evaluateRequirement(reqChallenge, [], { now });
const fromRequirement = clc.buildChallengeFromRequirement(
    reqChallenge, reqResult, challengeParams);
expectOk('challenge from requirement validates',
    () => clc.validateChallenge(fromRequirement));
check('challenge from requirement names missing role and constraint',
    [...new Set(fromRequirement.required.map((item) => item.id))].sort(),
    ['approver', 'varwof/evidence-v1:freshness:sec:60'].sort());
expectError('satisfied requirement produces no challenge',
    'challenge_not_outstanding',
    () => clc.buildChallengeFromRequirement(req, result, challengeParams));
const badNonceHigh = clone(challenge);
badNonceHigh.nonce = 'x'.repeat(clc.MAX_CHALLENGE_NONCE_BYTES + 1);
expectError('oversized challenge nonce is refused',
    'nonce must be', () => clc.validateChallenge(badNonceHigh));
const badJitter = clone(challenge);
badJitter.retry_timing!.jitter_sec = -1;
expectError('negative challenge jitter is refused',
    'jitter_sec out of range', () => clc.validateChallenge(badJitter));
const badRetry = clone(challenge);
badRetry.retry_timing!.not_before = '2026-10-19T12:06:00Z';
expectError('retry time after expiry is refused',
    'not_before is after expiry', () => clc.validateChallenge(badRetry));


// DSSE envelopes

function sign(payload: Buffer): string {
    return createHash('sha256').update(payload).digest('hex');
}

function verify(_keyId: string | undefined, payload: Buffer, signature: string): void {
    if (signature !== sign(payload)) throw new Error('bad signature');
}

const envelope = clc.newEnvelope(rec);
expectOk('unsigned envelope is internally consistent', () => clc.envelopeCheck(envelope));
expectError('unsigned envelope cannot verify as signed',
    'envelope_signature', () => clc.envelopeVerifyRecord(envelope, verify));
clc.envelopeSign(envelope, 'key-1', sign);
expectOk('signed envelope verifies with an explicit verifier',
    () => clc.envelopeVerifyRecord(envelope, verify));
check('envelope returns its decision record',
    clc.envelopeDecisionRecord(envelope).input_digest,
    rec.input_digest);

const badSig = clone(envelope);
badSig.signatures[0].sig = '00';
expectError('tampered DSSE signature is refused',
    'envelope_signature', () => clc.envelopeVerifyRecord(badSig, verify));
const multiSig = clc.newEnvelope(rec);
clc.envelopeSign(multiSig, 'bad-key', () => '00');
clc.envelopeSign(multiSig, 'good-key', sign);
expectOk('a later valid signature can satisfy a multi-signature envelope',
    () => clc.envelopeVerifyRecord(multiSig, verify));
const badType = clone(envelope);
badType.payloadType = 'application/example';
expectError('wrong envelope payload type is refused',
    'envelope_payload_type', () => clc.envelopeCheck(badType));
const badSubject = clone(envelope);
const statement = clc.envelopeStatement(badSubject);
statement.subject[0].digest.sha256 = '00'.repeat(32);
badSubject.payload = clc.canonicalJSON(statement);
expectError('retargeted envelope subject is refused',
    'envelope_subject_mismatch', () => clc.envelopeCheck(badSubject));


// Action identities and matching

const definition = clc.actionTypeDefinition('payment.release', ['amount', 'currency']);
const action = { amount: 5, currency: 'USD', note: 'not material' };
check('material projection keeps only declared fields',
    clc.materialProjection(definition, action),
    { amount: 5, currency: 'USD' });
check('material field digests cover every declared field',
    clc.materialFieldDigest(definition, action).length, 2);
const actionString = clc.computeActionID(definition, clc.SUITE_JCS_SHA256, action);
const observed = clc.parseActionId(actionString);
check('action id string round-trips',
    clc.actionIdString(observed), actionString);
check('same action identity matches exactly',
    clc.match(observed, clone(observed)), clc.MATCH_EXACT);
const other = clc.parseActionId(
    clc.computeActionID(definition, clc.SUITE_JCS_SHA256,
        { amount: 6, currency: 'USD' }));
check('different material is not equivalent',
    clc.match(observed, other), clc.MATCH_NOT_EQUIVALENT);
const crossType = clc.parseActionId(
    clc.computeActionID('payment.cancel', ['amount', 'currency'],
        clc.SUITE_JCS_SHA256, { amount: 5, currency: 'USD' }));
check('cross-type action identity is indeterminate',
    clc.match(observed, crossType), clc.MATCH_INDETERMINATE);
expectError('malformed action id is refused',
    'action_shape',
    () => clc.parseActionId('clc-action:1:payment.release:jcs-sha256:!!'));
expectError('missing material field is not matchable',
    'action_not_matchable',
    () => clc.materialProjection(definition, { amount: 5 }));

const profile = clc.actionMappingProfile('profile-1', clc.digestOf({ profile: 1 }));
check('mapping profile with digest is pinned',
    clc.mappingProfilePinned(profile), true);
check('pinned identity projector matches',
    clc.mapAndMatch(profile, (_p, ev) => ev, observed, observed),
    clc.MATCH_EXACT);
check('unpinned mapping profile is indeterminate',
    clc.mapAndMatch(
        clc.actionMappingProfile('profile-1'), (_p, ev) => ev,
        observed, observed),
    clc.MATCH_INDETERMINATE);
check('projector failure is indeterminate',
    clc.mapAndMatch(
        profile, () => { throw new Error('loss'); },
        observed, observed),
    clc.MATCH_INDETERMINATE);
check('projection into a foreign type is indeterminate',
    clc.mapAndMatch(profile, () => crossType, observed, observed),
    clc.MATCH_INDETERMINATE);
check('faithful projection of different content is not equivalent',
    clc.mapAndMatch(profile, () => other, observed, observed),
    clc.MATCH_NOT_EQUIVALENT);


// OCMP offline profile

const ocmpBase: ocmp.OcInputs = {
    grant_covers: true,
    trust_anchor: true,
    local_policy: true,
    status: {
        present: true,
        verified: true,
        as_of: 10,
        valid_until: 100,
        version: 2,
        last_accepted: 1,
    },
    trusted_time: 50,
    clock_offset: 1,
    clock_tolerance: 2,
};
check('OCMP valid inputs allow', ocmp.evaluate(ocmpBase), ['allow', '']);

const ocmpCases: Array<[string, ocmp.OcInputs, string]> = [
    ['grant', { ...ocmpBase, grant_covers: false }, 'capability_not_authorized'],
    ['trust anchor', { ...ocmpBase, trust_anchor: false }, 'trust_anchor_missing'],
    ['local policy', { ...ocmpBase, local_policy: false }, 'local_policy_missing'],
    ['missing status', { ...ocmpBase, status: {} }, 'status_snapshot_missing'],
    ['unverified status', {
        ...ocmpBase,
        status: { ...ocmpBase.status, verified: false },
    }, 'status_snapshot_missing'],
    ['status not yet valid', { ...ocmpBase, trusted_time: 5 }, 'status_snapshot_expired'],
    ['status expired', { ...ocmpBase, trusted_time: 101 }, 'status_snapshot_expired'],
    ['status rollback', {
        ...ocmpBase,
        status: { ...ocmpBase.status, version: 0 },
    }, 'status_snapshot_rollback'],
    ['revoked', { ...ocmpBase, revoked: true }, 'revoked'],
    ['credential expired', {
        ...ocmpBase, credential_expired: true,
    }, 'capability_not_authorized'],
    ['replay equal', {
        ...ocmpBase, replay_enabled: true, counter: 5, last_consumed: 5,
    }, 'replay_detected'],
    ['replay behind', {
        ...ocmpBase, replay_enabled: true, counter: 4, last_consumed: 5,
    }, 'replay_state_invalid'],
    ['fact unavailable', {
        ...ocmpBase, required_fact: true, fact_available: false,
    }, 'fact_unavailable'],
    ['clock skew', {
        ...ocmpBase, clock_offset: 3, clock_tolerance: 2,
    }, 'clock_unsynchronized'],
];
for (const [label, inputs, reason] of ocmpCases) {
    check(`OCMP ${label}`, ocmp.evaluate(inputs), ['deny', reason]);
}
check('OCMP valid replay counter allows',
    ocmp.evaluate({
        ...ocmpBase, replay_enabled: true, counter: 6, last_consumed: 5,
    }),
    ['allow', '']);
check('OCMP available required fact allows',
    ocmp.evaluate({ ...ocmpBase, required_fact: true, fact_available: true }),
    ['allow', '']);


// Scheme declaration

const schemeBase: scheme.Declaration = {
    '@version': 'CLC-SCHEME-v1',
    scheme: 'std/payments-v1',
    declaration_id: 'std/payments-v1@test',
    clc_revision: 'CLC-1.19',
    capabilities: {
        transfer: {
            params: {
                amount: { domain: 'quantity', unit: 'CNY' },
                currency: { domain: 'enum' },
                counterparty: { domain: 'enum' },
                account: { domain: 'enum' },
            },
        },
    },
};
expectOk('scheme declaration validates', () => scheme.validate(schemeBase));

function declarationDigest(decl: scheme.Declaration): string {
    const body: Record<string, unknown> = { ...decl };
    delete body.digest;
    const value = createHash('sha256')
        .update(clc.canonicalJSON(body), 'utf8')
        .digest('base64url');
    return `sha256:${value}`;
}

const digestDecl = clone(schemeBase);
digestDecl.digest = declarationDigest(digestDecl);
expectOk('scheme declaration digest validates', () => scheme.validate(digestDecl));

const schemeNegatives: Array<[string, scheme.Declaration, string]> = [
    ['version', { ...schemeBase, '@version': 'CLC-SCHEME-v2' }, 'unsupported_declaration'],
    ['missing scheme', { ...schemeBase, scheme: '' }, 'invalid_declaration'],
    ['no capabilities', { ...schemeBase, capabilities: {} }, 'invalid_declaration'],
    ['capability without params', {
        ...schemeBase,
        capabilities: { transfer: {} },
    } as unknown as scheme.Declaration, 'invalid_declaration'],
    ['unknown domain', {
        ...schemeBase,
        capabilities: { transfer: { params: { amount: { domain: 'money' } } } },
    }, 'unsupported_domain'],
    ['quantity without unit', {
        ...schemeBase,
        capabilities: { transfer: { params: { amount: { domain: 'quantity' } } } },
    }, 'invalid_declaration'],
    ['unit outside quantity', {
        ...schemeBase,
        capabilities: {
            transfer: { params: { currency: { domain: 'enum', unit: 'CNY' } } },
        },
    }, 'invalid_declaration'],
    ['digest mismatch', { ...schemeBase, digest: 'sha256:wrong' }, 'declaration_digest_mismatch'],
];
for (const [label, decl, code] of schemeNegatives) {
    expectError(`scheme ${label}`, code, () => scheme.validate(decl));
}

const here = dirname(fileURLToPath(import.meta.url));
const capabilityDir = process.env.CLC_CAPABILITY_DIR ?? join(here, '..', '..', 'capability');
const loadedDeclaration = scheme.load(
    join(capabilityDir, 'data/std/payments-v1/clc-declaration.json'),
);
const quantityGrant: clc.Grant = {
    id: 'std/payments-v1:transfer',
    params: {
        amount: { value: 5000, unit: 'CNY' },
        currency: ['CNY'],
        counterparty: ['vendor.example'],
        account: ['account-1'],
    },
};
const quantityOp: clc.Operation = {
    id: 'std/payments-v1:transfer',
    params: {
        amount: { value: 3000, unit: 'CNY' },
        currency: 'CNY',
        counterparty: 'vendor.example',
        account: 'account-1',
    },
};
check('scheme authorize allows narrower quantity',
    scheme.authorizeWithDeclaration(
        loadedDeclaration, 'transfer', [quantityGrant], quantityOp).verdict,
    'allow');
const widerQuantityOp = clone(quantityOp);
(widerQuantityOp.params!.amount as Record<string, unknown>).value = 6000;
check('scheme authorize rejects wider quantity',
    scheme.authorizeWithDeclaration(
        loadedDeclaration, 'transfer', [quantityGrant], widerQuantityOp).reason,
    'params_exceed_grant');
const childQuantity = clone(quantityGrant);
(childQuantity.params!.amount as Record<string, unknown>).value = 3000;
check('scheme contains accepts narrower quantity',
    scheme.containsWithDeclaration(
        loadedDeclaration, 'transfer', quantityGrant, childQuantity).contains,
    true);
childQuantity.params!.counterparty = ['other.example'];
check('scheme contains rejects wider enum',
    scheme.containsWithDeclaration(
        loadedDeclaration, 'transfer', quantityGrant, childQuantity).contains,
    false);


if (fails.length > 0) {
    console.error(fails.join('\n'));
    process.exit(1);
}
console.log(`extended_test: ${COUNT} checks passed`);
