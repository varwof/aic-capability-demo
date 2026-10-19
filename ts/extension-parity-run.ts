// Emit canonical extension-API outputs for cross-language parity checks.
// Run: node --experimental-strip-types ts/extension-parity-run.ts

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as clc from './clc_semantics.ts';

const here = dirname(fileURLToPath(import.meta.url));
const capabilityDir = process.env.CLC_CAPABILITY_DIR
    ?? join(here, '..', '..', 'capability');
const fixture = JSON.parse(
    readFileSync(
        join(
            capabilityDir,
            'data/_vectors/clc-v1/extension-parity-vectors.json',
        ),
        'utf8',
    ),
) as Record<string, any>;

const record = clc.recordWithContext(
    [fixture.grant], fixture.operation, fixture.context);

const challengeParams = { ...fixture.challenge_params };
const actionMaterial = challengeParams.action_material;
delete challengeParams.action_material;
challengeParams.action_digest = clc.digestOf(actionMaterial);
const challenge = clc.buildChallengeFromDecision(
    fixture.challenge_decision, challengeParams);

const actionId = clc.computeActionID(
    fixture.action_definition, clc.SUITE_JCS_SHA256, fixture.action);
const envelope = clc.newEnvelope(record);

const authorityDigest = clc.digestOf(fixture.source_chain.authority_material);
const artifactDigest = clc.digestOf(fixture.source_chain.artifact_material);
const sourceChain = {
    sources: [
        { kind: 'authority', id: 'root', digest: authorityDigest },
        {
            kind: 'artifact',
            id: 'child',
            digest: artifactDigest,
            references: [authorityDigest],
        },
    ],
    links: [{ from: artifactDigest, to: authorityDigest }],
};

const requirementResult = clc.evaluateRequirement(
    fixture.requirement, fixture.facts, fixture.requirement_context);

function clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value)) as T;
}

function errorCode(fn: () => unknown): string {
    try {
        fn();
    } catch (e: unknown) {
        return (e instanceof Error ? e.message : String(e)).split(':', 1)[0];
    }
    return 'none';
}

const missingDigest = clone(record);
Reflect.deleteProperty(missingDigest, 'input_digest');
const tamperedRecord = clone(record);
tamperedRecord.verdict = clc.VERDICT_DENY;
const invalidRequirement = clone(fixture.requirement);
invalidRequirement.expression = 'approver & executor';

const negativeErrors = {
    context_stale: errorCode(() => clc.freshContext(
        fixture.context, '2026-10-19T12:02:00Z')),
    record_missing_digest: errorCode(() => clc.recordVerify(missingDigest)),
    record_tampered_verdict: errorCode(() => clc.recordVerify(tamperedRecord)),
    challenge_expired: errorCode(() => clc.challengeUsable(
        challenge, '2026-10-19T12:05:00Z')),
    challenge_retry_not_before: errorCode(() => clc.challengeUsable(
        challenge, '2026-10-19T12:00:00Z')),
    envelope_no_signature: errorCode(() => clc.envelopeVerifyRecord(
        envelope, () => undefined)),
    action_malformed: errorCode(() => clc.parseActionId(
        'clc-action:1:payment.release:jcs-sha256:!!')),
    requirement_invalid_expression: errorCode(() => clc.validateRequirement(
        invalidRequirement)),
};

const sha256 = (s: string): string =>
    createHash('sha256').update(s, 'utf8').digest('hex');

const got = {
    record_canonical_sha256: sha256(clc.recordCanonicalBytes(record)),
    context_digest: clc.contextDigest(fixture.context),
    challenge_digest: clc.challengeDigest(challenge),
    action_id: actionId,
    envelope_payload_sha256: sha256(envelope.payload),
    source_chain_digest: clc.sourceChainDigest(sourceChain as never),
    standing_ids: clc.standingOn(sourceChain as never, artifactDigest)
        .map((s) => s.id),
    requirement_digest: clc.requirementDigest(fixture.requirement),
    requirement_roles: clc.requirementRoles(fixture.requirement),
    requirement_verdict: requirementResult.verdict,
    negative_errors: negativeErrors,
};

if (clc.canonicalJSON(got) !== clc.canonicalJSON(fixture.expect)) {
    console.error(`parity mismatch\nexpected ${clc.canonicalJSON(fixture.expect)}\ngot ${clc.canonicalJSON(got)}`);
    process.exit(1);
}

console.log(clc.canonicalJSON(got));
