// Edge-case checks a JSON corpus cannot carry (rev CLC-1.4): JSON cannot
// represent non-finite numbers, so "a value no bound check can compare must
// not become an allow" is pinned here.  Run: node --experimental-strip-types ts/edge_test.ts
import { authorize, validateConstraint, validateParams, validateRawParams } from './clc_semantics.ts';

const GID = 'std/database-v1:query:SELECT';
const fails: string[] = [];
let COUNT = 0;

function check(label: string, got: unknown, want: unknown): void {
    COUNT++;
    if (got !== want) {
        fails.push(`${label}: got ${String(got)}, want ${String(want)}`);
    }
}

for (const [name, value] of [['NaN', NaN], ['+Inf', Infinity], ['-Inf', -Infinity]] as const) {
    const d = authorize({ id: GID, params: { limit: 100 } } as never, { id: GID, params: { limit: value } } as never);
    check(`${name} under a numeric bound`, `${d.verdict}/${d.reason ?? ''}`, 'deny/invalid_params_number');
}

const d = authorize(
    { id: GID, constraints: ['varwof/constraint-v1:max_rows:10'] } as never,
    { id: GID, params: { max_rows: NaN } } as never,
);
check('NaN max_rows (refused at the input boundary, before the constraint runs)', d.reason, 'invalid_params_number');

// Malformed Unicode on the decoded path (rev CLC-1.6): a lone surrogate must
// yield the same stable denial (code before the first ':') as the raw boundary
// check, never a silent repair to U+FFFD.
for (const [label, key, value] of [
    ['lone surrogate value', 's', '\ud800'],
    ['lone surrogate key', '\udc00', 1],
    ['lone surrogate deep', 's', ['x', { t: '\udbff' }]],
] as const) {
    const dd = authorize(
        { id: GID, params: { limit: 100 } } as never,
        { id: GID, params: { [key]: value } } as never,
    );
    check(label, `${dd.reason ?? ''}`.split(':')[0], 'invalid_params_number');
}

// The decoded size check must refuse the JCS-over-limit case that
// deserializers measure differently ({"n":1e-06, "a":<494>} is 514 JCS bytes).
const ds = authorize(
    { id: GID, params: { limit: 100 } } as never,
    { id: GID, params: { n: 1e-6, a: 'a'.repeat(494) } } as never,
);
check('1e-6 + 494 a\'s (JCS 514, must refuse)', ds.reason ?? '', 'invalid_params_size');

// Raw path must use JCS octet counting (§3.2.2.2), so the raw boundary
// agrees with the decoded path: non-shortcut controls count 6, `"`/`\` count
// 2, `&`/`<`/`>` count 1, U+2028/U+2029 count 3.
const rawCases: Array<[string, string, string | null]> = [
    ['ctl_u0011 x250 invalid (6×250+8=1508 > 512)',
     '{"s":"' + '\\u0011'.repeat(250) + '"}', 'invalid_params_size'],
    ['quote x256 invalid (2×256+8=520 > 512)',
     '{"s":"' + '\\u0022'.repeat(256) + '"}', 'invalid_params_size'],
    ['backslash x256 invalid (2×256+8=520 > 512)',
     '{"s":"' + '\\u005c'.repeat(256) + '"}', 'invalid_params_size'],
    ['u2028 x160 ok (3×160+8=488 ≤ 512)',
     '{"s":"' + '\\u2028'.repeat(160) + '"}', null],
    ['u2028 x169 invalid (3×169+8=515 > 512)',
     '{"s":"' + '\\u2028'.repeat(169) + '"}', 'invalid_params_size'],
    ['amp x250 ok (1×250+8=258 ≤ 512)',
     '{"s":"' + '&'.repeat(250) + '"}', null],
    ['tab x250 ok (2×250+8=508 ≤ 512)',
     '{"s":"' + '\\t'.repeat(250) + '"}', null],
];
for (const [label, raw, want] of rawCases) {
    try {
        validateRawParams(raw);
        check(`raw ${label}`, null, want);
    } catch (e: unknown) {
        const reason = `${(e as Error).message ?? ''}`.split(':')[0];
        check(`raw ${label}`, reason, want);
    }
}

// The I-JSON integer bound (rev CLC-1.16 §6.2 step 3, [RFC7493] §6): an
// integer-valued number past 2^53 - 1 has no exact binary64 representation, so
// accepting it would decide `op <= grant` on a value the sender never wrote.
// Every spelling of an over-bound integer is refused, while a genuine fraction
// below the bound is not an integer and still reads.  The raw path is the only
// entry that can see the literal text — 2^53 + 1 arrives already rounded — but
// the bound must hold at both entries.
const ijsonCases: Array<[string, string, string | null]> = [
    ['at bound 2^53-1', '{"n":9007199254740991}', null],
    ['2^53-1 minus a half', '{"n":9007199254740990.5}', null],
    ['2^53 over', '{"n":9007199254740992}', 'invalid_params_number'],
    ['2^53+1 over', '{"n":9007199254740993}', 'invalid_params_number'],
    ['2^53+1 negative over', '{"n":-9007199254740993}', 'invalid_params_number'],
    ['2^53+1 fraction spelling', '{"n":9007199254740993.0}', 'invalid_params_number'],
    ['2^53+1 exponent spelling', '{"n":9.007199254740993e15}', 'invalid_params_number'],
    ['2^53+1 negative exponent spelling', '{"n":-9.007199254740993e15}', 'invalid_params_number'],
    ['20-digit over', '{"n":100000000000000000000}', 'invalid_params_number'],
    ['over behind a small exponent', '{"n":9.007199254740993e16}', 'invalid_params_number'],
    ['fraction below bound', '{"n":1.5}', null],
    ['negative fraction', '{"n":-0.25}', null],
    ['zero', '{"n":0}', null],
    ['one', '{"n":1}', null],
    // §6.2 step 8: String.trim() lists U+FEFF among its whitespace characters,
    // so without an explicit refusal this host would drop a leading BOM and
    // accept the payload — the ECMAScript-trim divergence the step closes.
    ['leading BOM refused', '\uFEFF{"s":1}', 'invalid_params_number'],
    ['leading BOM outranks the size cap', '\uFEFF' + '{"s":"' + 'a'.repeat(600) + '"}', 'invalid_params_number'],
];
for (const [label, raw, want] of ijsonCases) {
    try {
        validateRawParams(raw);
        check(`raw ${label}`, null, want);
    } catch (e: unknown) {
        const reason = `${(e as Error).message ?? ''}`.split(':')[0];
        check(`raw ${label}`, reason, want);
    }
}

// The decoded entry point must refuse the same values as the raw path, including
// inside a list, so a caller handing over an already-decoded params object cannot
// carry an integer the raw text would have refused.
const decodedCases: Array<[string, unknown, string | null]> = [
    ['at bound', { n: 9007199254740991 }, null],
    ['2^53+1 over', { n: 9007199254740993 }, 'invalid_params_number'],
    ['fraction', { n: 1.5 }, null],
    ['over inside a list', { n: [9007199254740993] }, 'invalid_params_number'],
];
for (const [label, value, want] of decodedCases) {
    try {
        validateParams(value as Record<string, unknown>);
        check(`decoded ${label}`, null, want);
    } catch (e: unknown) {
        const reason = `${(e as Error).message ?? ''}`.split(':')[0];
        check(`decoded ${label}`, reason, want);
    }
}

// §8.1 states the max_rows constraint operand is not exempt from layer-7 closure:
// an over-bound ceiling would be rounded before the "op <= grant" comparison.  The
// reason code is the §8.1 one (invalid_constraint), not the params one.
const constraintBoundCases: Array<[string, string, string | null]> = [
    ['at bound', 'varwof/constraint-v1:max_rows:9007199254740991', null],
    ['zero', 'varwof/constraint-v1:max_rows:0', null],
    ['ordinary', 'varwof/constraint-v1:max_rows:1000', null],
    ['2^53 over', 'varwof/constraint-v1:max_rows:9007199254740992', 'invalid_constraint'],
    ['2^53+1 over', 'varwof/constraint-v1:max_rows:9007199254740993', 'invalid_constraint'],
    ['20-digit over', 'varwof/constraint-v1:max_rows:100000000000000000000', 'invalid_constraint'],
    ['not an integer', 'varwof/constraint-v1:max_rows:10.5', 'invalid_constraint'],
    ['unknown scheme', 'foo/db-v1:max_rows:9007199254740993', 'unknown_constraint'],
];
for (const [label, c, want] of constraintBoundCases) {
    try {
        validateConstraint(c);
        check(`constraint ${label}`, null, want);
    } catch (e: unknown) {
        const reason = `${(e as Error).message ?? ''}`.split(':')[0];
        check(`constraint ${label}`, reason, want);
    }
}

if (fails.length > 0) {
    console.error(fails.join('\n'));
    process.exit(1);
}
console.log(`edge_test: ${COUNT} checks passed (non-finite, malformed Unicode, raw JCS-size boundary, I-JSON integer bound in params and constraints)`);
