// Edge-case checks a JSON corpus cannot carry (rev CLC-1.4): JSON cannot
// represent non-finite numbers, so "a value no bound check can compare must
// not become an allow" is pinned here.  Run: node --experimental-strip-types ts/edge_test.ts
import { authorize, validateRawParams } from './clc_semantics.ts';

const GID = 'std/database-v1:query:SELECT';
const fails: string[] = [];

function check(label: string, got: unknown, want: unknown): void {
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

if (fails.length > 0) {
    console.error(fails.join('\n'));
    process.exit(1);
}
console.log('edge_test: 15 checks passed (non-finite, malformed Unicode, raw JCS-size boundary)');
