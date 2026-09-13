// Edge-case checks a JSON corpus cannot carry (rev CLC-1.4): JSON cannot
// represent non-finite numbers, so "a value no bound check can compare must
// not become an allow" is pinned here.  Run: node --experimental-strip-types ts/edge_test.ts
import { authorize } from './clc_semantics.ts';

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

if (fails.length > 0) {
    console.error(fails.join('\n'));
    process.exit(1);
}
console.log('edge_test: 4 checks passed (non-finite values never allow)');
