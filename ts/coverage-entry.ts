// Combined coverage entry: runs every TypeScript conformance/extension runner
// in one process so Node's built-in coverage reports one aggregate result.
//
// The runners are imported dynamically and sequentially. Several runners call
// process.exit() as their CLI terminator; temporarily intercepting it keeps the
// aggregate process alive while preserving a failing exit status at the end.

const runners = [
    './extended_test.ts',
    './edge_test.ts',
    './property.ts',
    './vectors-run.ts',
    './contains-vectors-run.ts',
    './contain-property.ts',
    './param-bounds-vectors-run.ts',
    './param-bounds-meet-vectors-run.ts',
    './param-bounds-meet-property.ts',
    './resolve-vectors-run.ts',
    './constraint-union-vectors-run.ts',
    './authorize-chain-vectors-run.ts',
    './symmetry-vectors-run.ts',
    './quantity-vectors-run.ts',
    './scheme-declaration-vectors-run.ts',
    './offline-vectors-run.ts',
    './profile-declarations-run.ts',
    './jcs_check.ts',
] as const;

const realExit = process.exit;
let failed = false;

process.exit = ((code?: number) => {
    if ((code ?? 0) !== 0) {
        failed = true;
    }
}) as typeof process.exit;

try {
    for (const runner of runners) {
        await import(runner);
    }
} finally {
    process.exit = realExit;
}

if (failed) {
    realExit(1);
}
