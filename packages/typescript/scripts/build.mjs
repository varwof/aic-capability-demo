import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(packageRoot, '..', '..');
const tsc = resolve(repoRoot, 'ts', 'node_modules', 'typescript', 'bin', 'tsc');

if (!existsSync(tsc)) {
    throw new Error('TypeScript is not installed. Run "npm ci --prefix ts" from the repository root.');
}

rmSync(resolve(packageRoot, 'dist'), { recursive: true, force: true });

for (const config of ['tsconfig.esm.json', 'tsconfig.cjs.json']) {
    const result = spawnSync(process.execPath, [tsc, '-p', resolve(packageRoot, config)], {
        cwd: packageRoot,
        stdio: 'inherit',
    });
    if (result.status !== 0) {
        process.exit(result.status ?? 1);
    }
}

const entry = resolve(packageRoot, 'dist', 'esm', 'packages', 'typescript', 'src', 'index.js');
if (!existsSync(entry)) {
    throw new Error('ESM build did not produce the package entry point.');
}

const cjsDir = resolve(packageRoot, 'dist', 'cjs');
mkdirSync(cjsDir, { recursive: true });
writeFileSync(resolve(cjsDir, 'package.json'), '{\n  "type": "commonjs"\n}\n');
