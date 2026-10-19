#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

export CLC_CAPABILITY_DIR="${CLC_CAPABILITY_DIR:-$repo_root/../capability}"

deno_env=CLC_CAPABILITY_DIR,CLC_PROPERTY_CASES,CLC_VECTORS,CLC_D_VECTORS
deno_env+=",CLC_D_PROPERTY_CASES,CLC_PARAM_BOUNDS_VECTORS"
deno_env+=",CLC_PARAM_BOUNDS_MEET_VECTORS,CLC_PARAM_BOUNDS_MEET_PROPERTY_CASES"
deno_env+=",CLC_RESOLVE_VECTORS,CLC_CONSTRAINT_UNION_VECTORS"
deno_env+=",CLC_AUTHORIZE_CHAIN_VECTORS,CLC_SYMMETRY_VECTORS"
deno_env+=",CLC_QUANTITY_VECTORS,CLC_SCHEME_DECLARATION"
deno_env+=",CLC_STRING_DOMAIN_VECTORS,CLC_SCHEME_DECLARATION_VECTORS"
deno_env+=",CLC_OCMP_VECTORS,CLC_PROFILE_DECLARATIONS"

echo "== Node =="
node --disable-warning=ExperimentalWarning \
    --experimental-strip-types \
    ts/coverage-entry.ts

if command -v bun >/dev/null 2>&1; then
    echo "== Bun =="
    bun ts/coverage-entry.ts
else
    echo "SKIP: Bun is not installed"
fi

if command -v deno >/dev/null 2>&1; then
    echo "== Deno =="
    deno run --quiet \
        --allow-read \
        --allow-env="$deno_env" \
        ts/coverage-entry.ts
else
    echo "SKIP: Deno is not installed"
fi
