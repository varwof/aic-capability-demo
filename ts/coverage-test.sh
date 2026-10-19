#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"
export CLC_CAPABILITY_DIR="${CLC_CAPABILITY_DIR:-$repo_root/../capability}"

node --disable-warning=ExperimentalWarning \
    --experimental-strip-types \
    --experimental-test-coverage \
    --test-coverage-include='ts/clc_semantics.ts' \
    --test-coverage-include='ts/evidence_semantics.ts' \
    --test-coverage-include='ts/scheme_decl.ts' \
    --test-coverage-include='ts/ocmp.ts' \
    --test-coverage-lines=80 \
    --test-coverage-branches=70 \
    --test-coverage-functions=85 \
    --test ts/coverage-entry.ts
