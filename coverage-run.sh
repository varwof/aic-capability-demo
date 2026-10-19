#!/usr/bin/env bash
set -euo pipefail

coverage_bin="${COVERAGE:-coverage}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"
export COVERAGE_FILE="${COVERAGE_FILE:-/tmp/clc-python-coverage.data}"
export CLC_CAPABILITY_DIR="${CLC_CAPABILITY_DIR:-$repo_root/../capability}"
export CLC_VECTORS="${CLC_VECTORS:-$CLC_CAPABILITY_DIR/data/_vectors/clc-v1/vectors.json}"
export CLC_PROPERTY_CASES="${CLC_PROPERTY_CASES:-$CLC_CAPABILITY_DIR/data/_vectors/clc-v1/property-cases.json}"
export CLC_D_VECTORS="${CLC_D_VECTORS:-$CLC_CAPABILITY_DIR/data/_vectors/clc-d/containment-vectors.json}"
export CLC_D_PROPERTY_CASES="${CLC_D_PROPERTY_CASES:-$CLC_CAPABILITY_DIR/data/_vectors/clc-d/containment-property-cases.json}"
export CLC_PARAM_BOUNDS_VECTORS="${CLC_PARAM_BOUNDS_VECTORS:-$CLC_CAPABILITY_DIR/data/_vectors/clc-v1/param-bounds-vectors.json}"
export CLC_PARAM_BOUNDS_MEET_VECTORS="${CLC_PARAM_BOUNDS_MEET_VECTORS:-$CLC_CAPABILITY_DIR/data/_vectors/clc-v1/param-bounds-meet-vectors.json}"
export CLC_PARAM_BOUNDS_MEET_PROPERTY_CASES="${CLC_PARAM_BOUNDS_MEET_PROPERTY_CASES:-$CLC_CAPABILITY_DIR/data/_vectors/clc-v1/param-bounds-meet-property-cases.json}"
export CLC_RESOLVE_VECTORS="${CLC_RESOLVE_VECTORS:-$CLC_CAPABILITY_DIR/data/_vectors/clc-v1/resolve-vectors.json}"
export CLC_CONSTRAINT_UNION_VECTORS="${CLC_CONSTRAINT_UNION_VECTORS:-$CLC_CAPABILITY_DIR/data/_vectors/clc-v1/constraint-union-vectors.json}"
export CLC_AUTHORIZE_CHAIN_VECTORS="${CLC_AUTHORIZE_CHAIN_VECTORS:-$CLC_CAPABILITY_DIR/data/_vectors/clc-d/authorize-chain-vectors.json}"

"$coverage_bin" erase

run_cov() {
    "$coverage_bin" run --branch --append "$@"
}

run_cov extended_test.py
run_cov edge_test.py
run_cov property_test.py
run_cov vectors-run.py
run_cov contains-vectors-run.py
run_cov contain-property-run.py
run_cov param-bounds-vectors-run.py
run_cov param-bounds-meet-vectors-run.py
run_cov param-bounds-meet-property-run.py
run_cov resolve-vectors-run.py
run_cov constraint-union-vectors-run.py
run_cov authorize-chain-vectors-run.py
run_cov symmetry-vectors-run.py
run_cov quantity-vectors-run.py
run_cov scheme-declaration-vectors-run.py
run_cov offline-vectors-run.py
run_cov profile-declarations-run.py

"$coverage_bin" report \
    --include='clc_semantics.py,evidence_semantics.py,scheme_decl.py,ocmp.py' \
    --fail-under=80
"$coverage_bin" json -o /tmp/clc-python-coverage.json
"$coverage_bin" xml -o /tmp/clc-python-coverage.xml
