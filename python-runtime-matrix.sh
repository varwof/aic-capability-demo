#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
capability_dir="${CLC_CAPABILITY_DIR:-$repo_root/../capability}"
work_dir="$(mktemp -d /tmp/varwof-clc-python-matrix.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

versions=(3.10 3.11 3.12 3.13 3.14)
tests=(
    extended_test.py
    edge_test.py
    property_test.py
    vectors-run.py
    contains-vectors-run.py
    contain-property-run.py
    param-bounds-vectors-run.py
    param-bounds-meet-vectors-run.py
    param-bounds-meet-property-run.py
    resolve-vectors-run.py
    constraint-union-vectors-run.py
    authorize-chain-vectors-run.py
    symmetry-vectors-run.py
    quantity-vectors-run.py
    scheme-declaration-vectors-run.py
    offline-vectors-run.py
    profile-declarations-run.py
    jcs_check.py
)

resolve_python() {
    local version=$1
    if command -v uv >/dev/null 2>&1; then
        uv python find "$version"
        return
    fi
    command -v "python$version"
}

binaries=()
for version in "${versions[@]}"; do
    binaries+=("$(resolve_python "$version")")
done

build_python=${binaries[0]}
"$build_python" -m pip wheel "$repo_root" \
    --no-deps \
    --wheel-dir "$work_dir/dist" \
    >/dev/null
wheel=$(find "$work_dir/dist" -name 'varwof_clc-*.whl' -print -quit)

failed=0
for index in "${!versions[@]}"; do
    version=${versions[$index]}
    python_bin=${binaries[$index]}
    passed=0

    for test_file in "${tests[@]}"; do
        log="$work_dir/${version}-${test_file}.log"
        if CLC_CAPABILITY_DIR="$capability_dir" \
            "$python_bin" "$repo_root/$test_file" >"$log" 2>&1; then
            passed=$((passed + 1))
        else
            printf 'FAIL Python %s %s\n' "$version" "$test_file"
            tail -30 "$log"
            failed=1
        fi
    done

    venv="$work_dir/venv-$version"
    if ! "$python_bin" -m venv "$venv" >"$work_dir/venv-$version.log" 2>&1; then
        printf 'FAIL Python %s venv\n' "$version"
        tail -30 "$work_dir/venv-$version.log"
        failed=1
        continue
    fi

    if ! "$venv/bin/python" -m pip install \
        --no-index --no-deps "$wheel" \
        >"$work_dir/install-$version.log" 2>&1; then
        printf 'FAIL Python %s wheel-install\n' "$version"
        tail -30 "$work_dir/install-$version.log"
        failed=1
        continue
    fi

    smoke=$(
        cd "$work_dir"
        "$venv/bin/python" -c \
            "import varwof_clc as clc; d=clc.authorize({'id':'std/database-v1:query:SELECT','params':{'limit':100}}, {'id':'std/database-v1:query:SELECT','params':{'limit':50}}); print(clc.__version__, clc.CLC_REVISION, d['verdict'])"
    ) || {
        printf 'FAIL Python %s wheel-smoke\n' "$version"
        failed=1
        continue
    }

    printf 'PASS Python %-4s tests=%d/%d wheel=%s\n' \
        "$version" "$passed" "${#tests[@]}" "$smoke"
done

exit "$failed"
