#!/usr/bin/env python3
"""CLC differential fuzz: tri-implementation comparison.

Inputs:
  1. cases file (gen_cases.py JSONL) — source of the per-case axis label
  2. results JSONL from run_py.py
  3. results JSONL from run_ts.ts
  4. results JSONL from fuzz_runner (Go)

Classification (per case):
  - cross_impl: for each path (raw_path / decoded_path) the verdict+reason
    differs across impls, OR canonical_sha256 differs whenever a shared value
    is producible.
  - cross_path: within one impl, raw_text vs decoded_object verdict+reason
    differ (this is the §6.2 boundary divergence Iman reported).
  - unstable: an impl crashed or produced no result where others produced a
    clean decision.

Emits one JSON object on stdout. Determinism is NOT judged here: rerun both
rounds and diff the emitted bytes (see README).

Usage: compare.py <cases.jsonl> <py.jsonl> <ts.jsonl> <go.jsonl>
"""

import json
import sys
from collections import Counter, defaultdict

PATHS = ("raw_path", "decoded_path")


def load(path):
    out = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            out[r["id"]] = r
    return out


def path_key(p):
    return (p["verdict"], p["reason"])


def main():
    if len(sys.argv) < 5:
        sys.stderr.write(
            "usage: compare.py <cases.jsonl> <py.jsonl> <ts.jsonl> <go.jsonl>\n")
        return 2

    axis_of = {}
    cases = load(sys.argv[1])
    for cid, c in cases.items():
        axis_of[cid] = c.get("axis", "unknown")
    impls = {"py": load(sys.argv[2]), "ts": load(sys.argv[3]),
             "go": load(sys.argv[4])}

    ids = set()
    for rows in impls.values():
        ids.update(rows)
    ids.update(axis_of)
    ids = sorted(ids)

    cross_impl, cross_path, unstable = [], [], []

    for cid in ids:
        rows = {name: impls[name].get(cid) for name in impls}
        # unstable: any impl crashed / missing, or any impl missing line
        crashed = [
            name for name, r in rows.items()
            if r is None or r.get("error")
        ]
        if crashed:
            unstable.append({
                "id": cid,
                "axis": axis_of.get(cid, "unknown"),
                "impls": sorted(crashed),
                "detail": {
                    name: (rows[name].get("error") if rows[name] and rows[name].get("error") else "missing")
                    for name in crashed
                },
            })
            continue

        # cross-path within each impl
        for name, r in rows.items():
            if path_key(r["raw_path"]) != path_key(r["decoded_path"]):
                cross_path.append({
                    "id": cid, "impl": name,
                    "axis": axis_of.get(cid, "unknown"),
                    "raw": r["raw_path"], "decoded": r["decoded_path"],
                })

        # cross-impl per path + canonical digest
        for p in PATHS:
            keys = {name: path_key(rows[name][p]) for name in impls}
            if len(set(keys.values())) > 1:
                cross_impl.append({
                    "id": cid, "path": p, "axis": axis_of.get(cid, "unknown"),
                    "keys": {name: list(k) for name, k in keys.items()},
                })
        shas = {name: rows[name].get("canonical_sha256", "") for name in impls}
        real = [s for s in shas.values() if s]
        if real and len(set(real)) > 1:
            cross_impl.append({
                "id": cid, "path": "canonical_sha256",
                "axis": axis_of.get(cid, "unknown"),
                "keys": {"canonical_sha256": shas},
            })

    # --- summary ---------------------------------------------------------------
    per_axis = defaultdict(lambda: {"N": 0, "cross_impl": set(), "cross_path": set()})
    for r in cross_impl:
        per_axis[r["axis"]]["cross_impl"].add(r["id"])
    for r in cross_path:
        per_axis[r["axis"]]["cross_path"].add(r["id"])
    for ax, axes in per_axis.items():
        axes["N"] = sum(1 for c in cases.values() if c.get("axis") == ax)
    per_axis = {
        ax: {"N": v["N"], "cross_impl": sorted(v["cross_impl"]),
             "cross_path": sorted(v["cross_path"])}
        for ax, v in sorted(per_axis.items())
    }

    cross_impl_by_path = Counter(r["path"] for r in cross_impl)
    reason_counter = Counter()
    for r in cross_impl:
        if r["path"] == "canonical_sha256":
            continue
        rs = sorted(set(k[1] for k in r["keys"].values()))
        reason_counter[tuple(rs)] += 1
    cross_path_by_impl = Counter(r["impl"] for r in cross_path)

    summary = {
        "N_cases": len(ids),
        "per_axis": per_axis,
        "cross_impl_by_path": dict(cross_impl_by_path),
        "cross_impl_reason": [
            {"divergent_reasons": list(k), "count": c}
            for k, c in reason_counter.most_common()
        ],
        "cross_path_by_impl": dict(cross_path_by_impl),
        "unstable_count": len(unstable),
        "no_divergence_axes": sorted(
            ax for ax, v in per_axis.items()
            if not v["cross_impl"] and not v["cross_path"]
        ),
    }

    print(json.dumps({
        "classes": {
            "cross_impl": cross_impl,
            "cross_path": cross_path,
            "unstable": unstable,
        },
        "summary": summary,
    }, indent=1, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())