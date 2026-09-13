#!/usr/bin/env python3
"""Edge-case checks that a JSON corpus cannot carry (rev CLC-1.4).

JSON cannot represent NaN or +/-Infinity, so the "a value no bound check can
compare must not become an allow" rule is pinned here rather than in
vectors.json.  Run: python3 edge_test.py
"""
import math
import sys

from clc_semantics import authorize

GID = "std/database-v1:query:SELECT"
FAILS = []


def check(label, got, want):
    if got != want:
        FAILS.append(f"{label}: got {got}, want {want}")


for name, value in (("NaN", math.nan), ("+Inf", math.inf), ("-Inf", -math.inf)):
    d = authorize({"id": GID, "params": {"limit": 100}}, {"id": GID, "params": {"limit": value}})
    check(f"{name} under a numeric bound", (d.get("verdict"), d.get("reason")),
          ("deny", "invalid_params_number"))

d = authorize({"id": GID, "constraints": ["varwof/constraint-v1:max_rows:10"]},
              {"id": GID, "params": {"max_rows": math.nan}})
check("NaN max_rows (refused at the input boundary, before the constraint runs)",
      d.get("reason"), "invalid_params_number")

if FAILS:
    print("\n".join(FAILS))
    sys.exit(1)
print("edge_test: 4 checks passed (non-finite values never allow)")
