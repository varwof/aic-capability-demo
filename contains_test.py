#!/usr/bin/env python3
"""CLC-D Contains parity checks against the Go reference (draft-wei-clc-ext-00 §4).

Mirrors register/semantics/contains_test.go case-for-case.  Run:
python3 contains_test.py
"""
import sys

from clc_semantics import contains

GID = "std/database-v1:query:SELECT"
FAILS = []


def check(label, parent, child, want, reason=""):
    d = contains(parent, child)
    got = (d.get("contains"), d.get("reason") or "")
    if reason:
        want_tuple = (want, reason)
    else:
        want_tuple = (want, "")
    if got != want_tuple:
        FAILS.append(f"{label}: got {got}, want {want_tuple}")


# Layer 2: identifier coverage (§4.1)
check("literal equal", {"id": GID}, {"id": GID}, True)
check("child narrower id", {"id": "std/database-v1:query:*"}, {"id": GID}, True)
check("child wildcard broader than literal parent",
      {"id": GID}, {"id": "std/database-v1:query:*"}, False, "child_exceeds_parent")
check("child outside parent path",
      {"id": "std/database-v1:query:*"}, {"id": "std/database-v1:admin:DDL"}, False, "different_namespace")
check("different namespace",
      {"id": GID}, {"id": "std/crm-v1:read"}, False, "different_namespace")

# Layer 3: parameter narrowing (§4.2)
check("parent unconstrained contains bounded child",
      {"id": GID}, {"id": GID, "params": {"limit": 50}}, True)
check("number upper bound tighter",
      {"id": GID, "params": {"limit": 100}}, {"id": GID, "params": {"limit": 50}}, True)
check("number upper bound equal",
      {"id": GID, "params": {"limit": 100}}, {"id": GID, "params": {"limit": 100}}, True)
check("child bound exceeds parent",
      {"id": GID, "params": {"limit": 100}}, {"id": GID, "params": {"limit": 150}}, False, "params_not_narrower")
check("enum subset",
      {"id": GID, "params": {"tables": ["a", "b", "c"]}}, {"id": GID, "params": {"tables": ["a", "b"]}}, True)
check("enum element outside parent",
      {"id": GID, "params": {"tables": ["a", "b"]}}, {"id": GID, "params": {"tables": ["a", "z"]}}, False, "params_not_narrower")
check("child omits parent key",
      {"id": GID, "params": {"limit": 100, "offset": 10}}, {"id": GID, "params": {"limit": 50}}, False, "params_not_narrower")
check("child adds parent-undeclared key",
      {"id": GID, "params": {"limit": 100}}, {"id": GID, "params": {"limit": 50, "extra": 1}}, False, "params_not_narrower")
check("child unconstrained under bounded parent",
      {"id": GID, "params": {"limit": 100}}, {"id": GID}, False, "params_not_narrower")
check("nested object tighter",
      {"id": GID, "params": {"cfg": {"limit": 100}}}, {"id": GID, "params": {"cfg": {"limit": 50}}}, True)
check("nested object wider",
      {"id": GID, "params": {"cfg": {"limit": 50}}}, {"id": GID, "params": {"cfg": {"limit": 100}}}, False, "params_not_narrower")

# Constraints are NOT part of the relation: they compose by union across a
# delegation chain (intersect, §7), never by subset here.  Every constraint
# difference must leave the verdict alone.
check("child constraint tighter is ignored",
      {"id": GID, "constraints": ["varwof/constraint-v1:max_rows:100"]},
      {"id": GID, "constraints": ["varwof/constraint-v1:max_rows:50"]}, True)
check("child constraint wider is ignored",
      {"id": GID, "constraints": ["varwof/constraint-v1:max_rows:50"]},
      {"id": GID, "constraints": ["varwof/constraint-v1:max_rows:100"]}, True)
check("child adds constraint parent lacks is ignored",
      {"id": GID},
      {"id": GID, "constraints": ["varwof/constraint-v1:max_rows:50"]}, True)
check("child drops parent constraint is ignored",
      {"id": GID, "constraints": ["varwof/constraint-v1:max_rows:50"]},
      {"id": GID}, True)
check("unknown constraint identity is ignored",
      {"id": GID, "constraints": ["foo/db-v1:max_rows:100"]},
      {"id": GID, "constraints": ["foo/db-v1:max_rows:10"]}, True)
check("invalid constraint value is ignored",
      {"id": GID, "constraints": ["varwof/constraint-v1:max_rows:100"]},
      {"id": GID, "constraints": ["varwof/constraint-v1:max_rows:notanint"]}, True)

# Combined
check("fully narrower params",
      {"id": GID, "params": {"limit": 100}},
      {"id": GID, "params": {"limit": 50}}, True)
check("id mismatch dominates",
      {"id": GID}, {"id": "std/database-v1:admin:DDL"}, False, "different_namespace")

# Layer 1: validity
check("invalid parent id",
      {"id": "std/database-v1:query:SEL*"}, {"id": GID}, False, "unsupported_wildcard")
check("invalid child id",
      {"id": GID}, {"id": "std/database-v1:**"}, False, "unsupported_wildcard")

if FAILS:
    print(f"FAIL: {len(FAILS)} contains parity failures")
    for f in FAILS:
        print("  ", f)
    sys.exit(1)
print("OK: contains parity checks pass")