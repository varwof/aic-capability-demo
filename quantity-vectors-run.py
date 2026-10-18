#!/usr/bin/env python3
"""Run the CLC-1.19 quantity corpus against the sample scheme declaration."""

from __future__ import annotations

import json
import os
import sys

import scheme_decl

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.environ.get("CLC_CAPABILITY_DIR", os.path.join(HERE, "..", "capability"))
DECL = os.environ.get("CLC_SCHEME_DECLARATION", os.path.join(CAP, "data", "std", "payments-v1", "clc-declaration.json"))
VECTORS = os.environ.get("CLC_QUANTITY_VECTORS", os.path.join(CAP, "data", "_vectors", "clc-v1", "quantity-vectors.json"))


def main() -> int:
    try:
        decl = scheme_decl.load(DECL)
    except scheme_decl.DeclarationError as e:
        print(f"declaration: {e.code}")
        return 2
    with open(VECTORS, encoding="utf-8") as f:
        vectors = json.load(f)

    print("CLC-1.19 quantity domain")
    print("declaration: %s" % decl["declaration_id"])
    print("-" * 96)
    failures = 0
    for v in vectors:
        if v["kind"] == "authorize":
            got = scheme_decl.authorize(decl, v["capability"], v["grants"], v["operation"])
            ok = got.get("verdict") == v["expect"]["verdict"] and (
                not v["expect"].get("reason") or got.get("reason", "").startswith(v["expect"]["reason"]))
            shown = got.get("verdict", "?") + (("/" + got["reason"]) if got.get("reason") else "")
            want = v["expect"]["verdict"] + (("/" + v["expect"]["reason"]) if v["expect"].get("reason") else "")
        else:
            got = scheme_decl.contains(decl, v["capability"], v["parent"], v["child"])
            ok = bool(got.get("contains")) == bool(v["expect"]["contains"]) and (
                v["expect"]["contains"] or not v["expect"].get("reason") or got.get("reason", "").startswith(v["expect"]["reason"]))
            shown = "contains=" + str(bool(got.get("contains"))).lower() + (("/" + got["reason"]) if got.get("reason") else "")
            want = "contains=" + str(bool(v["expect"]["contains"])).lower() + (("/" + v["expect"]["reason"]) if v["expect"].get("reason") else "")
        if not ok:
            failures += 1
        print(f"{v['id']:<7} {v['kind']:<10} want {want:<32} got {shown:<32} {'PASS' if ok else 'FAIL'}")
    # Fail-closed path: a declared-but-unimplemented domain.
    import copy
    decl2 = copy.deepcopy(decl)
    decl2["capabilities"]["transfer"]["params"]["amount"] = {"domain": "money"}
    got = scheme_decl.authorize(decl2, "transfer",
        [{"id": "std/payments-v1:transfer", "params": {"amount": "/srv/a"}}],
        {"id": "std/payments-v1:transfer", "params": {"amount": "/srv/a/b"}})
    ok = got.get("verdict") == "deny" and got.get("reason") == "unsupported_domain"
    if not ok:
        failures += 1
    print(f"{'u-001':<7} {'domain':<10} want {'deny/unsupported_domain':<32} got {got.get('verdict','?') + '/' + got.get('reason',''):<32} {'PASS' if ok else 'FAIL'}")
    # A declared-domain key must not also carry a param_bounds family.
    got = scheme_decl.authorize(decl, "transfer",
        [{"id": "std/payments-v1:transfer", "param_bounds": {"amount": {"min": 1, "max": 10}}}],
        {"id": "std/payments-v1:transfer", "params": {"amount": {"value": 5, "unit": "CNY"}}})
    ok = got.get("verdict") == "deny" and got.get("reason") == "invalid_params_binding"
    if not ok:
        failures += 1
    print(f"{'p-001':<7} {'domain':<10} want {'deny/invalid_params_binding':<32} got {got.get('verdict','?') + '/' + got.get('reason',''):<32} {'PASS' if ok else 'FAIL'}")
    # String-shaped domains (shared corpus).
    sv_path = os.environ.get("CLC_STRING_DOMAIN_VECTORS", os.path.join(CAP, "data", "_vectors", "clc-v1", "string-domain-vectors.json"))
    n_string = 0
    with open(sv_path, encoding="utf-8") as f:
        for v in json.load(f):
            n_string += 1
            d = copy.deepcopy(decl)
            d["capabilities"]["transfer"]["params"] = {v["param"]: {"domain": v["domain"]}}
            got = scheme_decl.authorize(d, "transfer",
                [{"id": "std/payments-v1:transfer", "params": {v["param"]: v["grant"]}}],
                {"id": "std/payments-v1:transfer", "params": {v["param"]: v["op"]}})
            ok = got.get("verdict") == v["expect"]["verdict"] and (
                not v["expect"].get("reason") or got.get("reason", "").startswith(v["expect"]["reason"]))
            if not ok:
                failures += 1
            shown = got.get("verdict", "?") + (("/" + got["reason"]) if got.get("reason") else "")
            want = v["expect"]["verdict"] + (("/" + v["expect"]["reason"]) if v["expect"].get("reason") else "")
            print(f"{v['id']:<7} {v['domain']:<10} want {want:<32} got {shown:<32} {'PASS' if ok else 'FAIL'}")
    print("-" * 96)
    total = len(vectors) + 2 + n_string
    print(f"Total: {total} | Pass: {total-failures} | Fail: {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
