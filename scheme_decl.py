"""CLC-1.19 scheme declaration pilot: the `quantity` domain.

Mirrors register/internal/schemedecl: a declaration is validated (closed shape,
known domains, fixed unit, digest) and applied as a normalization layer — each
declared quantity value becomes value * 10^-scale before the ordinary CLC
relations run.
"""

from __future__ import annotations

import hashlib
import json
import math
from base64 import urlsafe_b64encode
from typing import Any, Optional

import clc_semantics as clc

KNOWN_DOMAINS = {
    "bound", "enum", "exact",
    "quantity", "decimal-string", "subdomain", "path-prefix",
}


class DeclarationError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _digest(decl: dict) -> str:
    body = {k: v for k, v in decl.items() if k != "digest"}
    canonical = clc.canonical_json(body).encode("utf-8")
    return "sha256:" + urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        decl = json.load(f)
    validate(decl)
    return decl


def validate(decl: dict) -> None:
    if decl.get("@version") != "CLC-SCHEME-v1":
        raise DeclarationError("unsupported_declaration", str(decl.get("@version")))
    for member in ("scheme", "declaration_id", "clc_revision"):
        if not decl.get(member):
            raise DeclarationError("invalid_declaration", f"missing {member}")
    caps = decl.get("capabilities")
    if not isinstance(caps, dict) or not caps:
        raise DeclarationError("invalid_declaration", "no capabilities")
    for cap_name, cap in caps.items():
        params = cap.get("params") if isinstance(cap, dict) else None
        if not isinstance(params, dict):
            raise DeclarationError("invalid_declaration", f"{cap_name}: no params")
        for p_name, p in params.items():
            domain = p.get("domain") if isinstance(p, dict) else None
            if domain not in KNOWN_DOMAINS:
                raise DeclarationError("unsupported_domain", f"{cap_name}.{p_name} = {domain!r}")
            if domain == "quantity" and not p.get("unit"):
                raise DeclarationError("invalid_declaration", f"{cap_name}.{p_name} is quantity without unit")
            if domain != "quantity" and p.get("unit"):
                raise DeclarationError("invalid_declaration", f"{cap_name}.{p_name} has unit outside quantity")
    if decl.get("digest"):
        want = _digest(decl)
        if want != decl["digest"]:
            raise DeclarationError("declaration_digest_mismatch", f"want {want}, got {decl['digest']}")


def _param(decl: dict, capability: str, name: str) -> Optional[dict]:
    return decl.get("capabilities", {}).get(capability, {}).get("params", {}).get(name)


def _quantity_number(value: Any, unit: str) -> tuple[Optional[float], str]:
    if not isinstance(value, dict):
        return None, "invalid_params_binding"
    val = value.get("value")
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None, "invalid_params_binding"
    u = value.get("unit")
    if not isinstance(u, str) or not u:
        return None, "invalid_params_binding"
    if u != unit:
        return None, "unit_mismatch"
    scale = 0
    if "scale" in value:
        s = value["scale"]
        if isinstance(s, bool) or not isinstance(s, (int, float)) or s != math.trunc(s):
            return None, "invalid_params_binding"
        scale = int(s)
    return float(val) * (10.0 ** -scale), ""


def _domain_map(decl: dict, capability: str) -> dict:
    params = decl.get("capabilities", {}).get(capability, {}).get("params", {})
    return {name: {"domain": p.get("domain"), "unit": p.get("unit")} for name, p in params.items()}


def authorize(decl: dict, capability: str, grants: list, op: dict) -> dict:
    return clc.authorize_set_with_domains(grants, op, _domain_map(decl, capability))


def contains(decl: dict, capability: str, parent: dict, child: dict) -> dict:
    dm = _domain_map(decl, capability)
    return clc.contains_with_domains(parent, child, dm, dm)
