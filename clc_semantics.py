"""
CLC-v1 Capability Language Core - Python reference implementation.

This is an independent implementation of the CLC-v1 authorization semantics.
It is NOT a translation of the Go implementation; it follows the spec directly.
The对外判决 must match the Go implementation exactly.
"""
import json
import math
import re
import sys
from typing import Any, Callable, Optional


class CLCError(Exception):
    """Base error for CLC-v1 violations."""
    pass


class UnsupportedWildcard(CLCError):
    pass


class InvalidCapabilityID(CLCError):
    pass


class MissingCapabilityID(CLCError):
    pass


class InvalidParamsNull(CLCError):
    pass


class ParamsMissing(CLCError):
    pass


class ParamsUndeclared(CLCError):
    pass


class CapabilityNotAuthorized(CLCError):
    pass


class UnknownConstraint(CLCError):
    pass


class InvalidParamsDuplicateKey(CLCError):
    pass


class InvalidParamsNumber(CLCError):
    pass


class InvalidParamsSize(CLCError):
    pass


class UnsupportedLanguageRevision(CLCError):
    pass


# Known constraint types for v1 (fail-closed for unknown types)
KNOWN_CONSTRAINT_TYPES = {"max_rows", "time", "network"}

# CLC-v1 §12.1: the language revision this implementation declares.
CLC_REVISION = "CLC-1.1"
# §6.2 step 4: bounds on the JCS-serialized params form.
MAX_PARAMS_SERIALIZED_BYTES = 512
MAX_PARAMS_NESTING = 32


def validate_capability_id(cid: str) -> None:
    """Validate a capability ID against CLC-v1 §2 grammar."""
    if not cid:
        raise MissingCapabilityID("missing_capability_id")
    if cid == "*":
        raise UnsupportedWildcard("unsupported_wildcard")
    if "**" in cid:
        raise UnsupportedWildcard("unsupported_wildcard")
    if "{" in cid or "}" in cid:
        raise UnsupportedWildcard("unsupported_wildcard")
    if "[" in cid or "]" in cid:
        raise UnsupportedWildcard("unsupported_wildcard")

    parts = cid.split(":")
    for i, p in enumerate(parts):
        if "*" in p:
            if p != "*":
                raise UnsupportedWildcard("unsupported_wildcard")
            if i != len(parts) - 1:
                raise UnsupportedWildcard("unsupported_wildcard")

    if len(parts) < 2:
        raise InvalidCapabilityID("invalid_capability_id")


def validate_params(params: Optional[dict]) -> None:
    """Check for null values in params (CLC-v1 §5.2)."""
    if params is None:
        return
    for k, v in params.items():
        if v is None:
            raise InvalidParamsNull(f"invalid_params_null: {k}")


def _parse_revision(rev: str) -> tuple[Optional[int], Optional[int]]:
    """Split a CLC-<major>.<minor> revision string."""
    m = re.match(r"^CLC-(\d+)\.(\d+)$", rev)
    if not m:
        return None, None
    return int(m.group(1)), int(m.group(2))


def revision_compatible(input_revision: str) -> bool:
    """Report whether an input declaring the given CLC revision may be
    evaluated by this implementation (CLC-v1 §12.1). A mismatch fails
    closed with unsupported_language_revision — never a silent downgrade."""
    i_maj, i_min = _parse_revision(input_revision)
    if i_maj is None:
        return False
    maj, minor = _parse_revision(CLC_REVISION)
    return i_maj == maj and i_min <= minor


def _scan_raw_params(t: str) -> tuple[int, int]:
    """Return (max nesting depth, compact length) of raw JSON params text.
    Whitespace outside strings is dropped (canonical-size proxy, §6.2)."""
    depth = 0
    max_depth = 0
    length = 0
    in_string = False
    esc = False
    for ch in t:
        if in_string:
            length += 1
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            length += 1
        elif ch in "{[":
            depth += 1
            max_depth = max(max_depth, depth)
            length += 1
        elif ch in "}]":
            depth = max(0, depth - 1)
            length += 1
        elif ch in " \t\n\r":
            continue
        else:
            length += 1
    return max_depth, length


def _significant_digits(lit: str) -> int:
    s = lit
    e = s.lower().find("e")
    if e != -1:
        s = s[:e]
    s = s.lstrip("+-")
    if "." in s:
        s = s.replace(".", "", 1)
    s = s.lstrip("0").rstrip("0")
    return len(s)


def validate_raw_params(raw: str) -> None:
    """Validate the raw JSON text of an operation's params object at the
    input boundary (§6.2, §9.3 layer 2), before any layer runs. Unlike a
    decoded dict, the raw text preserves duplicate keys, number literals,
    nesting depth and serialized size — none of which survive a dict-based
    decode (dicts drop duplicate keys, and JSON cannot carry non-finite
    numbers). Rejections follow §6.2 order: size/depth, then duplicate
    keys, then number shape; malformed input and a non-object params value
    fall into invalid_params_number."""
    t = raw.strip()
    if not t or not t.startswith("{"):
        raise InvalidParamsNumber("invalid_params_number")

    depth, compact_len = _scan_raw_params(t)
    if compact_len > MAX_PARAMS_SERIALIZED_BYTES or depth > MAX_PARAMS_NESTING:
        raise InvalidParamsSize("invalid_params_size")

    dup_key: list[str] = []
    bad_numbers: list[str] = []

    def obj_pairs(pairs: list[tuple[str, Any]]) -> dict:
        seen = set()
        for k, _ in pairs:
            if k in seen:
                if not dup_key:
                    dup_key.append(k)
                break
            seen.add(k)
        return dict(pairs)

    def num_hook(lit: str) -> Any:
        try:
            v = float(lit)
        except (ValueError, OverflowError):
            bad_numbers.append(lit)
            return 0.0
        if not math.isfinite(v) or _significant_digits(lit) > 17:
            bad_numbers.append(lit)
        return v

    try:
        json.loads(
            t,
            parse_int=num_hook,
            parse_float=num_hook,
            object_pairs_hook=obj_pairs,
        )
    except (json.JSONDecodeError, ValueError, RecursionError):
        raise InvalidParamsNumber("invalid_params_number")

    if dup_key:
        raise InvalidParamsDuplicateKey(
            f"invalid_params_duplicate_key: {dup_key[0]}"
        )
    if bad_numbers:
        raise InvalidParamsNumber(f"invalid_params_number: {bad_numbers[0]}")


def canonical_reason(reason: str) -> str:
    """Stable reason code: everything before the first ':' (§9.4).

    Implementations MAY append ": <detail>" as a diagnostic suffix; the
    canonical prefix is what tooling and compatibility checks compare.
    """
    if not reason:
        return ""
    return reason.split(":", 1)[0]


def namespace_of(cap_id: str) -> str:
    """Return scheme:action_class (first two ':'-delimited segments),
    per CLC-v1 §9.3 layer 3."""
    parts = cap_id.split(":")
    return parts[0] + ":" + parts[1] if len(parts) >= 2 else cap_id


def match_id(grant_id: str, op_id: str) -> tuple[bool, str]:
    """Check if grant ID covers operation ID per CLC-v1 §5.1 + §9.3.
    Layer 3 (namespace = scheme + action Class) first, then Layer 4
    (path coverage). Trailing * matches one or more segments."""
    g_parts = grant_id.split(":")
    o_parts = op_id.split(":")

    # §9.3 layer 3: namespace (scheme + action Class)
    if namespace_of(grant_id) != namespace_of(op_id):
        return False, "different_namespace"

    # §9.3 layer 4: path coverage within the same namespace
    if len(g_parts) != len(o_parts):
        if g_parts[-1] == "*":
            if len(o_parts) <= len(g_parts) - 1:
                return False, "wildcard_requires_trailing_segment"
            for i in range(len(g_parts) - 1):
                if g_parts[i] != o_parts[i]:
                    return False, "literal_mismatch"
            return True, ""
        # Exact grant does not broaden to a longer path
        return False, "literal_mismatch"

    for i in range(len(g_parts)):
        if g_parts[i] == "*":
            if i == len(g_parts) - 1:
                return True, ""
            return False, "literal_mismatch"
        if g_parts[i] != o_parts[i]:
            return False, "literal_mismatch"

    return True, ""


def is_empty_bound(v: Any) -> bool:
    """Explicit empty [] or {} param value (CLC-v1 §9.3 layer 5)."""
    return isinstance(v, (list, dict)) and len(v) == 0


def has_empty_bound(params: dict) -> bool:
    return any(is_empty_bound(v) for v in params.values())


def params_subset(op_params: Optional[dict], grant_params: Optional[dict]) -> tuple[bool, str]:
    """Check if operation params are a subset of grant params per CLC-v1 §5.2.
    When several conditions fail at once, the resolved reason follows
    §9.3 layers 5-9 (empty bound, null, presence, enum, bound)."""
    if grant_params is None:
        return True, ""
    if op_params is None:
        return False, "params_missing"

    # §9.3 layer 5: explicit empty bound ([] or {}) on the grant side
    for gv in grant_params.values():
        if is_empty_bound(gv):
            return False, "empty_bound_denies_class"

    # §9.3 layer 6: null values
    for k, gv in grant_params.items():
        if gv is None:
            return False, f"invalid_params_null: {k}"
    for k, ov in op_params.items():
        if ov is None:
            return False, f"invalid_params_null: {k}"

    # §9.3 layer 7: presence (all grant keys must be present in op)
    for k in grant_params:
        if k not in op_params:
            return False, "params_missing"

    # §9.3 layer 7 (request side): key closure — every op key must be
    # declared by the grant; the missing-key check above resolves first.
    for k in op_params:
        if k not in grant_params:
            return False, f"undeclared_param: {k}"

    # §9.3 layers 8-9: per-key value checks (enum membership, bounds)
    for k, gv in grant_params.items():
        ok, reason = value_subset(op_params[k], gv)
        if not ok:
            return False, reason

    return True, ""


def value_subset(op_val: Any, grant_val: Any) -> tuple[bool, str]:
    """Check if a single value is a subset of the grant value."""
    if op_val is None:
        return False, "invalid_params_null"
    if grant_val is None:
        return False, "empty_bound_denies_class"

    # Booleans are exact and are NOT numbers (CLC-v1 §6.2): `True` must not be
    # satisfied by `1`.  Python makes bool a subclass of int, so this branch has
    # to come before the numeric one — otherwise `1 <= True` and the grant
    # silently widens (fail-open).
    if isinstance(grant_val, bool) or isinstance(op_val, bool):
        if not (isinstance(grant_val, bool) and isinstance(op_val, bool)):
            return False, "params_exceed_grant"
        if op_val != grant_val:
            return False, "params_exceed_grant"
        return True, ""

    if isinstance(grant_val, (int, float)):
        if not isinstance(op_val, (int, float)) or isinstance(op_val, bool):
            return False, "params_exceed_grant"
        if op_val > grant_val:
            return False, "params_exceed_grant"
        return True, ""

    if isinstance(grant_val, str):
        if not isinstance(op_val, str) or op_val != grant_val:
            return False, "params_exceed_grant"
        return True, ""

    if isinstance(grant_val, list):
        # v1.1 enum semantics: an array-valued grant parameter is the set
        # of allowed values. The request may supply a scalar (must equal a
        # member) or an array (every element must equal a member). Numbers
        # inside the set are exact values, not bounds. An explicitly empty
        # grant set denies the class.
        if len(grant_val) == 0:
            return False, "empty_bound_denies_class"
        elems = op_val if isinstance(op_val, list) else [op_val]
        for o in elems:
            if o not in grant_val:
                return False, "not_in_enum"
        return True, ""

    if isinstance(grant_val, dict):
        if not isinstance(op_val, dict):
            return False, "params_exceed_grant"
        for k, gvv in grant_val.items():
            if k not in op_val:
                return False, "params_missing"
            ok, reason = value_subset(op_val[k], gvv)
            if not ok:
                return False, reason
        return True, ""

    # Exact equality
    if op_val != grant_val:
        return False, "params_exceed_grant"
    return True, ""


def entails(grant: dict, op: dict) -> dict:
    """Check if a grant covers an operation per CLC-v1 §5."""
    try:
        validate_capability_id(grant["id"])
    except CLCError as e:
        return {"entails": False, "reason": str(e)}

    try:
        validate_capability_id(op["id"])
    except CLCError as e:
        return {"entails": False, "reason": str(e)}

    # §5.3 step 1: scheme check
    g_scheme = grant["id"].split(":")[0]
    o_scheme = op["id"].split(":")[0]
    if g_scheme != o_scheme:
        return {"entails": False, "reason": "different_namespace"}

    # §5.3 step 2: id coverage
    ok, reason = match_id(grant["id"], op["id"])
    if not ok:
        return {"entails": False, "reason": reason}

    # §5.3 step 3: grant params absent → true (unconstrained)
    if grant.get("params") is None:
        return {"entails": True}

    # Validate null values
    try:
        validate_params(grant.get("params"))
    except CLCError as e:
        return {"entails": False, "reason": str(e)}

    try:
        validate_params(op.get("params"))
    except CLCError as e:
        return {"entails": False, "reason": str(e)}

    # §5.3 step 4: op params absent → false (bounded grant, fail-closed)
    if op.get("params") is None:
        return {"entails": False, "reason": "params_missing"}

    # §5.3 step 5: params subset
    ok, reason = params_subset(op.get("params"), grant.get("params"))
    if not ok:
        return {"entails": False, "reason": reason}

    return {"entails": True}


def intersect(grants: list[dict]) -> dict:
    """Combine multiple grants per CLC-v1 §6."""
    if not grants:
        raise CapabilityNotAuthorized("absent_source")

    # §9.3 layer 5: deny-when-declared — any source with an explicitly
    # empty bound ([] or {}) denies the class before any member math.
    for g in grants:
        if g.get("params") and has_empty_bound(g["params"]):
            raise CapabilityNotAuthorized("empty_bound_denies_class")

    result = grants[0].copy()

    for g in grants[1:]:
        # Check ID compatibility (§7 rule 2: the result must be covered by
        # every source, so the *narrower* identifier wins).
        if result["id"] != g["id"]:
            # Params-free comparison on purpose: entails() is the authorization
            # relation and fails closed when a bounded grant meets an operation
            # without params (§6.3 step 4), which would make two grants carrying
            # a present-but-empty params object look disjoint.
            if entails({"id": result["id"]}, {"id": g["id"]})["entails"]:
                result["id"] = g["id"]        # g is narrower
            elif not entails({"id": g["id"]}, {"id": result["id"]})["entails"]:
                raise CapabilityNotAuthorized("no_overlap")
            # otherwise result stays the narrower identifier

        # Intersect params.  Both conditions test `is not None`, mirroring the
        # Go implementation exactly: a *present but empty* params object is a
        # source that declares no constraint, and truthiness here used to let it
        # overwrite the accumulated bound (CLC-v1 §7 rule 6; P11).
        if result.get("params") is not None and g.get("params") is not None:
            intersected = {}
            for k, rv in result["params"].items():
                if k in g["params"]:
                    v, err = intersect_value(rv, g["params"][k])
                    if err:
                        raise CapabilityNotAuthorized(err)
                    intersected[k] = v
                else:
                    intersected[k] = rv
            for k, gv in g["params"].items():
                if k not in result["params"]:
                    intersected[k] = gv
            result["params"] = intersected
        elif g.get("params") is None:
            # g declares no constraint at all (params absent): keep the
            # accumulated params.  NB the test is `is None`, not truthiness:
            # an *empty* params object is a present-but-unconstrained source,
            # and treating it as falsy used to overwrite the accumulated bound
            # (CLC-v1 §7 rule 6; P11).  This mirrors the Go implementation.
            pass
        else:
            # result is unconstrained (params absent), adopt g params
            result["params"] = g["params"]

        # Merge constraints (§7 rule 3): constraints are conjunctive, so the
        # merge is a set *union* — every constraint of every source stays in
        # force, and for the same constraint type the tightest one binds.
        result_constraints = set(result.get("constraints", []))
        result_constraints.update(g.get("constraints", []))
        result["constraints"] = list(result_constraints)

    return result


def intersect_value(a: Any, b: Any) -> tuple[Any, str]:
    """Intersect two values."""
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return min(a, b), ""

    if isinstance(a, list) and isinstance(b, list):
        result = [x for x in a if x in b]
        if not result:
            return None, "no_overlap"
        return result, ""

    if isinstance(a, dict) and isinstance(b, dict):
        result = {}
        for k in a:
            if k in b:
                v, err = intersect_value(a[k], b[k])
                if err:
                    return None, err
                result[k] = v
        if not result:
            return None, "no_overlap"
        return result, ""

    if a == b:
        return a, ""
    return None, "no_overlap"


def validate_constraint(c: str) -> None:
    """Check if a constraint is known (CLC-v1 §7)."""
    parts = c.split(":")
    if len(parts) < 2:
        raise UnknownConstraint("unknown_constraint")
    constraint_type = parts[1]
    if constraint_type not in KNOWN_CONSTRAINT_TYPES:
        raise UnknownConstraint("unknown_constraint")


def check_constraint(c: str, op: dict) -> Optional[str]:
    """Evaluate a constraint against an operation."""
    parts = c.split(":")
    if len(parts) < 3:
        return None

    constraint_type = parts[1]
    if constraint_type == "max_rows" and len(parts) >= 3:
        try:
            max_val = float(parts[2])
        except ValueError:
            return None
        params = op.get("params", {})
        if params and "max_rows" in params:
            rows = params["max_rows"]
            if isinstance(rows, (int, float)) and rows > max_val:
                return "max_rows:violated"

    return None


def _is_params_level_reason(reason: str) -> bool:
    """Report whether an entailment failure is a params-level reason
    (propagated by authorize) rather than an ID-level reason (collapsed
    to capability_not_authorized per CLC-v1 §9 step 3)."""
    return reason in {"params_missing", "undeclared_param", "params_exceed_grant",
                      "empty_bound_denies_class", "not_in_enum",
                      "invalid_params_duplicate_key", "invalid_params_number",
                      "invalid_params_size", "unsupported_language_revision"} \
        or reason.startswith("invalid_params_null") or reason.startswith("undeclared_param")


def authorize(effective_grant: dict, op: dict) -> dict:
    """Evaluate the decision function per CLC-v1 §8."""
    # Absent/empty grant: no capability to check → fail-closed (§9 layer 10).
    if effective_grant is None or not effective_grant:
        return {"verdict": "deny", "reason": "capability_not_authorized"}

    # Absent operation → fail-closed (layer 1).
    if op is None:
        return {"verdict": "deny", "reason": "missing_capability_id"}

    # Step 1: Validate operation
    if not op.get("id"):
        return {"verdict": "deny", "reason": "missing_capability_id"}

    try:
        validate_capability_id(op["id"])
    except CLCError as e:
        return {"verdict": "deny", "reason": str(e)}

    # Validate operation params for null
    try:
        validate_params(op.get("params"))
    except CLCError as e:
        return {"verdict": "deny", "reason": str(e)}

    # Step 2: Check entailment
    result = entails(effective_grant, op)
    if not result["entails"]:
        reason = result["reason"]
        if _is_params_level_reason(reason):
            return {"verdict": "deny", "reason": reason}
        return {"verdict": "deny", "reason": "capability_not_authorized"}

    # Step 3: Evaluate constraints
    for c in effective_grant.get("constraints", []):
        try:
            validate_constraint(c)
        except CLCError as e:
            return {"verdict": "deny", "reason": str(e)}
        violation = check_constraint(c, op)
        if violation:
            return {"verdict": "deny", "reason": violation}

    return {"verdict": "allow"}
