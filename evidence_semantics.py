"""Minimal evidence-side evaluator (CLC §8.2 / §10) for the symmetry runner.

Covers the four core constraint types and the bounded AND/OR requirement
grammar.  Unknown or unimplemented input fails closed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _eligible(facts: list[dict]) -> list[dict]:
    return [f for f in facts if f.get("verified") is True]


def evaluate_constraint(c: str, facts: list[dict], ctx: dict[str, Any]) -> tuple[str, str]:
    if not c.startswith("varwof/evidence-v1:"):
        raise ValueError("invalid_evidence_constraint: %s" % c)
    parts = c.split(":")
    kind = parts[1]
    now = _parse_time(ctx.get("now")) or datetime.now(timezone.utc)
    if kind == "freshness":
        sec = int(parts[3])
        fs = _eligible(facts)
        if not fs:
            return "violated", "freshness:no_eligible_fact"
        for f in fs:
            t = _parse_time(f.get("issued_at"))
            if t is None:
                return "violated", "freshness:no_issuance_time"
            if t > now:
                return "violated", "freshness:future_issued"
            if (now - t).total_seconds() > sec:
                return "violated", "freshness:stale"
        return "satisfied", ""
    if kind == "quorum":
        threshold = int(parts[3])
        distinct = {f.get("subject") for f in _eligible(facts) if f.get("subject")}
        if len(distinct) < threshold:
            return "violated", "quorum:distinct_subjects=%d<threshold=%d" % (len(distinct), threshold)
        return "satisfied", ""
    if kind == "exclusion":
        who = parts[2]
        ident = ctx.get("initiator" if who == "initiator" else "executor")
        if not ident:
            return "unknown", "exclusion:identity_not_supplied"
        for f in _eligible(facts):
            if f.get("subject") == ident:
                return "violated", "exclusion:%s_is_approver" % who
        return "satisfied", ""
    if kind == "consumption":
        return "unknown", "evidence_not_core_evaluated"
    raise ValueError("invalid_evidence_constraint: %s" % c)


def evaluate_requirement(req: dict, facts: list[dict], ctx: dict[str, Any]) -> tuple[str, str]:
    expr = req.get("expression", "")
    constraints: dict[str, list[str]] = {}
    for c in req.get("constraints", []):
        constraints.setdefault(c["role"], []).append(c["constraint"])

    def role_true(role: str) -> bool:
        fs = [f for f in _eligible(facts) if f.get("type") == role]
        if not fs:
            return False
        for c in constraints.get(role, []):
            v, _ = evaluate_constraint(c, fs, ctx)
            if v != "satisfied":
                return False
        return True

    # Bonded grammar: AND/OR, left to right, parentheses not needed here.
    tokens = expr.split()
    if not tokens:
        return "UNSATISFIED", "requirement:expression_false"
    value = role_true(tokens[0])
    i = 1
    while i + 1 < len(tokens):
        op, role = tokens[i], tokens[i + 1]
        if op == "AND":
            value = value and role_true(role)
        elif op == "OR":
            value = value or role_true(role)
        else:
            return "UNSATISFIED", "requirement:expression_false"
        i += 2
    return ("SATISFIED", "") if value else ("UNSATISFIED", "requirement:expression_false")
