"""Compatibility wrappers for the evidence-side evaluator.

The normative implementation now lives in clc_semantics.py.  The symmetry
runner keeps its original tuple-returning API here; delegating to the core
implementation prevents the two evidence evaluators from drifting.
"""

from __future__ import annotations

from typing import Any

import clc_semantics as clc


def evaluate_constraint(
    c: str, facts: list[dict], ctx: dict[str, Any] | None = None,
) -> tuple[str, str]:
    result = clc.evaluate_evidence_constraint(c, facts, ctx or {})
    return result["verdict"], result.get("reason", "")


def evaluate_requirement(
    req: dict, facts: list[dict], ctx: dict[str, Any] | None = None,
) -> tuple[str, str]:
    result = clc.evaluate_requirement(req, facts, ctx or {})
    satisfaction = clc.requirement_satisfaction(result)
    return satisfaction["verdict"], satisfaction.get("reason", "")
