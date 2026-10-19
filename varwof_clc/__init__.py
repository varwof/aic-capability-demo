"""Preview package facade for the Varwof capability-language semantics."""

from __future__ import annotations

import clc_semantics as core
import evidence_semantics as evidence
import ocmp
import scheme_decl as scheme

from clc_semantics import (
    CLC_REVISION,
    COMBINING_DENY_OVERRIDES,
    COMBINING_FIRST_APPLICABLE,
    COMBINING_PERMIT_OVERRIDES,
    VERDICT_ALLOW,
    VERDICT_ALLOW_UNRESOLVED,
    VERDICT_DENY,
    authorize,
    authorize_json_text,
    authorize_set,
    authorize_with_chain,
    canonical_json,
    combine,
    compute_action_id,
    constraint_union,
    contains,
    entails,
    intersect,
    materialize_defaults,
    resolve,
    validate_capability_id,
    validate_constraint,
    validate_param_bounds,
    validate_params,
    validate_raw_params,
)

__version__ = "0.1.0"

__all__ = [
    "CLC_REVISION",
    "COMBINING_DENY_OVERRIDES",
    "COMBINING_FIRST_APPLICABLE",
    "COMBINING_PERMIT_OVERRIDES",
    "VERDICT_ALLOW",
    "VERDICT_ALLOW_UNRESOLVED",
    "VERDICT_DENY",
    "authorize",
    "authorize_json_text",
    "authorize_set",
    "authorize_with_chain",
    "canonical_json",
    "combine",
    "compute_action_id",
    "constraint_union",
    "contains",
    "core",
    "entails",
    "evidence",
    "intersect",
    "materialize_defaults",
    "ocmp",
    "resolve",
    "scheme",
    "validate_capability_id",
    "validate_constraint",
    "validate_param_bounds",
    "validate_params",
    "validate_raw_params",
]
