"""OCMP offline profile (R2–R7), mirroring register/ocmp."""

from __future__ import annotations


def evaluate(inp: dict) -> tuple[str, str]:
    st = inp.get("status", {})
    if not inp.get("grant_covers"):
        return "deny", "capability_not_authorized"
    if not inp.get("trust_anchor"):
        return "deny", "trust_anchor_missing"
    if not inp.get("local_policy"):
        return "deny", "local_policy_missing"
    if not st.get("present") or not st.get("verified"):
        return "deny", "status_snapshot_missing"
    t = inp.get("trusted_time", 0)
    if t < st.get("as_of", 0) or t > st.get("valid_until", 0):
        return "deny", "status_snapshot_expired"
    if st.get("version", 0) < st.get("last_accepted", 0):
        return "deny", "status_snapshot_rollback"
    if inp.get("revoked"):
        return "deny", "revoked"
    if inp.get("credential_expired"):
        return "deny", "capability_not_authorized"
    if inp.get("replay_enabled"):
        if inp.get("counter", 0) == inp.get("last_consumed", 0):
            return "deny", "replay_detected"
        if inp.get("counter", 0) < inp.get("last_consumed", 0):
            return "deny", "replay_state_invalid"
    if inp.get("required_fact") and not inp.get("fact_available"):
        return "deny", "fact_unavailable"
    if inp.get("clock_offset", 0) > inp.get("clock_tolerance", 0):
        return "deny", "clock_unsynchronized"
    return "allow", ""
