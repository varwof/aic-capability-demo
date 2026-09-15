#!/usr/bin/env python3
"""CLC differential fuzz: Python runner.

Reads the generator's JSONL and, for every case, evaluates BOTH paths with the
*Python* implementation:
  - raw_path:     §6.2 raw-text normalization via validate_raw_params, then
                  JSON-decode and authorize_set.
  - decoded_path: skip raw-text validation; JSON-decode the same text and
                  authorize_set directly (simulates a caller that already
                  parsed; this is where malformed Unicode / dup keys / number
                  shapes can diverge from the raw path).
  - canonical_sha256: sha256 of the JCS bytes of the decoded params value
                  ("value layer"); empty "" when no value is producible.

Emits result JSONL:
  {"id":..., "impl":"py",
   "raw_path":{"verdict":...,"reason":...},
   "decoded_path":{"verdict":...,"reason":...},
   "canonical_sha256":"..."}
On an uncaught exception it emits {"id":..., "impl":"py", "error":"..."} and
continues (the compare stage reports those under "unstable").
"""

import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clc_semantics import (  # noqa: E402
    CLCError,
    authorize_set,
    canonical_json,
    canonical_reason,
    validate_raw_params,
)


def decode_raw(raw: str):
    """Strict, non-repairing decode of the raw params text using std json."""
    return json.loads(raw)


def raw_validation_code(raw: str) -> str:
    try:
        validate_raw_params(raw)
        return ""
    except CLCError as e:
        return canonical_reason(str(e))


def eval_case(case):
    cid = case["id"]
    raw = case.get("raw")
    no_params = case.get("no_params", False)
    raw_b64 = case.get("raw_b64")
    if raw_b64 is not None:
        raw = base64.b64decode(raw_b64).decode("utf-8", errors="surrogateescape")
    op_id = case["op_id"]
    grant = case.get("grant")

    out = {"id": cid, "impl": "py"}

    # ---- raw text path --------------------------------------------------------
    if no_params:
        op = {"id": op_id}
        out["raw_path"] = _authorize(grant, op)
    else:
        code = raw_validation_code(raw)
        if code:
            out["raw_path"] = {"verdict": "deny", "reason": code}
        else:
            try:
                params = decode_raw(raw)
            except Exception:
                params = None
            if params is None:
                out["raw_path"] = {"verdict": "deny", "reason": "invalid_params_number"}
            else:
                out["raw_path"] = _authorize(grant, {"id": op_id, "params": params})

    # ---- decoded object path --------------------------------------------------
    decoded_params = None
    try:
        decoded_params = None if no_params else decode_raw(raw)
    except Exception:
        decoded_params = "##decode-failed##"
    if no_params:
        out["decoded_path"] = _authorize(grant, {"id": op_id})
    elif decoded_params == "##decode-failed##":
        out["decoded_path"] = {"verdict": "deny", "reason": "invalid_params_number"}
    else:
        out["decoded_path"] = _authorize(grant, {"id": op_id, "params": decoded_params})

    # ---- value-layer canonical digest ------------------------------------------
    try:
        if no_params:
            cj = canonical_json(None)
            out["canonical_sha256"] = hashlib.sha256(cj.encode("utf-8")).hexdigest()
        elif isinstance(decoded_params, dict):
            cj = canonical_json(decoded_params)
            out["canonical_sha256"] = hashlib.sha256(cj.encode("utf-8")).hexdigest()
        else:
            out["canonical_sha256"] = ""
    except Exception:
        out["canonical_sha256"] = ""
    return out


def _authorize(grant, op):
    try:
        res = authorize_set([grant], op)
        return {
            "verdict": res["verdict"],
            "reason": canonical_reason(res.get("reason", "")),
        }
    except CLCError as e:
        return {"verdict": "deny", "reason": canonical_reason(str(e))}
    # Any other exception is a semantics crash (e.g. AttributeError on
    # non-object params) — propagate to the per-case handler so it is recorded
    # as an "unstable" incident rather than papered over.


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: run_py.py <cases.jsonl>\n")
        return 2
    src = sys.argv[1]
    with open(src, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                case = json.loads(line)
                res = eval_case(case)
            except Exception as e:
                try:
                    cid = json.loads(line).get("id", "?")
                except Exception:
                    cid = "?"
                res = {"id": cid, "impl": "py", "error": "%s: %s" % (
                    type(e).__name__, e)}
            sys.stdout.write(json.dumps(res, ensure_ascii=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())