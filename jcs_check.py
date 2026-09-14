#!/usr/bin/env python3
"""RFC 8785 (JCS) cross-implementation check for the CLC-1.6 canonicalization
(rev CLC-1.6).

Pins the review's reproducer: Go's `json.Marshal` HTML-escaped `&` to `\\u0026`,
so the material-projection digest and `clc-action:` identifier were not RFC 8785
and disagreed with an independent implementation.  This script asserts the JCS
bytes, the SHA-256 digest, the `clc-action:` identifier, and the UTF-16 key
ordering that distinguishes JCS from a UTF-8 byte sort.

Run: python3 jcs_check.py
"""
import base64
import hashlib
import sys

from clc_semantics import canonical_json, compute_action_id

EXPECT_BYTES = '{"value":"&"}'
EXPECT_SHA256 = '9a2fe282f2733070b5a91a182e97d8efdf6e94135e4790a73a380257200a2903'
EXPECT_B64URL = 'mi_igvJzMHC1qRoYLpfY799ulBNeR5CnOjgCVyAKKQM'
EXPECT_ID = 'clc-action:1:probe.action.1:jcs-sha256:' + EXPECT_B64URL

# UTF-16 order: "a" (0x61) < U+1F4A9 (surrogate 0xD83D) < U+E000.  A UTF-8 byte
# sort would put U+E000 (EE 80 80) before U+1F4A9 (F0 9F 92 A9).
EXPECT_KEY_ORDER = '{"a":"ascii","\U0001F4A9":"astral","\uE000":"bmp"}'

FAILS = []


def check(label, got, want):
    if got != want:
        FAILS.append(f"{label}: got {got!r}, want {want!r}")


bytes_out = canonical_json({"value": "&"})
check("JCS bytes", bytes_out, EXPECT_BYTES)
check("sha256", hashlib.sha256(bytes_out.encode("utf-8")).hexdigest(), EXPECT_SHA256)
check("b64url", base64.urlsafe_b64encode(
    hashlib.sha256(bytes_out.encode("utf-8")).digest()).rstrip(b"=").decode("ascii"),
    EXPECT_B64URL)
check("action id", compute_action_id("probe.action.1", ["value"], "jcs-sha256", {"value": "&"}), EXPECT_ID)
check("utf-16 key order", canonical_json({
    "\uE000": "bmp", "\U0001F4A9": "astral", "a": "ascii"}), EXPECT_KEY_ORDER)

# Invalid Unicode is refused, not repaired or escaped: a lone surrogate has no
# UTF-8 form and therefore no JCS encoding (RFC 8785 3.2.2.2).
check("surrogate pair accepted", canonical_json("\U0001F602"), '"\U0001F602"')
for label, bad in [("lone high surrogate", "\ud800"), ("lone low surrogate", "\udc00")]:
    try:
        canonical_json(bad)
        check(label + " refused", "not refused", "refused")
    except Exception:
        pass

if FAILS:
    print("\n".join(FAILS))
    sys.exit(1)
print("jcs_check: 9 checks passed (RFC 8785 bytes/digest/action-id/key-order/invalid-unicode)")
