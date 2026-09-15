# CLC differential fuzz - divergence report

Seed `20260915`. Case generator `fuzz/gen_cases.py`, harness `fuzz/README.md`.

Two runs over the same 100,000-case file are reported:

| label  | aic-capability-demo | register  |
|--------|---------------------|-----------|
| before | `75bc79e` (CLC-1.7) | unchanged |
| after  | `2d3aa9a`           | unchanged |

The only difference between the two runs is commit `2d3aa9a` ("refuse
non-object params on the decoded path"). Case file, runners and the Go
implementation are byte-identical across the two runs, so the result sets are
directly comparable.

`fuzz-findings.json` is the raw comparison dump; it is generated and not
tracked (~9 MB). `fuzz/findings-summary.json` holds the summary block of the
after run.

## Corpus

- 100,000 axis-directed cases, 10,000 per axis a01-a10, fixed seed `20260915`.
- 2,000 boundary cases: 1,983 on a08, 7 on a03, 6 on a04, 4 on a02.

Case format and runner extensions are documented in `fuzz/README.md`.

## Implementations under test

| impl | file | entry |
|------|------|-------|
| Go | `register/semantics/semantics.go` | `Authorize`, `AuthorizeSet`, `ValidateRawParams` |
| Python | `aic-capability-demo/clc_semantics.py` | `authorize_set`, `validate_raw_params` |
| TypeScript | `aic-capability-demo/ts/clc_semantics.ts` | `authorizeSet`, `validateRawParams` |

Canonical JSON helpers: Go `CanonicalJSON`, Python `canonical_json`, TS
`canonicalJSON`.

## How the three classes are defined

- **cross_impl** - identical input, identical path, different verdict or reason
  across implementations. These are the findings that matter.
- **cross_path** - within one implementation, the raw-text boundary and the
  already-decoded boundary disagree. CLC 6.2 defines both boundaries on
  purpose: the raw boundary rejects what a JSON decoder would silently repair
  or collapse (duplicate keys, `1e400`, malformed escapes), and the decoded
  boundary can no longer see those features. A raw/decoded split is designed
  behavior, not a defect. The class is kept here for measurement only, and is
  never counted as a divergence.
- **unstable** - an implementation crashed or produced no decision where the
  others decided.

One caution about this harness: a case can be unrepresentable in one target
language. Where that happens the comparison is not meaningful and the case is
reported as such rather than as a divergence (see F2).

## Determinism

All three runners are byte-identical across two runs of the same case file
(`diff` exit 0 for py, ts and go, before and after the fix). The generator is
deterministic for a fixed seed. Determinism is total and verified.

## Summary

### Before the fix (`75bc79e`)

| class | unique cases | impl-rows | axes |
|-------|--------------|-----------|------|
| cross_impl (decoded path) | 2,499 | | a03 1,791, a08 708 |
| cross_path (designed) | 13,069 | 34,917 | a02 10,000, a03 1,791, a04 570, a08 708 |
| unstable (Python crash) | 1,350 | | a03 347, a08 1,003 |
| canonical_sha256 mismatch | 0 | | |

### After the fix (`2d3aa9a`)

| class | unique cases | impl-rows | axes |
|-------|--------------|-----------|------|
| cross_impl (decoded path) | 2,047 | | a03 |
| cross_impl (raw path) | 256 | | a03 |
| cross_impl (value digest) | 164 | | a03 |
| cross_path (designed) | 12,617 | 33,849 | a02 10,000, a03 2,047, a04 570 |
| unstable | 0 | | - |
| canonical_sha256 mismatch | 0 | | |

Delta: axis a08 disappears from every class. The 708 reason-code splits
(`invalid_params_number` vs `invalid_params_size`) and the 1,003 Python crashes
are gone, and Python instability reaches zero. What remains is axis a03, for
two different reasons - F1 and F2 below.

---

## F1 (open) - Go repairs lone surrogates on the decoded path

**Class:** cross_impl, decoded path
**Axis:** a03, lone UTF-16 surrogate escapes in the raw JSON text
**Count:** 2,047 cases after the fix (1,791 `raw`, 256 `raw_b64`)
**Example ids:** `f020006` (`{"s":"\ud83d"}`), `f020009` (`{"s":"\udc00"}`)

### Signature

```json
["decoded_path",
 {"go": ["allow", ""],
  "py": ["deny", "invalid_params_number"],
  "ts": ["deny", "invalid_params_number"]}]
```

### Root cause

On the decoded path the caller has already parsed the JSON, so the 6.2 raw
validation has not run. Go's `encoding/json` repairs a lone UTF-16 surrogate to
U+FFFD while decoding. The resulting params are well-formed, so `Authorize`
sees nothing wrong and allows. Python and TypeScript keep the lone surrogate in
the decoded string and `validate_params` / `validateParams` denies it with
`invalid_params_number`.

The raw path is consistent across all three implementations: the raw validator
scans the escapes before any decoding and returns `invalid_params_number`. Only
the decoded path diverges.

### The value layer confirms the repair is lossy

Two hand-built cases, one with a lone surrogate and one with a legitimate
U+FFFD:

```
$ printf '%s\n' '{"id":"t_sur",...,"raw":"{\"s\":\"\ud800\"}"}' \
                '{"id":"t_rep",...,"raw":"{\"s\":\"\ufffd\"}"}' > /tmp/eq.jsonl
$ go run ./semantics/fuzz_runner /tmp/eq.jsonl
{"id":"t_sur",...,"decoded_path":{"verdict":"allow","reason":""},
 "canonical_sha256":"7513ecfd87d7bd3c..."}
{"id":"t_rep",...,"decoded_path":{"verdict":"allow","reason":""},
 "canonical_sha256":"7513ecfd87d7bd3c..."}
```

Same decoded value, same canonical digest. On the raw path Go denies `t_sur`
and allows `t_rep`, which is correct; only the decoded path is unsafe.

### No post-decode remedy

Because the repair is lossy, a scan of the decoded value cannot separate the two
inputs: `\ud800` and a genuine U+FFFD are identical after decoding. The only
sound place to catch this is the raw text, which is what the 6.2 boundary is
for. An earlier draft of this report proposed adding a post-decode scan in Go;
that proposal was wrong, because there is nothing left to scan, and it has been
withdrawn.

What is actionable here is a consumer rule, not a Go change: an implementation
that must reject lone surrogates has to run the 6.2 raw check on the original
octets. After a lossy decoder has touched the input the information is gone in
all three languages.

### Location

- Go: `encoding/json` (standard library); the repair is not configurable.
- Python: `clc_semantics.py` `_reject_unpaired_surrogates` (deny).
- TS: `clc_semantics.ts` `rejectUnpairedSurrogates` via `validateParams` (deny).

---

## F2 (open, API shape) - TypeScript cannot see invalid UTF-8 octets on the raw path

**Class:** cross_impl, raw path
**Axis:** a03, literal invalid UTF-8 octets supplied as `raw_b64`
**Count:** 256 raw-path cases, the same 256 on the decoded path, and 164 value
digests
**Example id:** `f020028`

### Signature

```json
["raw_path",
 {"go": ["deny", "invalid_params_number"],
  "py": ["deny", "invalid_params_number"],
  "ts": ["allow", ""]}]
```

and, for the same 256 cases, on the decoded path:

```json
["decoded_path",
 {"go": ["allow", ""],
  "py": ["deny", "invalid_params_number"],
  "ts": ["allow", ""]}]
```

### Root cause

A JavaScript string is a sequence of UTF-16 code units and cannot carry an
invalid UTF-8 octet. The harness decodes `raw_b64` with
`Buffer.from(rawB64,"base64").toString("ascii")`, which substitutes `?` for
every high byte, so `validateRawParams` receives a well-formed string and
allows. Go keeps the bytes exactly (`string(b)`) and Python keeps them through
`errors="surrogateescape"`; both reject.

The TypeScript verdict is a statement about the API shape, not about the
decision logic: the raw validator has nothing malformed to look at by the time
it is called. 6.2 raw validation is defined over octets, so an implementation
in a language whose strings cannot hold them needs a byte-oriented entry point
(a `Uint8Array`/`Buffer` overload) if it wants to run that check. With the
current string-only signature, these 256 cases are not a faithful comparison
for TypeScript and should be read as not testable rather than as allowed.

The 164 value-digest mismatches are the same cases: TypeScript digests the
`?`-substituted text, Go digests the U+FFFD-repaired text, and Python produces
no digest. Same cause, not a separate finding.

### What would settle it

Either a byte entry point in the TypeScript binding, or an explicit statement in
the harness that `raw_b64` cases are out of scope for a string-based API. Both
are legitimate; leaving them as a silent cross-implementation difference is
not.

---

## F3 (fixed in `2d3aa9a`) - non-object params on the decoded path

**Class:** cross_impl and unstable, decoded path
**Axis:** a08

### What the fuzz found

A top-level JSON array or scalar reaching the decision function produced three
different outcomes:

| impl | before | after |
|------|--------|-------|
| Go | `deny` / `invalid_params_number` (decode boundary) | `deny` / `invalid_params_number` |
| Python | `AttributeError: 'list' object has no attribute 'items'` (1,003 cases) | `deny` / `invalid_params_number` |
| TypeScript | `allow` (fail-open) | `deny` / `invalid_params_number` |

The TypeScript entry is the one that matters. At array depths 28-32 the value
passed the depth check and `Object.entries` on an array does not throw, so
`authorizeSet` returned an ordinary allow for input that 6.2 says must be
denied. It was masked in the before run: `compare.py` classifies a case with a
crashing implementation as unstable and does not then compare the others, so
Python's `AttributeError` hid TypeScript's allow. It is not visible anywhere in
the before table above.

Above depth 32 the same input produced a reason-code split - Go
`invalid_params_number` at its decode boundary versus Python and TypeScript
`invalid_params_size` from the nesting cap (708 cases).

### Fix

Both validators now check "is this an object" before the depth and size caps, so
all three report `invalid_params_number`, matching 6.2's rule that JSON which
cannot be parsed as an object takes the same code as unparsable JSON.

- Python `clc_semantics.py` `validate_params`: `isinstance(params, dict)` guard
  ahead of `_reject_non_finite`, `_reject_unpaired_surrogates`, the size cap and
  the depth cap.
- TypeScript `ts/clc_semantics.ts` `validateParams`: `isPlainObject(params)`
  guard in the same position.

### Verification

- 100,000-case rerun: a08 in no class; Python instability 0.
- 2,000-case boundary corpus (1,983 of them a08): a08 contributes nothing.
- 107/107 authorization vectors, 1,184 property cases, edge tests and JCS
  checks pass in both languages.

---

## F4 (fixed in `2d3aa9a`) - Python raw validator crashed on literal invalid UTF-8

**Class:** unstable, raw path
**Axis:** a03, literal invalid UTF-8 octets (`raw_b64`)
**Before:** 347 crashes

```
UnicodeEncodeError: 'utf-8' codec can't encode character '\udcff' in position 0
```

The harness decodes `raw_b64` with `errors="surrogateescape"`, so a literal
invalid octet becomes a lone surrogate in the Python string. `_utf8_len` then
called `s.encode("utf-8")` and raised. The raw validator should have produced a
clean denial; instead it escaped as an exception.

Fixed: `_utf8_len` converts `UnicodeEncodeError` into the same stable
`invalid_params_number` denial that the escape-level check produces. Go was
already correct here (`scanRawBytes` catches the byte range); TypeScript never
sees the bytes (F2).

---

## F5 (designed, 6.2) - number shapes on the raw path versus the decoded path

**Class:** cross_path, all three implementations, 570 unique cases

The raw path rejects number literals the raw validator flags (`1e400`
overflows the IEEE-754 range, and similar). The decoded path decodes them
first: Python and TypeScript produce `inf`, which `validate_params` rejects as
`invalid_params_number`; Go's decoder rejects `1e400` at the boundary. All
three implementations agree with each other; the split is between the two paths
inside each implementation. This is the 6.2 boundary working as specified. No
code fix.

## F6 (designed, 6.2) - duplicate keys on the raw path versus the decoded path

**Class:** cross_path, all three implementations, 10,000 unique cases (one per
a02 case)

The raw path scans for duplicate keys and denies with
`invalid_params_duplicate_key`. The decoded path has already collapsed them to
the last value. All three implementations behave identically. Designed. No code
fix.

---

## Axes with no divergence

a01 (key order), a05 (missing / null / empty), a06 (types), a07 (arrays), a09
(constraint identity), a10 (id shapes): 10,000 cases each, zero cross_impl and
zero unstable.

a02, a04 and a08 show cross_path only, and a02 and a04 are designed (above).
a08 is now free of every class after F3.

a03 (malformed Unicode) is the only axis with a real cross_impl finding, and it
has two causes, F1 and F2, both about what a decoder has already done to the
input by the time the decision function is reached.

## Canonical SHA-256 (value layer)

Zero cross_impl digest mismatches outside the F2 raw-byte cases. For every
successfully decoded object value the three implementations produce identical
JCS canonical bytes. This covers the CLC-1.7 key-order fix and numeric
representation.

## Reproduce

```bash
cd aic-capability-demo
python3 fuzz/gen_cases.py --n 100000 --seed 20260915 > /tmp/cases.jsonl
python3 fuzz/run_py.py /tmp/cases.jsonl > /tmp/res_py.jsonl
npx --yes tsx fuzz/run_ts.ts /tmp/cases.jsonl > /tmp/res_ts.jsonl
(cd ../register && go run ./semantics/fuzz_runner /tmp/cases.jsonl > /tmp/res_go.jsonl)
python3 fuzz/compare.py /tmp/cases.jsonl /tmp/res_py.jsonl /tmp/res_ts.jsonl /tmp/res_go.jsonl \
  > fuzz-findings.json
```

Rerun step 2 and `diff` the result files to confirm determinism.

## Scope

- Done: 100,000-case and 2,000-case boundary runs, before and after `2d3aa9a`;
  per-case findings in `fuzz-findings.json`, summary in
  `fuzz/findings-summary.json`.
- Repeatable: fixed seed, deterministic generator, byte-identical reruns.
- Open: F1 (no decoded-path remedy; a consumer rule is required) and F2 (an API
  decision for the TypeScript binding). Neither is folded into the designed
  class.
- The corpus and result dumps are generated artifacts and are not committed.
  Only the harness, this report and the summary are.
