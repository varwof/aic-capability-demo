# CLC differential fuzz - divergence report

Seed `20260915`. Case generator `fuzz/gen_cases.py`, harness `fuzz/README.md`.

Two runs over the same 100,000-case file are reported:

| label | aic-capability-demo | register | corpus |
|-------|---------------------|----------|--------|
| before | `75bc79e` (CLC-1.7) | unchanged | 107 vectors |
| after | `2d3aa9a` | unchanged | 107 vectors |
| current | raw-boundary fix (CLC-1.8) | raw-boundary fix (CLC-1.8) | 113 vectors |

The first two runs differ only by commit `2d3aa9a` ("refuse non-object params on
the decoded path"). Case file, runners and the Go implementation are
byte-identical across them, so those two result sets are directly comparable.

The third run adds the raw-boundary fix described in F7: the raw validators
measure the JCS form of a number instead of the received spelling, TypeScript
counts a literal astral character by scalar value, and all three refuse a
literal control character. Its numbers appear under "After the raw-boundary
fix" below.

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

### After the decoded-path fix (`2d3aa9a`)

| class | unique cases | impl-rows | axes |
|-------|--------------|-----------|------|
| cross_impl (decoded path) | 2,047 | | a03: 1,791 lone surrogates (F1), 256 `raw_b64` (F2) |
| cross_impl (raw path) | 256 | | a03 `raw_b64` (F2) and the 92 literal-astral cases F7 fixes |
| cross_impl (value digest) | 164 | | a03 `raw_b64` (F2) |
| cross_path (designed) | 12,617 | 33,849 | a02 10,000, a03 2,047, a04 570 |
| unstable | 0 | | - |
| canonical_sha256 mismatch | 0 | | |

### After the raw-boundary fix (current)

| class | unique cases | impl-rows | axes |
|-------|--------------|-----------|------|
| cross_impl (decoded path) | 2,047 | | a03: 1,791 lone surrogates (F1), 256 `raw_b64` (F2) |
| cross_impl (raw path) | 164 | | a03 `raw_b64` only (F2) |
| cross_impl (value digest) | 164 | | a03 `raw_b64` (F2) |
| cross_path (designed) | 12,617 | 33,757 | a02 10,000, a03 2,047, a04 570 |
| unstable | 0 | | - |
| canonical_sha256 mismatch | 0 | | |

The 92 literal-astral cases are gone from both the raw path and the cross-path
count. After this run the only axis with a cross_impl case is a03, and every
remaining one is either F1 or the F2 harness set — there is no raw-path finding
left for text the harness can represent faithfully.

Delta: axis a08 disappears from every class. The 708 reason-code splits
(`invalid_params_number` vs `invalid_params_size`) and the 1,003 Python crashes
are gone, and Python instability reaches zero. What remains is axis a03, and it
is two different things. The 1,791 `raw` cases are a real implementation
difference (F1). The 256 `raw_b64` cases are not a difference between the
decision functions at all: each runner has to hand the same octets to a string
API and can only do so lossily, so the three are not being fed the same thing
(F2). Only the first should be read as a CLC finding.

---

## F1 (open) - Go repairs lone surrogates on the decoded path

**Class:** cross_impl, decoded path
**Axis:** a03, lone UTF-16 surrogate escapes in the raw JSON text
**Count:** 1,791 cases (axes `raw` only). The other 256 decoded-path cases are
`raw_b64` and belong to F2; they are a harness representability artifact, not a
Go decision difference.
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
digests. This whole axis is not an apples-to-apples comparison and is not a CLC
finding; it is kept in the report so the counts above are not misread.
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

The three runners share one case file, but a case whose input is a sequence of
bytes cannot be represented the same way in three string-typed APIs:

| impl | raw_b64 becomes | effect |
|------|-----------------|--------|
| Go | `string(b)` - the octets, unchanged | raw validator sees the bad octet |
| Python | `bytes.decode("utf-8", errors="surrogateescape")` | raw validator sees a lone surrogate |
| TypeScript | `Buffer.toString("ascii")` - `?` for every high byte | raw validator sees a well-formed string |

Only Go is holding the actual octets. Python's is a harness convention a real
caller could plausibly adopt; TypeScript's is lossy by construction, because a
JS string is a sequence of UTF-16 code units and cannot carry an invalid UTF-8
octet at all.

So the `raw_b64` sub-axis measures how each language can be made to accept
bytes, not what each decision function decides. The `deny`/`deny`/`allow` split
is a consequence of that, and the matching decoded-path split
(`allow`/`deny`/`allow`) is the same thing one layer later: Go regenerates
U+FFFD, TypeScript keeps the `?`, Python keeps the surrogate and refuses it.
Neither split is evidence that the implementations disagree about CLC.

The TypeScript `allow` is therefore not a fail-open in the decision path. It
is the raw validator having nothing malformed to look at by the time it is
called. 6.2 raw validation is defined over octets, so a binding whose strings
cannot hold them needs a byte-oriented entry point (a `Uint8Array`/`Buffer`
overload) to run that check at all.

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

---

## F7 (fixed in CLC-1.8) - the raw validators measured the received number spelling

**Class:** boundary inconsistency, found by review rather than by this harness
**Axis:** a04 (number shapes) crossed with a08 (size cap) - which the corpus
never generated

### What was wrong

§6.2 step 4 measures the size of the JCS form, but all three raw validators
counted a number by the length of the token as received. JCS rewrites numbers,
so the two counts disagree whenever a token is not already canonical - exactly
at the size cap that means the raw and decoded boundaries can reach opposite
verdicts on the same input:

| raw params | received | JCS | raw path (before) | decoded path |
|---|---|---|---|---|
| `{"n":1e-6,"s":"<494 a>"}` | 511 | 515 | allow | deny `invalid_params_size` |
| `{"n":1.0,"s":"<498 a>"}` | 514 | 512 | deny `invalid_params_size` | allow |
| `{"s":"<100×U+1F600>"}` | 408 | 408 | TypeScript deny, Go/Python allow | allow |

The third row is the same defect in the string path: TypeScript's raw scanner
walked a JS string by UTF-16 code unit, so a literal astral character counted six
octets instead of four, and a literal control character passed a check that Go
and Python already refused.

This is an input-boundary inconsistency, not a released authorization bypass: a
caller that also runs the decoded check still refuses the oversized input. It
matters because §6.2 names one size and both boundaries are specified to agree
on it.

### Why this harness missed it

The axes are independent. a04 varies number shapes at a fixed small size, so it
never approaches the 512-octet cap; a08 pads a string to the cap but always with
a canonical number token (`1`). The class only exists at the intersection of the
two, and no axis generates that intersection - which is the general lesson: the
cross product of two boundary dimensions is a corpus in its own right.

It was found by review (Iman Schrock, 2026-09-15), not by the 100,000 cases.

### Fix

- Go `semantics.go` (`walkParamsValue`, `json.Number`): after the precision
  check on the received token, write `CanonicalJSON(n)` for a finite value so
  the size pass counts JCS octets; a non-finite token keeps the received
  spelling so malformed numbers still report the size code before the number
  code.
- Python `clc_semantics.py` (`_scan_raw_params`): match the number token and add
  `len(_canonical_number(value))` when the value is finite.
- TypeScript `ts/clc_semantics.ts` (`scanRawParams`): the same canonical length
  for a finite number, plus the literal-string loop now advances by code point,
  refuses a control character or lone surrogate, and counts the scalar's UTF-8
  octets.

### Pinned by the shared corpus

`params-033`-`params-038` in `capability/data/_vectors/clc-v1/vectors.json`, one
pair per direction plus the literal/escaped astral pair. All three
implementations declare `CLC-1.8` and pass 113 authorization, 32 evidence and 13
crosswalk vectors, 1,184 property cases, the edge checks and the JCS checks.

## Axes with no divergence

a01 (key order), a05 (missing / null / empty), a06 (types), a07 (arrays), a09
(constraint identity), a10 (id shapes): 10,000 cases each, zero cross_impl and
zero unstable.

a02, a04 and a08 show cross_path only, and a02 and a04 are designed (above).
a08 is now free of every class after F3.

a03 (malformed Unicode) is the only axis carrying a real cross_impl finding:
F1, the Go decoded-path repair. The `raw_b64` cases on the same axis (F2) are a
harness representability artifact and carry no finding. a04 carries a cross_path
split only, and F7 shows why an axis-by-axis corpus is not enough to see the
whole boundary: the raw size defect lived where a04 and a08 meet.

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
- Open: F1 (no decoded-path remedy; a consumer rule is required). F2 is a
  harness and API question rather than a CLC finding - the TypeScript binding
  would need a byte-oriented raw entry point before `raw_b64` can be tested
  against it at all. Neither is folded into the designed class.
- Not covered: the axes are varied one at a time, so no axis generates the
  intersection of two boundary dimensions (F7) and the corpus holds no
  multi-grant, delegation, evidence or crosswalk case. "All three implementations
  agree" in this report means the parameter boundary only.
- The corpus and result dumps are generated artifacts and are not committed.
  Only the harness, this report and the summary are.
