# CLC differential fuzz harness

Directed, deterministic differential testing of the CLC decision function across
the three reference implementations (Go / Python / TypeScript), on both input
boundaries:
- **raw text path** (`raw_path`): the §6.2 raw-text normalization boundary.
  Raw params JSON text goes through `ValidateRawParams` /
  `validate_raw_params` / `validateRawParams`; a rejection becomes an immediate
  `deny` with the canonical code.  Otherwise the validated text is decoded and
  evaluated.
- **decoded object path** (`decoded_path`): a caller that already parsed the
  JSON.  The same text is decoded with each platform's own JSON decoder
  (collapsing duplicate keys, silently repairing lone surrogates in Go,
  `1e400 → +Inf` in Python/JS) and evaluated **without** the §6.2 raw
  validation.  This is the boundary where malformed Unicode, duplicate keys and
  number-shape handling diverged in review.

`canonical_sha256` is the sha-256 of the RFC 8785 (JCS) canonical bytes of the
decoded params **value layer**, so cross-implementation value fidelity (key
order, number repr, Unicode normalization) is checked byte-for-byte.  It is
`""` when no object-typed value is producible (params must be an object).

## Files

| file          | role                                                        |
|---------------|-------------------------------------------------------------|
| `gen_cases.py`| deterministic, axis-directed case generator (15 axes a01-a15) |
| `run_py.py`   | Python runner → result JSONL                                 |
| `run_ts.ts`   | TypeScript runner (tsx / node strip-types) → result JSONL    |
| Go runner     | `register/semantics/fuzz_runner/main.go`                     |
| `compare.py`  | cross-impl + cross-path + unstable classification            |
| `shrink.py`   | ddmin minimizer for a recorded finding                       |

The Go runner lives in the register repo at `semantics/fuzz_runner/main.go`;
it is invoked as a package and written against the `semantics` package API.  It
does not modify any implementation file.

## Usage

```bash
# 1. generate
python3 fuzz/gen_cases.py --n 100000 --seed 20260915 > /tmp/cases.jsonl
python3 fuzz/gen_cases.py --n 2000 --seed 20260915 --boundary > /tmp/cases_bnd.jsonl

# 2. run the three implementations
python3 fuzz/run_py.py /tmp/cases.jsonl > /tmp/res_py.jsonl
npx --yes tsx fuzz/run_ts.ts /tmp/cases.jsonl > /tmp/res_ts.jsonl
go run ./semantics/fuzz_runner /tmp/cases.jsonl > /tmp/res_go.jsonl

# 3. compare
python3 fuzz/compare.py /tmp/cases.jsonl /tmp/res_py.jsonl /tmp/res_ts.jsonl /tmp/res_go.jsonl \
  > fuzz-findings.json

# 4. determinism: rerun step 2 and diff the result bytes
diff <(cat /tmp/res_py.jsonl) <(cat /tmp/res_py2.jsonl) ...

# 5. shrink a finding
python3 fuzz/shrink.py /tmp/cases.jsonl /tmp/res_py.jsonl /tmp/res_ts.jsonl /tmp/res_go.jsonl f000012
```

## Case format

JSONL, one case per line:

```json
{ "id": "f000123", "axis": "a08",
  "raw": "{\"n\":1e-6,\"s\":\"...\"}",
  "op_id": "std/database-v1:query:SELECT",
  "grant": {"id": "std/database-v1:query:SELECT"},
  "note": "near 512 bytes" }
```

`raw` is the raw JSON text of an operation's params object.  `grant` may be
`null` / `{}` (absent grant).  Optional extensions (documented adjustments to
the prompt skeleton):

- `grants` — for multi-grant (a11) cases, the full grant array in input order.
  When present, runners call the multi-grant entry point
  (`authorize_set`/`authorizeSet`/`AuthorizeSet`) with the whole array; the
  single `grant` field is kept as a mirror of the first element for compat.
- `op_id` — the operation capability id (the decision function needs one);
  drawn from a fixed legend of well-formed ids.
- `no_params: true` — the operation carries **no** params field at all; `raw`
  is ignored consistently by both paths.
- `raw_b64` — when present, this is the base64 of the raw *bytes* supplied to
  the implementation, replacing `raw`.  Used for literal-invalid-UTF-8 raw text
  (e.g. `{"s":"\xff"}`), which a UTF-8 JSONL document cannot carry.  Python
  decodes these via `surrogateescape`; Go passes the bytes as a Go string;
  TypeScript now mirrors Python's surrogateescape (`U+DC00+byte` per invalid
  octet) so all three runners feed the raw validator the same octets.

  With that runner parity the `raw_b64` sub-axis is a genuine (and currently
  convergent) comparison, not the representability artifact the note below
  described.  It was a harness bug while TypeScript used `toString('ascii')`,
  which mapped every high byte to `?` and hid the invalid octet from the TS
  validator.

## Result format

```json
{ "id": "f000123", "impl": "go",
  "raw_path": {"verdict": "deny", "reason": "invalid_params_number"},
  "decoded_path": {"verdict": "deny", "reason": "invalid_params_number"},
  "canonical_sha256": "9a2fe282..." }
```

An `allow_unresolved` verdict carries the residual obligation set, which the
compare stage checks byte-for-byte across implementations:

```json
{ "id": "f053332", "impl": "ts",
  "raw_path":   {"verdict": "allow_unresolved", "reason": "",
                 "unresolved": ["varwof/constraint-v1:network:cidr:[\"192.0.2.0/24\"]"]},
  "decoded_path": {"verdict": "allow_unresolved", "reason": "",
                 "unresolved": ["varwof/constraint-v1:network:cidr:[\"192.0.2.0/24\"]"]},
  "canonical_sha256": "..." }
```

Reasons are compared as their canonical prefix (everything before the first
`:`).  A runner that hits an uncaught exception (a semantics crash, e.g.
Python raising `AttributeError` for a non-object params value, or
`UnicodeEncodeError` inside the raw validator for invalid UTF-8 bytes) emits
`{"id":..., "impl":"py", "error": "..."}` instead; the compare stage files that
case under **unstable**, not as a clean denial.

## Axes

| axis | name                  | what it stresses                                   |
|------|-----------------------|----------------------------------------------------|
| a01  | key order             | permutation of object keys / value-layer ordering  |
| a02  | duplicate keys        | same key 2–3 times in raw text (raw must reject)   |
| a03  | unicode / escapes     | astral pairs, U+2028/29, control, lone surrogates, literal invalid UTF-8 bytes |
| a04  | numbers               | exponent forms, 1e400, -0, big ints, leading zeros |
| a05  | missing/null/empty    | absent params, null wrapper, `{}`, empty strings   |
| a06  | types                 | scalar↔object↔array mismatches at the top level    |
| a07  | arrays                | nesting, order, element shapes                     |
| a08  | size / depth          | JCS-serialized size 512±4 bytes, nesting depth 32±2|
| a09  | constraint identity   | reserved `varwof/constraint-v1:*` vs unknown       |
| a10  | id shapes             | well-formed ids, wildcards, bad ids in params/keys |
| a11  | multi-grant           | 1–4 grants; union allow, allow_unresolved union, denyReasonFirst order |
| a12  | grant paramsSubset    | grant.params vs op.params: subset, empty, enum, nested, null |
| a13  | malformed / boundary  | bare scalars, `{}`, deep arrays (≤20k), NUL, control chars, raw bytes |
| a14  | JCS round-trip numbers| 2^53, 1e21, -0, subnormals, big decimals → canonical digest |
| a15  | i18n / Unicode edges  | CJK, BMP boundary, astral, combining marks, RTL, BOM, overlong UTF-8 |

The `--boundary` set concentrates ~2000 cases on the a08 size/depth decision
edges (503–521 JCS bytes, depth 30–34), a02 dup-key pairs, a03 malformed
escapes, and a04 number literals that sit exactly on the §6.2 rejection lines.

## Output invariants

- `gen_cases.py` is deterministic for a fixed `--n/--seed` (total byte
  equality, verified by re-running and sha256-diffing).
- Runners are line-stable: rerunning produces byte-identical output for the
  same case file, so determinism is checked by rerunning each impl and
  diffing.
- Compare only flags a case in one class at most per path:
  cross-impl `reason` comparison uses the canonical code prefix.