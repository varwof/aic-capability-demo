# CLC-v1 Parity Report

Date: 2026-09-12 (rev 12: CLC-1.3 closeout — 98 vectors; `allow_unresolved` independent verdict, (scheme,type) constraint identity, same-day time-window grammar, `{}`≡absent params, §9.3 multi-grant aggregation; Go/Python/TS parity)

## Summary

| Metric | Value |
|--------|-------|
| Total vectors | 98 |
| Go (register/semantics) | 98/98 PASS |
| Python (aic-capability-demo/clc_semantics) | 98/98 PASS |
| TypeScript (aic-capability-demo/ts/clc_semantics) | 98/98 PASS |
| Verdict consistency | 100% (3 implementations) |
| Reason-code consistency (cross-implementation) | 100% (3 implementations) |
| Reason-code consistency (impl vs vector expectation) | **100%** |
| Reason assertion in runners | **enforced (canonical code, §9.4)** |
| `expect.unresolved` assertion | **enforced (sorted compare, present on decidable vectors)** |
| `allow_unresolved` verdict assertion | **enforced (rev CLC-1.3, decide-019/020/024, 028..030)** |
| P11 property (intersection, shared 1184 cases) | 1184 cases / 869 order-symmetry checks / 841 closure probes / 0 failures in Go, Python and TS (Go verified with `-count=1`; after the rev CLC-1.3 `{}`≡absent rule the closure probe skips empty-params merged grants — see Addendum 2) |
| Differences | 0 |

## Per-Kind Breakdown

Grouped by `kind` field (as in vectors.json):

| Kind | Count | Go Pass | Python Pass | TS Pass | Match |
|------|-------|---------|-------------|---------|-------|
| syntax | 9 | 9 | 9 | 9 | ✓ |
| entail | 37 | 37 | 37 | 37 | ✓ |
| intersect | 14 | 14 | 14 | 14 | ✓ |
| decide | 38 | 38 | 38 | 38 | ✓ |

TS runner output is **byte-identical** to the Python runner output on all 98
rows and on the property summary line (`diff` clean), so cross-parity is a
plain diff, not a re-sampled reading.

Grouped by appendix semantic category (as in the spec):

| Appendix | Count | Vectors |
|----------|-------|---------|
| B.1 syntax | 9 | syntax-001..009 |
| B.2 entail | 6 | entail-001..006 |
| B.3 params | 27 | params-001..027 |
| B.4 intersect | 10 | intersect-001..010 |
| B.5 decision | 29 | decide-001..009, decide-015..018, revision-001..002, undeclared-001..002, decide-019..030 |
| B.6 combined | 11 | combined-001..011 |
| scheme stress-test | 6 | clinical-001..002, payments-001..002, data-001..002 |

## Reason Code Enumeration

Every deny vector's expected reason matches what both implementations
produce (verified Go==Python and impl==vector):

| Reason Code | Vector(s) | Description |
|-------------|-----------|-------------|
| `unsupported_wildcard` | syntax-003..006 | v1-forbidden wildcard shape |
| `wildcard_requires_trailing_segment` | entail-005 | wildcard with no trailing segment |
| `literal_mismatch` | entail-006 | literal ID mismatch (path level) |
| `different_namespace` | entail-004 | scheme or action Class differs |
| `invalid_capability_id` | syntax-007, syntax-008, decide-004, decide-025, combined-010 | malformed capability ID (§3 scheme grammar, rev CLC-1.2: no vendor `/` product `-vN`) |
| `unknown_constraint` | decide-003, payments-002 | unrecognized constraint identity — by (scheme,type) pair since rev CLC-1.3: only `varwof/constraint-v1` types are core-recognized, so ANY other scheme's constraint (incl. a same-name `foo/db-v1:max_rows`) fails closed; §8 fail-closed |
| `invalid_constraint` | decide-019, decide-021, decide-022 | recognized type × out-of-§8.1 value grammar: scalar `time:window:3600`, prefix-less CIDR, and the cross-midnight SINGLE-segment `22:00→06:00` (rev CLC-1.3) |
| `allow_unresolved` (+ `unresolved`) | decide-020, decide-024 | independent verdict for recognized-but-unevaluated `network`/`time` constraints, carried on `unresolved`, never silently dropped (§8.4, rev CLC-1.3) |
| `params_exceed_grant` (multi) | decide-030 | §9.3 multi-grant: no covering grant allows → first covering grant reason in input order (rev CLC-1.3) |
| `capability_not_authorized` | decide-002, decide-015, decide-016, combined-006 | no covering grant; absent/empty grant (fail-closed, §9.3 pre-check resolves even when the operation is also absent); unknown scheme |
| `missing_capability_id` | decide-017 | operation has no `id` (layer 1) |
| `max_rows:violated` | decide-006, decide-023 | constraint violation; `decide-023` pins the fail-closed empty-eval case (rev CLC-1.2) |
| `params_missing` | decide-007, decide-009, combined-003, undeclared-002 | granted param omitted (or no params at all); layer-7 order — resolves before `undeclared_param` |
| `undeclared_param` | undeclared-001 | operation param key not declared by a bounded grant (key closure, §6.2; §9.3 layer 7 request side) |
| `params_exceed_grant` | params-002, clinical-002, data-002, combined-002 | numeric/bound exceeded |
| `not_in_enum` | params-004,005,010,012,014, clinical-001, payments-001, combined-007 | value not a member of granted array set |
| `empty_bound_denies_class` | params-007, intersect-002, combined-005,011 | explicitly empty `[]`/`{}` bound |
| `invalid_params_null` | params-008, decide-008 | `null` parameter value; implementations MAY report `invalid_params_null: <param>` (matched via canonical prefix, §9.4) |
| `invalid_params_duplicate_key` | params-016 | duplicate JSON key in raw request params (§6.2 step 2, §9.3 layer 2) |
| `invalid_params_number` | params-017 | non-finite / over-precision number literal (`1e400`) (§6.2 step 3) |
| `invalid_params_size` | params-018, params-019 | >512 bytes or nesting >32 (§6.2 step 4) |
| `unsupported_language_revision` | revision-002 | declared revision incompatible with implementation (§12.1; revision-001 asserts compatibility → allow) |
| `no_overlap` | intersect-003,006, combined-008 | intersection result empty; dict intersection with **different key sets** → `no_overlap` (P11 key-set rule, rev CLC-1.2, pinned by the property wall) |
| `absent_source` | intersect-007 | intersection over zero sources: fail-closed (§7 rule 5) |

## rev 11 Changes (2026-09-12) — CLC-1.2 Sweep

Language revision CLC-1.2 (spec `§3`/`§7`/`§8.1`/`§8.4`/`§9`/`§12.1`, all rev-annotated)
implemented and pinned in all three implementations **first in the spec text, then
in code**:

- **§8.4 residual-obligation channel `unresolved`**: `Authorize` now returns an
  allow with an additive `unresolved: string[]` (sorted, deduped) for every
  recognized constraint the core does not evaluate (time/network).  Runners assert
  it when the vector declares `expect.unresolved` (sorted compare).  Consumers
  must resolve residual obligations themselves or deny.
- **§8.1 value grammar → `invalid_constraint`**: recognised = type name × value
  grammar.  Scalar `time:window:3600`, a prefix-less CIDR → `invalid_constraint`.
  `max_rows` must be exactly one strict JSON non-negative integer token; the
  constraint value is `parts[2:]` joined back together (colon-bearing JSON round
  trips).  `max_rows` with the operation carrying **no** value defaults to the
  empty input → fail-closed `max_rows:violated` (previously silently skipped).
- **§3 scheme grammar**: capability ids now MUST match
  `vendor/product-vN` (`^[a-zA-Z0-9-]+/[a-zA-Z0-9-]+-v[0-9]+$`); the spec's own
  `database:query` counter-example and `bad:op` are rejected
  (`invalid_capability_id`).  Grant-side malformed ids still collapse to
  `capability_not_authorized` in `Authorize` (pinned by `decide-026`); op-side
  ids propagate the concrete layer-1 code.
- **§7 dict key-set P11 rule**: two object values intersect only when their key
  sets are identical, else `no_overlap`.  The property wall caught the
  widening (prop-0956); all three implementations fixed the same day.
- **Go implementation alignment**: `knownConstraintTypes` tightened to
  `{max_rows, time, network}` (indexed by `parts[1]`), matching Python/TS; the
  `decide-026` trap (op id grammar evaluated before the grant path) closed by
  pinning the vector with a valid op; `Authorize` now propagates
  `err.Error()` for `invalid_constraint`/`unknown_constraint` and collects
  unresolved in sorted order.
- **Python**: `intersect_value` gained a bool guard so `True` never compares as
  `1` (`no_overlap` on bool-vs-number) — read-only code paths were already exact
  (params-022/023).
- **TypeScript**: removed two now-wrong NOTES (the Go "known set" divergence note
  and the layer-6 ordering note); a duplicate `canonicalStringify` export that
  shadowed the module-level one was deleted and the `validateParams` calls
  re-added to `entails`.
- **Corpus 83 → 95**: `intersect-005` time window → array form; new
  `syntax-007/008/009` and `decide-019..027` (unresolved, invalid_constraint,
  op-absent max_rows, three-segment window, §3 scheme pins).  Schema extended
  with `expect.unresolved`.
- **Property wall 524 → 1184**: generator PARAMS grew to 14 shapes (nested
  `profile`/`filters`, `flags admin true vs 1`, two-key vs single-key dicts) →
  regenerated `property-cases.json`; all three 1184/1184, 0 failures.  Diag
  counters verified equal with `go test -count=1` (869/860 in all three; the
  addendum's cache lesson holds on this corpus too).
- **Known parity**: py/ts runner output diff-clean byte-for-byte; Go matches on
  every asserted field (its summary lines use different dash counts — cosmetic).

## rev 12 Changes (2026-09-12) — CLC-1.3 Closeout

The CLC-1.3 revision (additive) removes the last "pseudo-allow" narrative and
adds multi-grant aggregation:

- **Verbatim removal / `allow_unresolved` verdict**: the informational
  `verbatim` field was dropped from all three implementations; the §8.4
  residual-obligation channel is now the single `verdict:'allow_unresolved'` +
  `unresolved:[...]` surface (rev spec §8.4).  Corpus re-pinned: `decide-019`
  (cross-midnight single window → `invalid_constraint`), `decide-020` and
  `decide-024` (network/time recognized-but-unevaluated →
  `allow_unresolved`).  Schema verdict enum gained `allow_unresolved`.
- **Constraint identity = (scheme,type) pair**: recognized set keyed on
  `scheme:type`; only `varwof/constraint-v1` declares core types.  A same-name
  constraint under any other scheme (`foo/db-v1:max_rows`) is
  `unknown_constraint`.  Go/Python/TS each got a defensive identity gate in
  `CheckConstraint`/`check_constraint` and the same "identity first" order in
  validation.
- **Same-day time-window grammar**: single segments may no longer cross
  midnight (must be split); `end:"00:00"` stays reserved as next-day midnight;
  full-day `00:00→00:00` invalid; segments ascending and non-overlapping
  (touching allowed).  Grammar identical across the three validators
  (verified against the CLC-1.3 vectors).
- **`{}` ≡ absent**: an explicit empty grant params object is unconstrained —
  no key closure, any op params allowed (`decide-028`).  `entails` and
  `paramsSubset`/`params_subset` aligned; property closure probe now skips
  empty-params merged grants (841 probes, was 860).
- **§9.3 multi-grant aggregation**: new `AuthorizeSet(grants, op)` — any
  covering-and-allowing grant authorizes (union); residual obligations union
  across covering-and-allowing grants; when nothing allows, the first covering
  grant's params/constraint reason surfaces in input order.
  `decide-029` (any-allow) and `decide-030` (all-deny, first reason) pin it;
  vector type gained `"multi": true`.
- **Corpus 95 → 98** (syntax 9 / entail 37 / intersect 14 / decide 38);
  Go/Python/TS each 98/98 with reason + unresolved assertions enforced; P11
  property 1184/1184, 0 failures everywhere, counters 869/841 in all three.

## rev 10 Changes (2026-09-11) — TypeScript Third Implementation

New **TypeScript** reference implementation and runners, written from the spec
text (not translated from Go/Python), exercising the language with a third
independent reading and checking the spec for gaps.

- **`ts/clc_semantics.ts`**: full v1 core — grammar (§3), params normalization
  with a hand-rolled JSON scanner preserving duplicate keys / number literals /
  size / depth (§6.2, §9.3 layer 2), matchId (§5.1/§9.3 layers 3–4), value
  subset + key closure (§5.2, §9.3 layers 5–9), entails (§6.3), intersect
  (§7 incl. rules 5–6), constraints (§8), authorize (§9), revision compat
  (§12.1). Zero npm deps; runs on Node ≥22 `--experimental-strip-types`.
- **`ts/vectors-run.ts`** + **`ts/property.ts`**: outputs are byte-identical to
  `vectors-run.py` / `property_test.py`, so parity is verified by plain `diff`.
- **Parity (executed today)**: Go, Python, TS each report **76/76, Reason-fail
  0** — identical verdict + canonical reason on every vector, and each runs the
  same P11 property wall (524 cases, 299 order-symmetry checks, 290 closure
  probes, 0 failures). TS↔Python vector + property outputs `diff`-clean.
- **Spec-driven findings**: four corpus-unexercised inter-implementation
  divergences were surfaced (bool grant params; decide op-id wildcard reason
  normalization; known-constraint-type set; null-vs-absent precedence in
  Entails) plus one spec wording ambiguity around §8.3 constraint type
  segmentation. TS picks the spec reading in each case and agrees with the
  other two on every covered input. Full record in
  `capability/data/_vectors/clc-v1/clc-v1-ambiguities.md §6`.
- **CI**: `ts` job added to `.github/workflows/clc-conformance.yml` (Node 22,
  vectors + property against the cloned `capability` corpus).

## rev 9 Changes (2026-09-11) — Codex Batch: Gap-Fill + Uncovered Paths

Review follow-up (68 → 76). No core-semantic change; vectors pin behavior the
reference implementations already produced, except one conformance fix:

- **Gap-fill (2)**: `params-006` (unconstrained grant, → B.3 P6) and
  `params-013` (enum member + scalar bound allow, → B.3 P13); the appendix
  rows always existed, the vectors did not.
- **Normalization positive boundaries (2)**: `params-020` (serialized exactly
  512 B → allow) and `params-021` (depth exactly 32 → allow) — raw payloads
  carried in `raw_params`; negative sides are params-018/-019.
- **Decision-layer paths (2)**: `decide-016` (empty grant AND empty operation
  → `capability_not_authorized`, §9.3 pre-check resolves before any layer)
  and `decide-017` (id-less operation → `missing_capability_id`, layer 1);
  both were already implemented and agreed but unrepresented in the corpus.
- **Intersection §7 rules 5–6 (4)**: `intersect-007` (zero sources →
  `absent_source`), `intersect-008/-009` (an empty-params source must not
  displace a bound, order-independent), `intersect-010` (identifier
  comparison is params-free; narrower id wins) — **conformance fix**: both
  implementations previously reported `no_overlap` for the intersect-010
  scenario; aligned to the already-stated §7 rule 2, spec text unchanged.
- **Records**: spec Appendix B → B.3 19→21, B.4 6→10, B.5 14→16, Total → 76;
  design-notes §20; vector/capability READMEs.

Both runners 76/76, Reason-fail 0, Go==Python verbatim on every vector.

## rev 8 Changes (2026-09-11) — P2' Key Closure (undeclared_param)

Audit finding P2' (pre-release): a bounded grant silently ignored undeclared
operation parameter keys. Resolved per **Plan A** (negative gate → deny,
fail-closed):

- **Spec**: §6.2 adds the normative "Key closure (Plan A)" paragraph
  (bounded grant governs its declared keys; unconstrained grant accepts any
  keys; `params_missing` resolves before `undeclared_param`). §9.3 layer 7
  covers both directions; §9.4 adds the `undeclared_param` reason row;
  Appendix B.5 D13/D14 pin the rule and the resolution order.
- **Go** (`register/semantics`): `ErrParamsUndeclared`, key-closure loop in
  `paramsSubset` after the missing-key check, added to `isParamsLevelReason`.
- **Python** (`aic-capability-demo`): `ParamsUndeclared`, key-closure loop in
  `params_subset`, added to `_is_params_level_reason` (bare + `: <key>`
  prefix).
- **Vectors (66 → 68)**: `undeclared-001` (extra request key → deny
  `undeclared_param`), `undeclared-002` (missing granted key + undeclared
  request key → `params_missing` wins, pins layer-7 order). Both runners
  68/68, Reason-fail 0, Go==Python verbatim on every vector; no pre-existing
  vector changed its outcome.
- **Consequence**: v1 already had no fail-open gap, but now the gate is
  explicit and covered by conformance vectors on both implementations.

## rev 7 Changes (2026-09-11) — Scheme Stress-Test Batch clinical/payments/data

New schemes and vectors to probe CLC v1 coverage in three additional domains
(no core-semantic change; no reference-implementation change):

- **Schemes**: `std/clinical-v1` (7 caps, 2 HIGH-RISK), `std/payments-v1`
  (6 caps), `std/data-v1` (5 caps) at `capability/data/std/*`. Categorical
  params → arrays; ordered quantities (dose/amount/rows) → scalar upper
  bounds. Scheme-scoped constraint types declared as § extension points:
  `clinical:quorum:2`, `payments:quota:daily:<n>`, `data:purpose:<v>`,
  `data:region:<v>`. Each carries a disclaimer note (authorization boundary,
  not clinical decision / anti-fraud / privacy certification). Human-readable
  `*-capabilities.md` per scheme (Constraint Types + fail-closed note).
- **Vectors (60 → 66)**: `clinical-001` (drug-class non-member →
  `not_in_enum`), `clinical-002` (dose bound → `params_exceed_grant`),
  `payments-001` (counterparty whitelist → `not_in_enum`), `payments-002`
  (scheme-scoped constraint triple → `unknown_constraint`, the fail-closed
  demonstration), `data-001` (purpose/region classification via params →
  allow, the v1-decidable form), `data-002` (rows bound →
  `params_exceed_grant`). Both runners 66/66, Reason-fail 0.
- **Evidence**: three CLC-v2 requirements recorded in design-notes §18
  (cumulative quota, purpose/region classification constraints, quorum/会签)
  with suggested input shapes — **not implemented**.
- **Housekeeping**: spec Appendix B total → 66 (note added), capability
  README scheme list + vector count updated, `vectors.schema.json` still
  validates 66/66.

Per-kind delta: entail 25 → 29 (clinical-001/002, payments-001, data-002);
decide 19 → 21 (payments-002, data-001).

## rev 6 Changes (2026-09-11) — Params Normalization + Language Revision Closeout

Closeout consistency work (53 → 60 vectors, both runners green):

**P2 — spec table correction.** §6.2 object row flipped to ✓ (request element
`id` is a member of the granted set under the v1.1 enum rule); `params-015`
added as the allow-direction vector.

**P3 — params input normalization (normative).** New §6.2 representation
block (5 statements: JCS-first serialization; duplicate keys; number shape;
size/depth caps; fixed check order) and new §9.3 layer 2. Three new codes,
fired at the input boundary before any layer:
`invalid_params_duplicate_key`, `invalid_params_number` (non-finite or >17
significant digits; malformed-JSON catch-all), `invalid_params_size` (512-byte
cap, depth-32 cap). Order: size/depth → duplicate keys → number shape.
Non-object or unparseable params → `invalid_params_number`.

Because a decoded map drops duplicate keys and JSON cannot carry `1e400`,
vectors carry the raw JSON text in a new optional `raw_params` string field;
both runners validate it at the boundary and short-circuit to `deny(<code>)`.
New vectors: params-016 (dup key), params-017 (`1e400`), params-018 (600-char
string), params-019 (depth 33). Layer 2→11 renumbering applied across spec,
design notes, OCMP reference, source comments and vector derivations.

**P4 — §12.1 language revision.** Every implementation declares
`CLC-<major>.<minor>` (this spec: `CLC-1.1`); compatible reading = same major
and input minor ≤ impl minor; incompatible → fail-closed
`unsupported_language_revision` with no silent downgrade, resolved before any
layer. New vectors `revision-001` (CLC-1.0 → allow) and `revision-002`
(CLC-2.0 → deny); every vector carries a `clc_revision`.

**Schema**: `vectors.schema.json` now requires `clc_revision` +
`conformance_class` (all `CLC-A`) and allows optional `raw_params`; validated
against all 60 vectors.

**Also in rev 6**: P5 (four Security Considerations bullets), P7
(`offline-vectors.json`, 11 reference-only OCMP fail-closed cases — not part
of CLC-A/B semantics), P8 (scheme-data audit: only `std/robot-line-v1`
declares numeric-array params, intentional §6.2 enum coding; recorded in
`data/artifacts-index-zh.md`).

**Verification**: Go and Python 60/60, Reason-fail 0, Go==Python identical on
every vector; `go test ./...`, `go vet`, `gofmt` clean.

## rev 5 Changes (2026-09-10) — Reason Enforcement + Fail-Closed Absent Grant

Independent review noted dead-letter reasons and a fail-open hazard despite
100% prior consistency:

**F3 (tooling): runners now assert reasons.** Both `cmd/vectors-run/main.go`
and `vectors-run.py` compare the actual reason against the vector
expectation on every vector — verdict-only no longer suffices. A
deliberately broken expectation (`decide-015` → `BROKEN_reason`) fails both
runners (Pass 52 / Fail 1 / Reason-fail 1), proving enforcement.

**F1 (spec): canonical-code format.** CLC-v1 §9.4 now states the canonical
code is everything before the first `:`; implementations MAY append
`: <detail>` (e.g. `invalid_params_null: limit`) as diagnostics. Runners and
tooling MUST compare the canonical prefix only. Diagnostics preserved,
interop-safe string comparison restored.

**F2 (impl): absent/empty grant is fail-closed.** `Authorize` /
`authorize()` previously raised (`TypeError` / nil-deref) on a `null` or
empty grant (masked by runner shortcuts). Now: absent/empty grant →
`deny("capability_not_authorized")` (§9 layer 9, first check); absent
operation → `deny("missing_capability_id")` (layer 1). Runners removed the
nil shortcuts so the hardened path is exercised per vector.

**New vector `decide-015`** (grant `{}`, no id → `capability_not_authorized`).
Total 52 → 53. B.5 → 10 vectors; `kind=decide` → 17.

## v1.2 Changes (2026-09-10) — Resolved Reason Ordering

CLCV-1 §9.3 now defines a fixed normative order that resolves which reason
code is reported when more than one condition fails. This closes the six
reason-only divergences noted in rev 3 (verdicts were always correct and
Go==Python; the vector expectations disagreed with both implementations).

Order (first applicable layer wins): valid, badness → `invalid_capability_id`
/ `unsupported_wildcard`; namespace = scheme + action Class →
`different_namespace`; path coverage → `literal_mismatch` /
`wildcard_requires_trailing_segment`; explicit empty `[]`/`{}` bound →
`empty_bound_denies_class` (deny-when-declared, evaluated before member
math, incl. in Intersect); `null` values → `invalid_params_null`; param
presence → `params_missing`; enum membership → `not_in_enum`; bounds →
`params_exceed_grant`; coverage/intersection emptiness → `no_overlap` /
`capability_not_authorized`; constraints → `unknown_constraint` /
`{type}:violated`.

Effects:

1. `entail-004` — Class mismatch (`query` vs `admin`) is now
   `different_namespace` (namespace = scheme + Class), not
   `literal_mismatch`. Implemented via `namespaceOf` pre-check.
2. `intersect-002`, `combined-005`, `combined-011` — an explicitly empty
   `tables:[]` bound now yields `empty_bound_denies_class` instead of
   `no_overlap` (Intersect scans sources before merging).
3. `combined-003` — vector expectation corrected to `params_missing`
   (intersection yields `{limit:50}`; op requests only `max_rows`, so the
   `limit` key is absent; no `max_rows` constraint is declared).
4. `combined-006` — vector expectation corrected to
   `capability_not_authorized` (unknown `scheme` = namespace mismatch → no
   coverage; not a constraint-type failure).
5. Bound-case prefix behaviors normalized (`empty_bound_denies_class` for
   empty `{}` values; paramsSubset now evaluates order 4→8 deterministically).

## v1.1 Changes (2026-09-10) — Enum Rule

Adopted Plan A from `clc-v1-finding-param-domain-2026-09-10.md`: array-valued
grant parameters are the **set of allowed values** (CLC-v1 §6.2). Request
may send a scalar (member test) or array (every element a member); members
compare by exact equality; new code `not_in_enum`; empty `[]` →
`empty_bound_denies_class`. Six new vectors P9–P14, 46 → 52. See rev 3.

## Implementation Notes

### Go (register/semantics)

- File: `semantics/semantics.go`
- CLI: `cmd/vectors-run/main.go`
- Module: `github.com/varwof/register/semantics`
- Known constraints: `max_rows`, `time`, `network` (indexed by `parts[1]`, rev CLC-1.2)
- Test: `go test ./...` green (semantics 16 tests); `gofmt -l` clean; `go vet` clean

### Python (aic-capability-demo/clc_semantics)

- File: `clc_semantics.py`
- CLI: `vectors-run.py`
- Known constraints: `max_rows`, `time`, `network`
- No third-party dependencies (stdlib only)

### TypeScript (aic-capability-demo/ts/clc_semantics)

- File: `ts/clc_semantics.ts`
- CLI: `ts/vectors-run.ts`, `ts/property.ts` (package.json scripts)
- Known constraints: `max_rows`, `time`, `network` (§8.3 grammar: type = second
  `:`-delimited segment)
- Zero npm dependencies; Node ≥22 `--experimental-strip-types` (type: module)

### Semantic Differences

None on the conformance surface: all three implementations produce identical
verdicts **and reason codes** for all 98 vectors, and all match the vector
expectations; the shared P11 property wall (1184 cases) passes in all three.
The four corpus-unexercised corner cases recorded in `clc-v1-ambiguities.md §6`
(2026-09-11) were resolved and pinned by new vectors during the CLC-1.2 sweep —
Boolean grant values are exact (params-022/023), op-id wildcards propagate the
concrete layer-1 code (decide-018), the known-constraint set is
`{max_rows, time, network}` with a value grammar (decide-019..024,027), and
`null` precedes presence (params-024).  The CLC-1.3 closeout (rev 12) then
removed the residual area: the `verbatim` field is gone (the
`allow_unresolved` verdict is the only residual channel) and the natural
multi-grant question ("same operation, several grants") is now defined by §9.3
aggregation with vectors (decide-028..030).

## Revision History

- 2026-09-12 rev 12: CLC-1.3 closeout — `allow_unresolved` independent verdict
  (verbatim field removed), (scheme,type) constraint identity, same-day
  time-window grammar, `{}` ≡ absent params, §9.3 multi-grant aggregation
  (`AuthorizeSet`); corpus 95 → 98 (decide 35 → 38); Go/Python/TS 98/98 and
  1184/1184 (0 failures), counters 869/841 in all three (`-count=1`).
- 2026-09-12 rev 11: CLC-1.2 sweep — `unresolved` channel (allow-side additive
  field), `invalid_constraint` value grammar, §3 scheme grammar, max_rows
  op-absent fail-closed, dict key-set P11 rule; corpus 83 → 95 (syntax 9, entail
  37, intersect 14, decide 35); property wall 524 → 1184; Go known-set and
  `authorize`-collapse alignments; TS NOTE cleanups. Go/Python/TS 95/95 and
  1184/1184 (0 failures), counters 869/860 in all three (`-count=1`).
- 2026-09-11 rev 10: TypeScript third implementation (`ts/clc_semantics.ts`,
  `ts/vectors-run.ts`, `ts/property.ts`, zero-dep Node) written from the spec.
  Go/Python/TS each 76/76 Reason-fail 0 at the time; P11 property 524 cases, 0 failures
  in all three (the 281/274 counter split recorded here was later found to be a harness
  counting difference, not a semantic one — see Addendum 2)
  three; TS runner output byte-identical to Python's (plain-diff parity).
  Recorded 4 corpus-unexercised implementation divergences + 1 §8.3 wording
  ambiguity (ambiguities.md §6); added TS job to clc-conformance workflow.
- 2026-09-11 rev 9: Codex batch — gap-fill `params-006/013` (B.3 P6/P13),
  normalization positive boundaries `params-020/021` (P20/P21), decision-layer
  paths `decide-016/017` (D15/D16), intersection §7 rules 5–6 `intersect-007..010`
  (I7..I10) incl. one conformance alignment (`intersect-010`, impl → §7 rule 2).
  68 → 76. entail 29→31, intersect 10→14, decide 23→25.
- 2026-09-11 rev 8: P2' key closure — `undeclared_param` deny for operation
  keys a bounded grant does not declare (§6.2, §9.3 layer 7, §9.4, B.5
  D13/D14); Go `ErrParamsUndeclared` + `paramsSubset` loop; Python
  `ParamsUndeclared` + `params_subset` loop; vectors undeclared-001/002.
  66 → 68. decide 21→23. Pre-release audit item closed.
- 2026-09-11 rev 7: scheme stress-test batch — `std/{clinical,payments,data}-v1`
  schemes (18 capabilities) + 6 vectors (clinical-001/002, payments-001/002,
  data-001/002) probing §6.2 enum/bound paths and §8 fail-closed
  `unknown_constraint` for scheme-scoped constraint types; CLC v2 requirements
  evidence in design-notes §18. 60 → 66. entail 25→29, decide 19→21.
- 2026-09-11 rev 6: closeout consistency work — §6.2 object-row fix + params-015
  (P2); §6.2 params normalization + §9.3 layer 2 with `invalid_params_duplicate_key`
  / `invalid_params_number` / `invalid_params_size` + `raw_params` vectors
  params-016..019 (P3); §12.1 language revision + revision-001/002 (P4); four
  Security Considerations bullets (P5); schema `clc_revision`/`conformance_class`/
  `raw_params` + third-party run contract (P6); offline-vectors.json (P7); scheme
  audit + artifacts-index (P8). 53 → 60. Layer 2→11 renumbering across the corpus.
  Reason-fail: 0 by tooling.
- 2026-09-10 rev 5: reason assertions enforced in both runners (F3);
  §9.4 canonical-code/suffix format (F1); fail-closed absent/empty grant in
  both implementations + operand guard (F2); added decide-015; 52 → 53.
  Reason-fail: 0 by tooling.
- 2026-09-10 rev 4: added §9.3 resolved-reason ordering (v1.2); namespace =
  scheme + action Class; empty-bound deny-when-declared in Intersect;
  corrected combined-003 (`params_missing`) and combined-006
  (`capability_not_authorized`) expectations. Six rev-3 divergences closed;
  impl↔vector reason consistency now 100%.
- 2026-09-10 rev 3: applied v1.1 enum rule (spec §6.2 + §9.4 `not_in_enum`);
  added P9–P14; reclassified params-004/005, combined-007 to `not_in_enum`;
  fixed params-007 reason; documented 6 pre-existing reason-only divergences.
  Count 46 → 52.
- 2026-09-10 rev 2: added decide-009 (issue 2); unified notation notes
  (issue 1); wildcard v1/v2 boundary record (issue 3); wording fix
  (issue 4); Go runner default path fix + appendix mapping note (issue 5).
  Count 45 → 46.

## Reproduction Commands

```sh
# Go (either explicit CLC_VECTORS or default path)
cd ~/src/github.com/register && go run ./cmd/vectors-run/            # default path
CLC_VECTORS=../capability/data/_vectors/clc-v1/vectors.json go run ./cmd/vectors-run/

# Python
cd ~/src/github.com/aic-capability-demo
python3 vectors-run.py
python3 property_test.py

# TypeScript (Node >= 22)
cd ~/src/github.com/aic-capability-demo
node --disable-warning=ExperimentalWarning --experimental-strip-types ts/vectors-run.ts
node --disable-warning=ExperimentalWarning --experimental-strip-types ts/property.ts

# Cross-language parity (byte-level)
cd ~/src/github.com/aic-capability-demo
python3 vectors-run.py > /tmp/py.out
node --disable-warning=ExperimentalWarning --experimental-strip-types ts/vectors-run.ts > /tmp/ts.out
diff /tmp/py.out /tmp/ts.out && echo "TS == PYTHON"
```

---

## Addendum (2026-09-11, evening): the third implementation, and the count

This report was written for the **Go/Python** pair.  A third implementation now
exists — `ts/` in this repository (`clc_semantics.ts` + `vectors-run.ts` +
`property.ts`, Node-only, zero npm deps) — and it is part of the conformance bar:
all three run `vectors.json` and `property-cases.json` from `varwof/capability`.

Current state (2026-09-11): **83 vectors** (was 60 when this report was
written; `params-022..024`, `decide-016..018`, `intersect-007..010` and the
boundary positives were added since) and **524 property cases**, with all three
implementations agreeing on both corpora.

The four vectors added on this date pin real disagreements that this report
could not see, because it compared verdicts and reason codes but never the
merged result the divergences lived in:

- `params-022/023` — a boolean grant value must not be satisfied by `1`
  (Python's `bool`-is-`int` made this an *allow* until it was fixed).
- `params-024` — layer 6 (`null`) precedes layer 7 (presence): a grant carrying
  `null` reports `invalid_params_null` even when the operation omits `params`.
- `decide-018` — wildcard-shape detection precedes the base grammar, and layer 1
  propagates the specific code (`unsupported_wildcard`).

Still open: the TypeScript `validateRawParams` is a single-pass scan, so for
"over-limit + duplicate key / bad number" combinations it reports the
dup/number code before the size code, which is the reverse of §6.2 item 5.  The
corpus holds single-fault inputs only, so no runner currently catches it.

> **Update (2026-09-12, rev 12)**: the multi-fault gap was closed that same
> evening — `params-025/-026/-027` pin the §6.2 item 5 order and `ts`
> `validateRawParams` is now a two-pass scan (size/depth before dup/number).
> Current corpus is 98 vectors and 1184 property cases (see rev 12 above).

See also `varwof/capability` → `docs/design-notes.md` for the English decision record
(why each rule was chosen, what was rejected, and the probe batch that found three
implementation divergences).

### Addendum 2 (2026-09-11, late): the counters DO agree — Go's run was cached

Resolved the same evening.  The apparent split (Go 281 order / 274 closure vs
Python and TS 299 / 290) was **not** a semantics difference and **not** a
counting-rule difference: the property corpus lives outside the Go module, so
`go test` reused a cached result and replayed the counters from the previous
corpus revision.  With the cache disabled the three agree exactly:

```
go test -count=1 ./semantics/ -run TestIntersectionProperty -v
  → 524 cases, 299 order-symmetry checks, 290 closure probes
python3 property_test.py   → 524 cases, 299 / 290
ts/property.ts             → 524 cases, 299 / 290
```

The CI job now runs `go test -count=1` for the property suite, with a comment
explaining why.  All three runners also agree **case by case**: a full export of
the forward verdict for the 524 cases diffs clean between Go and Python.

Superseded text follows.

### (superseded) the per-runner counters are not comparable

All three runners agree **case by case**: a full per-case export of the forward
verdict (`allow` / `deny:<code>`) for the regenerated 524-case file diffs clean
between Go and Python (0 differences), and the 83-vector corpus passes in all
three.  What differs is the **diagnostic counters** each runner prints
(Go 281 order / 274 closure vs Python and TS 299 / 290): the two counters are
incremented under slightly different guards in the three harnesses.  They are a
runner diagnostic, not a conformance claim, and they are therefore not published
as numbers until the counting rule is written down once and implemented
identically in all three.

Fix for the next session: define the two counters in `property-cases.json._meta`
(`order-symmetry checks = every case with ≥2 sources whose forward merge
succeeded`; `closure probes = successful merges whose effective grant is
bounded`), implement that predicate identically in
`register/semantics/property_test.go`, `aic-capability-demo/property_test.py` and
`aic-capability-demo/ts/property.ts`, and re-run.
