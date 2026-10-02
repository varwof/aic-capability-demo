# Varwof AIC — Capability Semantics Demo Package

> Part of the Varwof AIC suite — flagship repos: [aic-agent](https://github.com/varwof/aic-agent) · [aic-verifier](https://github.com/varwof/aic-verifier) · [aic-exec](https://github.com/varwof/aic-exec)

> ⚠️ **Preview** — Not for production use. APIs and features may change before official release.

A runnable, end-to-end demonstration of the AIC capability authorization
semantics: **AI-proposed least privilege → tool validation (version pinned) →
role-grant intersection → cryptographically bound into the AIC → gateway
enforcement per request**. Four scenarios: database, digital wallet, deploy/
infrastructure, and MCP tool calls. Everything is reproducible and auditable.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[中文](README_CN.md)

This package consumes the capability data and conformance corpora from
[`varwof/capability`](https://github.com/varwof/capability) and implements the
same CLC-v1 semantics as the Go reference
[`varwof/register`](https://github.com/varwof/register).

## 0. Clone and run (3 steps on a fresh machine)

```bash
git clone https://github.com/varwof/aic-capability-demo.git && cd aic-capability-demo
# 1) Build all binaries from pinned commits (one command)
./build.sh && export PATH="$PWD/bin:$PATH"
# 2) Bootstrap a CA, issue a principal certificate (REVIEWER-GUIDE §6)
# 3) Generate the gateway config from your CA-issued certs
./setup.sh --gateway-cert gw.pem --gateway-key gw.key --jwt-ca issuing-ca.pem
# 4) Start backends + gateway, run any scenario
python3 backends.py &
gateway-http --config gateway.json &      # run from this directory (relative capdata paths)
python3 scenario-demo.py --scenario mcp --principal-cert principal.pem \
  --principal-key principal.key --client-config client.json --ca-cert ca-bundle.pem \
  --pa-authz --execute
```

- The `.p7s` files in `capdata/` are signed by `capdata/trust/demo-codesign-ca.pem`
  and verify out of the box.
- Scripts default to the in-package `capdata/`; the register repo is only
  needed for `gen-capability` (auto-detected as `../register` or a local checkout).
- `gateway.json` is generated from `gateway.json.template` by `setup.sh` — no
  absolute machine paths.

## 1. What this is

```
 DeepSeek / mock              register tools              core (CA)               gateway-http
      |                            |                          |                       |
 task + prompt + spec         claims.json              PA signs DA -> CA issues AIC   Bearer AIC-JWT
      |  ----------------->  gen-capability -minimal -> params bound in cert -------> capability plugin
      |                       (scheme_version pinned)   --pa-authz role intersection  (out-of-scope -> 403)
```

## 2. Capability scenarios (5 schemes)

| Scenario | scheme | capabilities | enforced parameters |
|---|---|---|---|
| Database | `std/database-v1` | query:SELECT/INSERT/UPDATE/DELETE/EXECUTE, admin:DDL/TRUNCATE | see the table below |
| Digital wallet | `std/wallet-v1` | balance / transfer / history | assets, networks, max_amount_per_tx, recipients allowlist |
| Deploy/infra | `std/deploy-v1` | deploy:apply / infra:read / secret:read | environments, namespaces, resources, max_replicas, secrets allowlist |
| MCP tools | `std/mcp-v1` | tools:call | tools allowlist (declared empty = deny) + tool_args/path_prefixes |
| LLM | `varwof/llm` | chat | model, max_tokens |

The database scheme does **not** carry one shared parameter set — each capability
declares its own required keys, and the gateway refuses a request missing any
required one.  Read from `capdata/std/database-v1/v1.json`:

| capability | required | optional |
|---|---|---|
| `query:SELECT` | `tables`, `columns` | `aggregate`, `row_filter`, `filter_columns`, `limit` |
| `query:INSERT` | `tables`, `columns` | — |
| `query:UPDATE` | `tables`, `columns`, `row_filter` | `filter_columns`, `limit`, `order_by` |
| `query:DELETE` | `tables`, `row_filter` | `filter_columns`, `limit`, `order_by` |
| `query:EXECUTE` | `procedures` | — |
| `admin:DDL` | `operations`, `tables` | — |
| `admin:TRUNCATE` | `tables` | — |

Note: upstream [`varwof/capability`](https://github.com/varwof/capability) names
this package's LLM scheme `varwof/llm-v1`; the copy vendored in `capdata/` still
carries the older `varwof/llm` identifier.

## 3. Files

| File | Purpose |
|---|---|
| `REVIEWER-GUIDE.md` | Independent-reviewer walkthrough (build/CA/issue/gateway/matrices); verified 2026-09-01 |
| `QUICKSTART.md` | Two-command quickstart + per-scenario matrices |
| `deepseek-capability-aic.py` | Database scenario end-to-end (DeepSeek/mock -> validate -> AIC) |
| `wallet-demo.py` | Wallet scenario end-to-end + 6-case matrix |
| `scenario-demo.py` | Deploy/MCP scenarios (`--scenario deploy\|mcp`) |
| `backends.py` | Mock backends: data :9100 / LLM :9200 / wallet :9300 / deploy :9400 / MCP :9500 |
| `build.sh` | One-command build of all binaries from pinned commits |
| `gateway.json.template` + `setup.sh` | Portable gateway config generation |
| `capdata/` | Capability schemes + PKCS#7 signatures + demo trust root |

### CLC-v1 implementation and runners

| File | Purpose |
|---|---|
| `clc_semantics.py` | Python CLC-v1 implementation (the reference for everything below) |
| `vectors-run.py` | CLC-A authorization corpus runner |
| `resolve-vectors-run.py` | §8.5 `Resolve` runner |
| `param-bounds-vectors-run.py` | §6.5 parameter-bounds runner |
| `param-bounds-meet-vectors-run.py` | §6.6 `BoundMeet` runner |
| `constraint-union-vectors-run.py` | §7.1 `ConstraintUnion` runner |
| `contains-vectors-run.py` | §13 `Contains` runner |
| `authorize-chain-vectors-run.py` | §13.11 `AuthorizeWithChain` runner |
| `property_test.py` | P11 property runner (1184 cases: narrowing + order-symmetry) |
| `param-bounds-meet-property-run.py` | §6.6 meet-invariant property runner (500 cases) |
| `contain-property-run.py` | CLC-D forward-closure property runner (784 cases) |
| `edge_test.py` | raw/decoded boundary suite (non-finite, malformed Unicode, JCS size, I-JSON integer bound in params **and** constraints) |
| `contains_test.py` | containment parity checks against the Go reference |
| `jcs_check.py` | RFC 8785 (JCS) canonicalization: bytes, digest, `clc-action:` id, key order, invalid Unicode |
| `ts/` | TypeScript mirror of all of the above (Node-only, zero npm deps) |
| `fuzz/` | Deterministic differential fuzz harness (`gen_cases.py`, `run_py.py`, `run_ts.ts`, `compare.py`, `shrink.py`) |
| `clc-v1-parity-report.md` | Cross-implementation parity record |
| `fuzz-divergence-report.md` | Differential-fuzz result at the current pin, open findings included |

This package ships runners for the corpora it implements; the evidence-side
(`evidence-vectors.json`) and crosswalk (`crosswalk-vectors.json`) corpora are run
by the Go runners in
[`varwof/register`](https://github.com/varwof/register).

## 4. Verification matrices (all pass)

- **database**: in-scope 200; out-of-scope table/column/limit 403 (body and query)
- **wallet**: in-scope transfer 200; over-amount / non-allowlisted recipient /
  unauthorized asset 403; balance 200/403
- **deploy**: staging 200; production / out-of-scope namespace / over replicas 403;
  secret allowlist 200/403
- **mcp**: read_file/list_dir 200; bash/delete_file 403; initialize protocol 200;
  hostile boundary (v0.4.6): missing params.name / declared empty allowlist /
  /workspace-evil sibling / /workspace/../etc parent traversal -> 403
- **replay protection**: same JWT twice -> 200 then 401

## 5. Implementation commits behind the claims

| Repo | Commit | What it provides |
|---|---|---|
| varwof/register | 954951f / edaa378 / 71c0f39 | flat-param value validation, params_schema validation, scheme_version pinning |
| varwof/types | addb8b0 / 4868765 | capability/grant JSON-container params; HTTPFacts/PluginContext body |
| varwof/client | 44b210b / 6b74b23 / 9dbd21e | caps/pa JSON params, --from-claims, --pa-authz role intersection |
| varwof/core | 1a6cbe7 / ed42b00 | generic parameter-subset at issuance; claims digest in issuance audit |
| varwof/gateway-core | v0.4.1–v0.4.6 (9674d7c) | database/wallet/deploy/mcp plugins; bearer fail-closed; hostile path/allowlist boundary fix |
| varwof/gateway | 763b6ce / 779481d / a35d9c6 | body to plugins; capreg .p7s verification; plugin wiring |
| varwof/capability | 10162b5 / d225486 / d8bd1c3 / f124868 / 24a9ca9 | std/database-v1, std/wallet-v1, std/deploy-v1, std/mcp-v1 (v1.1.0 doc), varwof/llm |

## 6. Security properties demonstrated

1. Capability parameters cryptographically bound into AIC/PA/DA (claims digest
   anchored in the DA reason and issuance audit)
2. CA rejects claims outside the operator role's grants (`--pa-authz`,
   Pprincipal ∩ Cagent)
3. Gateway enforces parameter boundaries per request
4. Registry PKCS#7 signature verification (tamper fail-closed)
5. Bearer replay protection + plaintext rejection

## 7. Known boundaries

- The gateway serves only its leaf certificate: pass `--ca-cert` a bundle of
  root + intermediate
- The mcp plugin treats a request without a JSON-RPC body as a protocol method
- Rate limits (wallet daily, mcp rpm) are parameter placeholders, not yet enforced
- Plugins use structured operation payloads; real SQL/wallet/deploy APIs need
  their own adapters

## 8. CLC-v1 implementations and conformance corpora

Three implementations run the **same** corpus and assert **verdict, normative
reason code and the merged intersection result**:

| Implementation | Where | Vectors runner | Property runner |
|---|---|---|---|
| Go | `varwof/register` (`semantics/`) | `go run ./cmd/vectors-run/` | `go test ./semantics/ -run TestIntersectionProperty` |
| Python | this repo | `python3 vectors-run.py` | `python3 property_test.py` |
| TypeScript | `ts/` (Node 22 `--experimental-strip-types`, zero npm deps) | `node --experimental-strip-types ts/vectors-run.ts` | `node --experimental-strip-types ts/property.ts` |

```bash
# all three, against the shared corpora in varwof/capability
export CLC_VECTORS=../capability/data/_vectors/clc-v1/vectors.json
export CLC_PROPERTY_CASES=../capability/data/_vectors/clc-v1/property-cases.json
python3 vectors-run.py && python3 property_test.py
node --experimental-strip-types ts/vectors-run.ts && node --experimental-strip-types ts/property.ts
(cd ../register && go run ./cmd/vectors-run/ && go test ./semantics/ -run TestIntersectionProperty)
# RFC 8785 canonicalization (rev CLC-1.6): Go, Python and TypeScript must emit
# the same JCS bytes, digest and clc-action: identifier.
python3 jcs_check.py && node --experimental-strip-types ts/jcs_check.ts
```

Corpora (in [`varwof/capability`](https://github.com/varwof/capability),
`data/_vectors/`): `clc-v1/vectors.json` (the CLC-A authorization vectors, incl.
the rev CLC-1.3 `allow_unresolved` verdict and §9.1 multi-grant aggregation —
**146 vectors**; that repository's README carries the authoritative count),
`evidence-vectors.json` (32), `crosswalk-vectors.json` (13),
`param-bounds-vectors.json` (43), `param-bounds-meet-vectors.json` (27),
`param-bounds-equality-vectors.json` (11), `constraint-union-vectors.json` (12),
`constraint-union-collation-vectors.json` (2), `resolve-vectors.json` (26),
`property-cases.json` (1184 deterministic P11 cases),
`param-bounds-meet-property-cases.json` (500),
`offline-vectors.json` (12 OCMP reference cases), and under `clc-d/`
`containment-vectors.json` (64), `authorize-chain-vectors.json` (15),
`containment-crosswalk-vectors.json` (44),
`containment-property-cases.json` (784).

Point any runner at a corpus through its environment variable — the table in
[`varwof/register`](https://github.com/varwof/register#conformance-corpora) lists
the variable per corpus:

```bash
export CLC_VECTORS=../capability/data/_vectors/clc-v1/vectors.json
python3 vectors-run.py
export CLC_D_VECTORS=../capability/data/_vectors/clc-d/containment-vectors.json
python3 contains-vectors-run.py
```

Why three: a language is only as strong as the agreement between its
interpreters.  These three share an author, so their parity is a regression
test of the specification, not independent validation (§12, principle P12) —
and even so they disagreed on real inputs until 2026-09-11: the Go and Python
implementations each violated a rule the TypeScript one already followed
(boolean-exactness, layer-6-before-layer-7, layer-1 code propagation).  The parity record is in `clc-v1-parity-report.md`; the CI in
`.github/workflows/clc-conformance.yml` clones `varwof/capability` and runs
`py_compile`, the vectors and the property suite on every push and PR.

## 9. Differential fuzz (behavioral parity)

The vectors above assert that the three implementations produce the *same
answer*.  The fuzz harness asks the harder question: on inputs nobody wrote a
vector for, do they still behave the same, including the reason codes and the
value layer?

```bash
python3 fuzz/gen_cases.py --n 100000 --seed 20260915 > /tmp/cases.jsonl
python3 fuzz/run_py.py /tmp/cases.jsonl > /tmp/res_py.jsonl
npx --yes tsx fuzz/run_ts.ts /tmp/cases.jsonl > /tmp/res_ts.jsonl
(cd ../register && go run ./semantics/fuzz_runner /tmp/cases.jsonl > /tmp/res_go.jsonl)
python3 fuzz/compare.py /tmp/cases.jsonl /tmp/res_py.jsonl /tmp/res_ts.jsonl /tmp/res_go.jsonl
```

The corpus is seed-deterministic and covers ten axes (key order, duplicate
keys, malformed escapes and lone surrogates, number shapes, missing/null/empty,
types, arrays, size and depth caps, constraint identity, id shapes).
`fuzz-divergence-report.md` holds the result at the current pin, including the
findings that are still open.  A raw/decoded boundary difference inside one
implementation is CLC §6.2 working as designed, not a divergence; the report
separates the two so the counts are not read the wrong way.

## 10. Related repositories

| Repository | What it is |
|---|---|
| [`varwof/capability`](https://github.com/varwof/capability) | the capability schemes and every CLC-v1 conformance corpus this package consumes ([中文](https://github.com/varwof/capability/blob/main/README_CN.md)) |
| [`varwof/register`](https://github.com/varwof/register) | the Go reference implementation of the same CLC-v1 semantics ([中文](https://github.com/varwof/register/blob/main/README_CN.md)) |

## Links

| | |
|---|---|
| Homepage | https://varwof.com |
| Community | https://varwof.org |
| License | Apache-2.0 |
| Member | [Open Invention Network](https://openinventionnetwork.com/) |
