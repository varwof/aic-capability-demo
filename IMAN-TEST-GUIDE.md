# Varwof AIC Demo — Reproducible Test Guide

> Target reader: independent reviewer (Iman / EMILIA). This guide reproduces
> the full AIC pipeline: AI-generated least-privilege capability claims →
> registry validation → Principal signs DelegationAuthorization → CA issues
> AIC → gateway enforces capability on Bearer AIC-JWT → LLM backend.
>
> Date: 2026-09-01. Verified end-to-end with real DeepSeek API.

## 1. Architecture

```
 DeepSeek (LLM)          register tools               core (CA)             gateway-http              backend
      |                        |                          |                     |                    |
 task + AI_PROMPT_EN.md  claims.json                /oauth/token        Bearer AIC-JWT         /v1/query (data)
 capability.json         gen-capability -minimal    (RFC 8693)          capability_schemes      /v1/chat/completions
      |---------------->  minimal set ------------->  x509 -> JWT ----->  required_capabilities -> LLM sidecar
      |                        |                     (iss/aud=varwof-core) (SELECT / chat)         (mock or DeepSeek)
      |                        v
      |              AIC request (--pa/--caps)
      |                        |
      +---------- PA signs DA + CA issues AIC <---- (client aic issue)
```

Two security properties exercised: (1) AIC-declared capabilities must be
registered in the gateway capability registry (fail-closed); (2) bearer-only
listeners deny requests without a token (fail-closed).

## 2. Required repositories and commits

| Repo | Required | Commit/status |
|---|---|---|
| github.com/varwof/register | gen-capability supports `params_schema` | `edaa378` (main) |
| github.com/varwof/gateway | bearer fail-closed fix | `63e4891` (main) |
| github.com/varwof/core | `/oauth/token` (RFC 8693 x509→JWT) | main (recent) |
| github.com/varwof/client | `aic issue` / `aic jwt` | main |
| github.com/varwof/capability | capability data (std/database-v1) | main |

Note: core `routes.json` must include `/oauth/token` in `public_paths` for the
token exchange endpoint to be reachable (the repo file does not contain it yet;
the demo uses a copy).

## 3. Prerequisites

- Go 1.26+, openssl, curl, python3
- Optional: a DeepSeek API key (`DEEPSEEK_API_KEY`) for the real LLM step;
  without it the demo uses an offline mock.

## 4. Build

```bash
git clone git@github.com:varwof/register.git && cd register && go build -o /tmp/demo/gen-capability ./cmd/gen-capability && go build -o /tmp/demo/gen-authz ./cmd/gen-authz
git clone git@github.com:varwof/core.git && cd core && go build -o /tmp/demo/varwof ./cmd/pki
git clone git@github.com:varwof/gateway.git && cd gateway && go build -o /tmp/demo/gateway-http ./cmd/http
git clone git@github.com:varwof/client.git && cd client && go build -o /tmp/demo/client .
git clone git@github.com:varwof/capability.git
```

## 5. Capability registry tools (no services needed)

```bash
CAP=capability/data
# list capabilities from the standard database scheme
/tmp/demo/gen-authz -list $CAP/std/database-v1/v1.json
# generate authz policy from capability schemes (roles scheme first)
/tmp/demo/gen-authz -out /tmp/demo/authz.json $CAP/varwof/core/v1.json $CAP/varwof/gateway/v1.json
# AI least-privilege validation: claims -> report + minimal set
cat > /tmp/demo/claims.json <<'JSON'
[{"scheme_id":"std/database-v1","capability":"query:SELECT",
  "parameters":{"tables":["customers","orders"],
    "columns":{"customers":["id","name","email"],"orders":["id","amount"]},
    "row_filter":{"customers":{"column":"tenant_id","op":"=","value":"org-a"},
                  "orders":{"column":"tenant_id","op":"=","value":"org-a"}},
    "limit":{"max":500}},
  "rationale":"read customers/orders for tenant org-a, max 500 rows"}]
JSON
/tmp/demo/gen-capability -schemes $CAP -grants "std/database-v1:query:SELECT" -minimal /tmp/demo/claims.json
```

`params_schema` (nested tables/columns/row_filter) is validated by the
JSON-Schema-subset validator added in `register@edaa378`.

## 6. CA + certificates

Bootstrap a private CA with the core CLI (core README quickstart), then issue
a principal (user) certificate:

```bash
/tmp/demo/varwof init-ca --name root --profile root-ca --out-dir /tmp/demo/root
/tmp/demo/varwof init-ca --name issuing --profile sub-ca --parent root   --parent-key /tmp/demo/root/private/ca.key --out-dir /tmp/demo/issuing
/tmp/demo/varwof serve &
```

Client config:

```json
{"server":"https://127.0.0.1:4433",
 "ca_cert":"/tmp/demo/root/certs/ca.pem",
 "client_cert":"/tmp/demo/principal.pem",
 "client_key":"/tmp/demo/principal.key"}
```

Issue the principal cert from the issuing CA (the configured default CA), then
an AIC:

```bash
/tmp/demo/client cfg.json issue --cn "principal@example.com" --ca "issuing"   --profile tls-client --validity 30 --out /tmp/demo/principal
/tmp/demo/client cfg.json aic issue --user-cert principal.pem --user-key principal.key   --agent agent-01 --ou gateway:llm   --pa "std/database-v1:query:SELECT" --caps "std/database-v1:query:SELECT"   --out /tmp/demo/aic
# inspect the AIC (capabilities + DA + PA grants)
/tmp/demo/client cfg.json cert show --cert /tmp/demo/aic/agent-01.pem
```

## 7. AI-generated capability claims (DeepSeek) -> AIC

Use the helper script `deepseek-capability-aic.py` (attached; see §10). With a
key it calls DeepSeek, without it uses a mock:

```bash
DEEPSEEK_API_KEY=sk-... python3 deepseek-capability-aic.py \
  --task "query customers and orders for tenant org-a, read only, no writes" \
  --scheme capability/data/std/database-v1/v1.json \
  --schemes-dir capability/data \
  --principal-cert /tmp/demo/principal/<serial>.pem \
  --principal-key  /tmp/demo/principal/<serial>-key.pem \
  --client-config  cfg.json \
  --agent-id agent-db-01 --execute
```

Expected: DeepSeek returns one claim `std/database-v1:query:SELECT` with
structured parameters; `gen-capability` reports `least privilege: true`; an AIC is
issued with that single capability.

## 8. Gateway capability enforcement

1) Demo capability dir (AIC-declared capabilities must be registered):

```bash
mkdir -p /tmp/demo/capdata/std/database-v1 /tmp/demo/capdata/varwof/llm
cp capability/data/std/database-v1/v1.json /tmp/demo/capdata/std/database-v1/
# varwof/llm chat capability (see attached v1.json)
```

2) Exchange AIC -> AIC-JWT (requires core `/oauth/token` public; §2 note):

```bash
/tmp/demo/client cfg.json aic jwt --cert /tmp/demo/aic/agent-db-01.pem --out /tmp/demo/db.jwt
```

3) Gateway config (`gateway.json`, attached template): listener
`127.0.0.1:9443` http2, `mode=server`, `jwt_ca_file=<issuing CA>`,
`jwt_issuer=varwof-core`, `jwt_audience=["varwof-core"]`,
`capability_schemes=/tmp/demo/capdata`; routes:
- `/v1/query` -> `http://127.0.0.1:9100`, `required_capabilities: ["std/database-v1:query:SELECT"]`
- `/v1/chat/completions` -> `http://127.0.0.1:9200`, `required_capabilities: ["varwof/llm:chat"]`

4) Start backends (`backends.py`): mock data API on :9100; LLM sidecar on
:9200 (forwards to DeepSeek when `DEEPSEEK_API_KEY` is set, otherwise mocks).
Start gateway, then run the matrix:

```bash
BASE=https://127.0.0.1:9443
# T1 no token -> 401
curl -sk --cacert ca.pem -o /dev/null -w '%{http_code}
' $BASE/v1/query
# T2 db.jwt -> /v1/query -> 200
curl -sk --cacert ca.pem -H "Authorization: Bearer $(cat db.jwt)" $BASE/v1/query
# T3 db.jwt -> chat -> 403 (missing varwof/llm:chat)
# T4 llm.jwt -> chat -> 200
# T5 llm.jwt -> query -> 403 (missing SELECT)
# T6 tampered token -> 401
# T7 same token twice -> 200 then 401 (replay protection)
```

## 9. Expected results

| # | request | expected |
|---|---|---|
| T1 | no token, /v1/query | 401 bearer_required |
| T2 | db.jwt, /v1/query | 200 mock rows |
| T3 | db.jwt, /v1/chat | 403 capability mismatch |
| T4 | llm.jwt, /v1/chat | 200 chat reply (mock or DeepSeek) |
| T5 | llm.jwt, /v1/query | 403 capability mismatch |
| T6 | tampered token | 401 |
| T7 | reused token | 200 then 401 |

## 10. Attachments

- `deepseek-capability-aic.py` — §7 helper (DeepSeek or mock -> claims ->
  gen-capability -> AIC)
- `backends.py` — §8 backends (data API :9100, LLM sidecar :9200)
- `gateway.json` — gateway config template
- `capdata/varwof/llm/v1.json` — LLM chat capability scheme

## 11. Notes / known boundaries

- Bearer tokens are bound to issuer/audience (`varwof-core`) and one-time
  jti/DA nonce (replay protection on by default); the synthesized certificate
  carries no OU, so `allow_roles` does not apply to bearer paths (role-based
  control for bearer is future work).
- The gateway bearer fail-closed fix and the register `params_schema`
  validator are required (commits in §2).
- Real DeepSeek calls cost tokens; the mock path exercises the same code.
- Proof of possession: the token exchange (RFC 8693) requires mTLS or DPoP;
  gateway bearer verification checks signature/binding but not key possession
  per request (documented boundary, matches the EMILIA crossing adapter).
