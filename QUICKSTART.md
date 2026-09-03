# Varwof AIC — Two-Command Quickstart

Generate a least-privilege AIC and enforce it at the gateway, end to end.

## Prerequisites

- Built binaries: `varwof` (core), `client`, `gateway-http`, `gen-capability`
- A running CA: `varwof init-ca ... && varwof serve` (see core README)
- A principal certificate (issue with `client issue --profile tls-client`)
- Optional `DEEPSEEK_API_KEY` (falls back to an offline mock)

## Command 1 — generate the AIC from a task

```bash
python3 deepseek-capability-aic.py \
  --task "query customers and orders for tenant org-a, read only, no writes" \
  --scheme capability/data/std/database-v1/v1.json \
  --schemes-dir capability/data \
  --principal-cert principal.pem --principal-key principal.key \
  --client-config client.json \
  --agent-id agent-01 --execute
```

What happens inside:

1. DeepSeek (or mock) reads AI_PROMPT_EN.md + the capability spec and
   proposes least-privilege claims (tables/columns/row_filter/limit);
2. `gen-capability` validates them (scheme version pinned, params checked);
3. `client aic issue --from-claims minimal-claims.json` signs the
   DelegationAuthorization with the principal key, anchors the claims
   SHA-256 into the DA reason, and the CA issues the AIC with the narrow
   parameters bound into the certificate;
4. Optionally add `--pa-authz` so the CA derives the PrincipalAuthorization
   from the operator's role grants in authz.json (claims must fit the role).

Output: `out/aic/agent-01.pem` + `out/minimal-claims.json`.

## Command 2 — enforce at the gateway

`gateway.json` (template in this package):

- listener with `jwt_ca_file`, `jwt_issuer=varwof-core`,
  `jwt_audience=["varwof-core"]`
- `capability_schemes` -> signed capability data directory
  (`capability_schemes_trust` enables PKCS#7 verification)
- `capability_plugins` -> `{"std/database-v1": {"type": "database"}}`
- route `/v1/query` with `required_capabilities: ["std/database-v1:query:SELECT"]`

```bash
gateway-http --config gateway.json
client client.json aic jwt --cert out/aic/agent-01.pem --out agent.jwt
curl -H "Authorization: Bearer $(cat agent.jwt)" \
  "https://127.0.0.1:9443/v1/query?table=customers&cols=id,name&limit=100"
# POST body also works: {"table":"customers","cols":["id","name"],"limit":100}
```

Out-of-scope operations (other tables/columns, higher limit) are denied 403.

## Security properties demonstrated

- Capability parameters are cryptographically bound into the AIC/PA/DA
- The CA refuses claims that widen the principal's role grants (`--pa-authz`)
- The gateway enforces the narrow parameters per request (table/cols/limit)
- The claims file digest is anchored in the signed DA and the issuance audit
- Capability definitions can require PKCS#7 signatures from a trust root


## Wallet capability control (digital wallet permissions)

The same mechanism gates an agent's access to a digital wallet:

- scheme `std/wallet-v1`: `balance` / `transfer` / `history`
- `transfer` params: assets, networks, `max_amount_per_tx`, `max_amount_daily`,
  recipients (allowlist)
- gateway `wallet` plugin enforces per request (body or query):

```bash
# in scope
POST /v1/wallet/transfer {"asset":"USDC","amount":50,"recipient":"0xVendor","network":"ethereum"} -> 200
# out of scope
{"asset":"USDC","amount":150,...}   -> 403 (over per-tx max)
{"asset":"USDC","recipient":"0xStranger"} -> 403 (not allowlisted)
{"asset":"BTC",...}                 -> 403 (asset not authorized)
GET /v1/wallet/balance?asset=USDC   -> 200
GET /v1/wallet/balance?asset=BTC    -> 403
```

Automated runner: `wallet-demo.py` (mock or DeepSeek claims -> gen-capability ->
AIC -> JWT -> 6-case enforcement matrix). Trust store note: point `--ca-cert`
at a bundle containing the gateway CA chain (root + intermediate); the demo
gateway serves only its leaf certificate.

## More scenarios: deploy & MCP

`scenario-demo.py --scenario deploy|mcp` runs the same end-to-end flow
(claims -> gen-capability -> AIC -> JWT -> enforcement matrix):

- **deploy** (std/deploy-v1): deploy:apply bounded by environment/namespace/
  resource allowlists + max_replicas; infra:read scoped to environments;
  secret:read by name allowlist. Production is denied unless explicitly
  granted (8 cases: staging ok, production 403, namespace out 403,
  replicas over 403, secret allowlist 200/403).
- **mcp** (std/mcp-v1): MCP JSON-RPC tools/call must reference an allowlisted
  tool; protocol methods (initialize/ping/tools/list) pass read-only.
  5 base cases: read_file 200, bash 403, list_dir 200, initialize 200,
  delete_file 403; plus hostile boundary cases (gateway-core v0.4.6):
  missing params.name, declared empty "tools":[], /workspace-evil sibling,
  /workspace/../etc parent traversal -> 403.

Schemes are signed in `capdata/`; add the matching grants to the operator
role in authz.json for `--pa-authz`.

## Full demo (scripts in this package)

- `deepseek-capability-aic.py` — Command 1 automation
- `backends.py` — mock data API (:9100) + LLM sidecar (:9200)
- `gateway.json` — gateway config template
- `capdata/` — signed std/database-v1 + varwof/llm capability schemes
