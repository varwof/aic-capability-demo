# Varwof AIC — Capability Semantics Demo Package

A runnable, end-to-end demonstration of the AIC capability authorization
semantics: **AI-proposed least privilege → tool validation (version pinned) →
role-grant intersection → cryptographically bound into the AIC → gateway
enforcement per request**. Four scenarios: database, digital wallet, deploy/
infrastructure, and MCP tool calls. Everything is reproducible and auditable.

## 0. Clone and run (3 steps on a fresh machine)

```bash
git clone https://github.com/varwof/aic-capability-demo.git && cd aic-capability-demo
# 1) Build all binaries from pinned commits (one command)
./build.sh && export PATH="$PWD/bin:$PATH"
# 2) Bootstrap a CA, issue a principal certificate (IMAN-TEST-GUIDE §6)
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
| Database | `std/database-v1` | query:SELECT/INSERT/UPDATE/DELETE/EXECUTE, admin:DDL/TRUNCATE | tables, columns, row_filter, limit |
| Digital wallet | `std/wallet-v1` | balance / transfer / history | assets, networks, max_amount_per_tx, recipients allowlist |
| Deploy/infra | `std/deploy-v1` | deploy:apply / infra:read / secret:read | environments, namespaces, resources, max_replicas, secrets allowlist |
| MCP tools | `std/mcp-v1` | tools:call | tools allowlist (declared empty = deny) + tool_args/path_prefixes |
| LLM | `varwof/llm` | chat | model, max_tokens |

## 3. Files

| File | Purpose |
|---|---|
| `IMAN-TEST-GUIDE.md` | Full English walkthrough (build/CA/issue/gateway/matrices) |
| `QUICKSTART.md` | Two-command quickstart + per-scenario matrices |
| `deepseek-capability-aic.py` | Database scenario end-to-end (DeepSeek/mock -> validate -> AIC) |
| `wallet-demo.py` | Wallet scenario end-to-end + 6-case matrix |
| `scenario-demo.py` | Deploy/MCP scenarios (`--scenario deploy|mcp`) |
| `backends.py` | Mock backends: data :9100 / LLM :9200 / wallet :9300 / deploy :9400 / MCP :9500 |
| `build.sh` | One-command build of all binaries from pinned commits |
| `gateway.json.template` + `setup.sh` | Portable gateway config generation |
| `capdata/` | Capability schemes + PKCS#7 signatures + demo trust root |

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
