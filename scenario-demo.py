#!/usr/bin/env python3
"""
scenario-demo.py — deploy & MCP capability enforcement, end to end.

Runs the same flow as wallet-demo.py for two more scenarios:
  --scenario deploy   std/deploy-v1: deploy:apply / infra:read / secret:read
  --scenario mcp      std/mcp-v1: tools:call (MCP JSON-RPC tool allowlist)
"""

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def run(args, show=False):
    r = subprocess.run(args, capture_output=True, text=True)
    if show:
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
    if r.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(args)}\n{r.stderr[-800:]}")
    return r.stdout


SCENARIOS = {
    "deploy": {
        "scheme": "std/deploy-v1",
        "claims": [
            {"scheme_id": "std/deploy-v1", "capability": "deploy:apply",
             "parameters": {"environments": ["staging", "dev"], "namespaces": ["web"],
                            "resources": ["deployment"], "max_replicas": 5},
             "rationale": "deploy web to staging/dev, max 5 replicas"},
            {"scheme_id": "std/deploy-v1", "capability": "infra:read",
             "parameters": {"environments": ["staging"]},
             "rationale": "inspect staging state"},
            {"scheme_id": "std/deploy-v1", "capability": "secret:read",
             "parameters": {"secrets": ["api-key-staging"]},
             "rationale": "read staging api key"},
        ],
        "cases": [
            ("D1 deploy to staging", "POST", "/v1/deploy/apply",
             {"environment": "staging", "namespace": "web", "resource": "deployment", "replicas": 3}, 200),
            ("D2 deploy to production", "POST", "/v1/deploy/apply",
             {"environment": "production", "namespace": "web", "replicas": 3}, 403),
            ("D3 namespace out of scope", "POST", "/v1/deploy/apply",
             {"environment": "staging", "namespace": "billing", "replicas": 3}, 403),
            ("D4 replicas over limit", "POST", "/v1/deploy/apply",
             {"environment": "staging", "namespace": "web", "replicas": 9}, 403),
            ("D5 infra staging", "GET", "/v1/infra/read?environment=staging", None, 200),
            ("D6 infra production", "GET", "/v1/infra/read?environment=production", None, 403),
            ("D7 allowlisted secret", "GET", "/v1/secrets/read?secret=api-key-staging", None, 200),
            ("D8 non-allowlisted secret", "GET", "/v1/secrets/read?secret=db-root", None, 403),
        ],
    },
    "mcp": {
        "scheme": "std/mcp-v1",
        "claims": [
            {"scheme_id": "std/mcp-v1", "capability": "tools:call",
             "parameters": {"tools": ["read_file", "list_dir"]},
             "rationale": "read project files only"},
        ],
        "cases": [
            ("M1 read_file", "POST", "/mcp",
             {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "read_file", "arguments": {"path": "/a"}}}, 200),
            ("M2 bash", "POST", "/mcp",
             {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "bash", "arguments": {"cmd": "rm -rf /"}}}, 403),
            ("M3 list_dir", "POST", "/mcp",
             {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "list_dir", "arguments": {"path": "/a"}}}, 200),
            ("M4 initialize protocol", "POST", "/mcp",
             {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {}}, 200),
            ("M5 delete_file", "POST", "/mcp",
             {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
              "params": {"name": "delete_file", "arguments": {"path": "/a"}}}, 403),
        ],
    },
}


def main():
    ap = argparse.ArgumentParser(description="deploy/MCP scenario demo")
    ap.add_argument("--scenario", choices=["deploy", "mcp"], required=True)
    ap.add_argument("--agent-id", default="agent-scenario-" + str(int(time.time())))
    ap.add_argument("--schemes-dir", default=os.path.join(HERE, "capdata"))
    ap.add_argument("--ou", default="gateway:llm")
    ap.add_argument("--principal-cert", required=True)
    ap.add_argument("--principal-key", required=True)
    ap.add_argument("--client-config", required=True)
    ap.add_argument("--gateway", default="https://127.0.0.1:9443")
    ap.add_argument("--ca-cert", default="")
    ap.add_argument("--out-dir", default=os.path.join(os.getcwd(), "scenario-demo-out"))
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--pa-authz", action="store_true")
    args = ap.parse_args()
    sc = SCENARIOS[args.scenario]
    os.makedirs(args.out_dir, exist_ok=True)

    claims_path = os.path.join(args.out_dir, "claims-" + args.scenario + ".json")
    json.dump(sc["claims"], open(claims_path, "w"), ensure_ascii=False, indent=2)

    print(f"== 1. gen-capability validation ({sc['scheme']}) ==")
    gen_cap = os.path.join(HERE, "gen-capability")
    if not os.path.exists(gen_cap):
        for cand in (os.path.join(HERE, "..", "register", "cmd", "gen-capability"),
                     "/home/varwof/src/github.com/register/cmd/gen-capability"):
            if os.path.isdir(cand):
                gen_cap = "go run ./cmd/gen-capability"  # from register dir
                break
        else:
            raise SystemExit("gen-capability not found; clone varwof/register and build ./cmd/gen-capability")
    report = run([gen_cap, "-schemes", args.schemes_dir, "-minimal", claims_path])
    # NOTE: the "== 最小权限集合 ==" marker is gen-capability's localized
    # output; keep it as-is for parsing.
    m = re.search(r"== 最小权限集合 ==\n(\[.*\])", report, re.S)
    if not m:
        raise SystemExit("no minimal set")
    minimal_path = os.path.join(args.out_dir, "minimal-" + args.scenario + ".json")
    json.dump(json.loads(m.group(1)), open(minimal_path, "w"), ensure_ascii=False, indent=2)

    print("== 2. Issue AIC ==")
    aic_dir = os.path.join(args.out_dir, "aic")
    os.makedirs(aic_dir, exist_ok=True)
    cmd = ["client", args.client_config, "aic", "issue",
           "--user-cert", args.principal_cert, "--user-key", args.principal_key,
           "--agent", args.agent_id, "--ou", args.ou,
           "--from-claims", minimal_path, "--out", aic_dir]
    if args.pa_authz:
        cmd.append("--pa-authz")
    if args.execute:
        run(cmd)
    else:
        print("  (add --execute) " + " ".join(cmd))
        return

    print("== 3. Gateway enforcement matrix ==")
    ctx = ssl.create_default_context()
    if args.ca_cert:
        ctx.load_verify_locations(args.ca_cert)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    cert = os.path.join(aic_dir, args.agent_id + ".pem")
    jwt_path = os.path.join(args.out_dir, "token.jwt")

    def fresh():
        run(["client", args.client_config, "aic", "jwt", "--cert", cert, "--out", jwt_path])
        return open(jwt_path).read().strip()

    def call(method, path, body):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(args.gateway + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + fresh())
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    ok = 0
    for name, method, path, body, want in sc["cases"]:
        got = call(method, path, body)
        mark = "✅" if got == want else "❌"
        if got == want:
            ok += 1
        print(f"  {mark} {name}: HTTP {got} (want {want})")
    print(f"\nResult: {ok}/{len(sc['cases'])} passed")
    if ok != len(sc["cases"]):
        raise SystemExit("matrix failed")


if __name__ == "__main__":
    main()
