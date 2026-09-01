#!/usr/bin/env python3
"""
wallet-demo.py — digital-wallet permission control, end to end.

Flow:
  1. Generate wallet capability claims (DeepSeek if DEEPSEEK_API_KEY is set,
     otherwise a deterministic offline mock).
  2. Validate with gen-capability (scheme version pinned, params checked).
  3. Issue the AIC via `client aic issue --from-claims` (PA from role grants
     with --pa-authz when the role permits the wallet capabilities).
  4. Exchange the AIC for a Bearer AIC-JWT.
  5. Run the gateway enforcement matrix (in-scope 200, out-of-scope 403).

Usage:
  python3 wallet-demo.py \
      --principal-cert principal.pem --principal-key principal.key \
      --client-config client.json [--gateway https://127.0.0.1:9443] \
      [--ca-cert ca.pem] [--out-dir ./wallet-demo-out] [--execute] [--pa-authz]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCHEMES = os.path.join(HERE, "capdata")
if not os.path.isdir(DEFAULT_SCHEMES):
    DEFAULT_SCHEMES = "/home/varwof/src/github.com/capability/data"


def run(args, show=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if show:
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
    if r.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(args)}\n{r.stderr[-800:]}")
    return r.stdout


def mock_claims():
    return [
        {"scheme_id": "std/wallet-v1", "capability": "transfer",
         "parameters": {"assets": ["USDC"], "networks": ["ethereum"],
                        "max_amount_per_tx": 100, "recipients": ["0xVendor"]},
         "rationale": "pay vendor invoice up to 100 USDC"},
        {"scheme_id": "std/wallet-v1", "capability": "balance",
         "parameters": {"assets": ["USDC"]},
         "rationale": "check USDC balance before paying"},
    ]


def ask_deepseek(task, api_key, base_url, model):
    prompt = (
        "You are a zero-trust permissions expert. The task: " + task +
        ".\nOutput ONLY a JSON array of least-privilege std/wallet-v1 claims "
        "with scheme_id/capability/parameters (assets, networks, "
        "max_amount_per_tx, max_amount_daily, recipients)/rationale. "
        "Capabilities: balance, transfer, history.")
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": prompt}],
                       "temperature": 0}).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions", data=body, method="POST",
        headers={"Authorization": "Bearer " + api_key,
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.load(resp)
    text = data["choices"][0]["message"]["content"]
    start = text.find("[")
    return json.loads(text[start:text.rfind("]") + 1])


def main():
    ap = argparse.ArgumentParser(description="Wallet permission demo")
    ap.add_argument("--task", default="pay the vendor 50 USDC and check the USDC balance first")
    ap.add_argument("--agent-id", default="agent-wallet-" + str(int(time.time())))
    ap.add_argument("--schemes-dir", default=DEFAULT_SCHEMES)
    ap.add_argument("--ou", default="gateway:llm")
    ap.add_argument("--principal-cert", required=True)
    ap.add_argument("--principal-key", required=True)
    ap.add_argument("--client-config", required=True)
    ap.add_argument("--gateway", default="https://127.0.0.1:9443")
    ap.add_argument("--ca-cert", default="")
    ap.add_argument("--api-key", default=os.environ.get("DEEPSEEK_API_KEY", ""))
    ap.add_argument("--base-url", default="https://api.deepseek.com")
    ap.add_argument("--model", default="deepseek-chat")
    ap.add_argument("--out-dir", default=os.path.join(os.getcwd(), "wallet-demo-out"))
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--pa-authz", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    print("== 1. Wallet capability claims ==")
    if args.api_key:
        claims = ask_deepseek(args.task, args.api_key, args.base_url, args.model)
        print("  (real DeepSeek)")
    else:
        claims = mock_claims()
        print("  (offline mock)")
    claims_path = os.path.join(args.out_dir, "claims-wallet.json")
    with open(claims_path, "w", encoding="utf-8") as f:
        json.dump(claims, f, ensure_ascii=False, indent=2)

    print("\n== 2. gen-capability validation (least privilege + version pinning) ==")
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
    minimal = json.loads(m.group(1))
    minimal_path = os.path.join(args.out_dir, "minimal-claims-wallet.json")
    with open(minimal_path, "w", encoding="utf-8") as f:
        json.dump(minimal, f, ensure_ascii=False, indent=2)
    caps = " ".join(f"{c['scheme_id']}:{c['capability']}" for c in minimal)
    print(f"  caps: {caps}")

    print("\n== 3. Principal signs DA -> CA issues AIC ==")
    aic_dir = os.path.join(args.out_dir, "aic")
    os.makedirs(aic_dir, exist_ok=True)
    cmd = ["client", args.client_config, "aic", "issue",
           "--user-cert", args.principal_cert,
           "--user-key", args.principal_key,
           "--agent", args.agent_id,
           "--ou", args.ou,
           "--from-claims", minimal_path,
           "--out", aic_dir]
    if args.pa_authz:
        cmd.append("--pa-authz")
    if args.execute:
        run(cmd)
    else:
        print("  (add --execute to issue) " + " ".join(cmd))
        return

    print("\n== 4. Exchange AIC-JWT ==")
    jwt_path = os.path.join(args.out_dir, "wallet.jwt")
    run(["client", args.client_config, "aic", "jwt",
         "--cert", os.path.join(aic_dir, args.agent_id + ".pem"),
         "--out", jwt_path])

    print("\n== 5. Gateway enforcement matrix ==")
    import urllib.error
    import ssl
    ctx = ssl.create_default_context()
    if args.ca_cert:
        ctx.load_verify_locations(args.ca_cert)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    def fresh_token():
        run(["client", args.client_config, "aic", "jwt",
             "--cert", os.path.join(aic_dir, args.agent_id + ".pem"),
             "--out", jwt_path])
        return open(jwt_path).read().strip()

    def call(method, path, body=None, token=""):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(args.gateway + path, data=data, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    cases = [
        ("W1 in-scope transfer", "POST", "/v1/wallet/transfer",
         {"asset": "USDC", "amount": 50, "recipient": "0xVendor", "network": "ethereum"}, 200),
        ("W2 amount over limit", "POST", "/v1/wallet/transfer",
         {"asset": "USDC", "amount": 150, "recipient": "0xVendor"}, 403),
        ("W3 recipient not allowlisted", "POST", "/v1/wallet/transfer",
         {"asset": "USDC", "amount": 50, "recipient": "0xStranger"}, 403),
        ("W4 asset not authorized", "POST", "/v1/wallet/transfer",
         {"asset": "BTC", "amount": 50, "recipient": "0xVendor"}, 403),
        ("W5 balance USDC", "GET", "/v1/wallet/balance?asset=USDC", None, 200),
        ("W6 balance BTC", "GET", "/v1/wallet/balance?asset=BTC", None, 403),
    ]
    ok = 0
    for name, method, path, body, want in cases:
        tok = fresh_token()
        got = call(method, path, body, tok)
        mark = "✅" if got == want else "❌"
        if got == want:
            ok += 1
        print(f"  {mark} {name}: HTTP {got} (want {want})")
    print(f"\nResult: {ok}/{len(cases)} passed")
    if ok != len(cases):
        raise SystemExit("matrix failed")


if __name__ == "__main__":
    main()
