#!/usr/bin/env python3
"""
deepseek-capability-aic.py

AI least-privilege capability generation -> AIC issuance, one script.

Flow:
  1. Load register AI_PROMPT_EN.md + a capability spec (capability.json).
  2. Ask DeepSeek (OpenAI-compatible chat API) to produce capability claims
     for the given task.  Without DEEPSEEK_API_KEY it falls back to a local
     mock so the whole pipeline stays runnable offline.
  3. Validate with gen-capability (-grants/-minimal) and print the report.
  4. Fill the AIC request from the minimal set.
  5. Principal signs the DelegationAuthorization (client `aic issue` does the
     DA signature with the user key) and the CA issues the AIC.

Usage:
  DEEPSEEK_API_KEY=sk-... python3 deepseek-capability-aic.py \
      --task "query customers and orders for tenant org-a, read only" \
      --principal-cert /tmp/aic-demo/principal/P.pem \
      --principal-key  /tmp/aic-demo/principal/P-key.pem \
      --client-config  /tmp/aic-demo-client.json \
      --execute

Flags:
  --task TEXT            task description for the agent (required)
  --agent-id TEXT        AIC agent id (default: auto)
  --scheme FILE          capability spec JSON (default: register testdata std/database-v1)
  --prompt FILE          AI_PROMPT_EN.md path
  --schemes-dir DIR      capability data dir for gen-capability validation
  --grants LIST          identity grants for overreach detection (comma separated)
  --ou TEXT              AIC OU for gateway RBAC (default: gateway:llm)
  --principal-cert FILE  PA certificate (user cert)
  --principal-key FILE   PA private key
  --client-config FILE   varwof-cli config JSON (server/ca/client cert/key)
  --api-key KEY          DeepSeek API key (default: env DEEPSEEK_API_KEY)
  --base-url URL         API base (default: https://api.deepseek.com)
  --model NAME           model (default: deepseek-chat)
  --out-dir DIR          output dir (default: ./aic-demo-out)
  --execute              actually run `client aic issue` (default: print command)
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
# Locate the register repo: sibling of this package, else this machine's
# checkout. The package is self-contained for capdata; register is only
# needed for gen-capability and the AI prompt defaults.
def _find_register():
    for cand in (os.path.join(HERE, "..", "register"),
                 "/home/varwof/src/github.com/register"):
        if os.path.isdir(cand):
            return os.path.normpath(cand)
    return "/home/varwof/src/github.com/register"
REGISTER = _find_register()
DEFAULT_SCHEME = os.path.join(
    REGISTER, "testdata", "capability", "std", "database-v1", "v1.json")
DEFAULT_PROMPT = os.path.join(REGISTER, "AI_PROMPT_EN.md")
DEFAULT_SCHEMES = os.path.join(HERE, "capdata")
if not os.path.isdir(DEFAULT_SCHEMES):
    DEFAULT_SCHEMES = "/home/varwof/src/github.com/capability/data"


def load_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def ask_deepseek(prompt, capability_spec, task, api_key, base_url, model):
    """Call the OpenAI-compatible chat API and return raw assistant text."""
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content":
                "Capability specification (JSON):\n"
                + json.dumps(capability_spec, ensure_ascii=False)
                + "\n\nTask: " + task
                + "\n\nOutput ONLY the JSON array of capability claims."},
        ],
        "temperature": 0,
    }).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        })
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.load(resp)
    return data["choices"][0]["message"]["content"]


def mock_claims(task):
    """Offline fallback: a canned claims set that exercises validation
    (one narrow SELECT, one redundant duplicate, one overreach DDL)."""
    return [
        {"scheme_id": "std/database-v1", "capability": "query:SELECT",
         "parameters": {
             "tables": ["customers", "orders"],
             "columns": {"customers": ["id", "name", "email"],
                         "orders": ["id", "amount"]},
             "row_filter": {"customers": {"column": "tenant_id", "op": "=",
                                          "value": "org-a"},
                            "orders": {"column": "tenant_id", "op": "=",
                                       "value": "org-a"}},
             "limit": {"max": 500}},
         "rationale": "Read customers and orders for tenant org-a, max 500 rows"},
        {"scheme_id": "std/database-v1", "capability": "admin:DDL",
         "parameters": {"operations": ["create"], "tables": ["customers"]},
         "rationale": "Overreach: identity does not hold admin grants"},
    ]


def extract_json_array(text):
    """Robustly pull the first JSON array out of an LLM reply."""
    start = text.find("[")
    if start < 0:
        raise SystemExit("No JSON array found in model reply:\n" + text[:400])
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise SystemExit("Unterminated JSON array in model reply")


def run(args, show=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if show:
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
    if r.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(args)}\n{r.stderr[-800:]}")
    return r.stdout


def main():
    ap = argparse.ArgumentParser(
        description="DeepSeek least-privilege capability -> AIC issuance")
    ap.add_argument("--task", required=True)
    ap.add_argument("--agent-id", default="agent-" + str(int(time.time())))
    ap.add_argument("--scheme", default=DEFAULT_SCHEME)
    ap.add_argument("--prompt", default=DEFAULT_PROMPT)
    ap.add_argument("--schemes-dir", default=DEFAULT_SCHEMES_DIR)
    ap.add_argument("--grants", default="std/database-v1:query:SELECT")
    ap.add_argument("--ou", default="gateway:llm")
    ap.add_argument("--principal-cert", default="")
    ap.add_argument("--principal-key", default="")
    ap.add_argument("--client-config", default="")
    ap.add_argument("--api-key", default=os.environ.get("DEEPSEEK_API_KEY", ""))
    ap.add_argument("--base-url", default="https://api.deepseek.com")
    ap.add_argument("--model", default="deepseek-chat")
    ap.add_argument("--out-dir", default=os.path.join(os.getcwd(), "aic-demo-out"))
    ap.add_argument("--execute", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    print("== 1. Load prompt and capability spec ==")
    prompt = load_text(args.prompt)
    spec = load_json(args.scheme)
    print(f"  prompt: {args.prompt}")
    print(f"  scheme: {spec.get('scheme_id')} "
          f"({len(spec.get('capabilities', []))} capabilities)")

    print("\n== 2. AI-generated capability claims ==")
    if args.api_key:
        print(f"  calling {args.base_url} model={args.model} ...")
        raw = ask_deepseek(prompt, spec, args.task, args.api_key,
                           args.base_url, args.model)
        claims = extract_json_array(raw)
        print("  (real DeepSeek reply)")
    else:
        print("  DEEPSEEK_API_KEY not set -> using offline mock claims")
        claims = mock_claims(args.task)

    claims_path = os.path.join(args.out_dir, "claims.json")
    with open(claims_path, "w", encoding="utf-8") as f:
        json.dump(claims, f, ensure_ascii=False, indent=2)
    print(f"  claims saved: {claims_path}")

    print("\n== 3. gen-capability validation (least-privilege guidance) ==")
    gen_cap = os.path.join(HERE, "gen-capability")
    if not os.path.exists(gen_cap):
        cand = os.path.join(REGISTER, "cmd", "gen-capability")
        if os.path.isdir(cand):
            gen_cap = "go run ./cmd/gen-capability"  # run from register dir
        else:
            gen_cap = "go run ./cmd/gen-capability"
    report = run([gen_cap, "-schemes", args.schemes_dir,
                  "-grants", args.grants, "-minimal", claims_path])

    # NOTE: the "== 最小权限集合 ==" marker is gen-capability's localized
    # output; keep it as-is for parsing.
    m = re.search(r"== 最小权限集合 ==\n(\[.*\])", report, re.S)
    if not m:
        raise SystemExit("gen-capability did not emit a minimal set; "
                         "adjust claims/grants")
    minimal = json.loads(m.group(1))
    if not minimal:
        raise SystemExit("minimal capability set is empty")

    caps = [f"{c['scheme_id']}:{c['capability']}" for c in minimal]
    caps_str = " ".join(caps)
    # Save the validated minimal set so `client aic issue --from-claims` can
    # consume it directly (no manual caps/pa string, digest auto-anchored).
    minimal_path = os.path.join(args.out_dir, "minimal-claims.json")
    with open(minimal_path, "w", encoding="utf-8") as f:
        json.dump(minimal, f, ensure_ascii=False, indent=2)
    print(f"\n== 4. AIC request (capability list) ==")
    print(f"  agent_id : {args.agent_id}")
    print(f"  ou       : {args.ou}")
    print(f"  caps     : {caps_str}")
    print(f"  claims   : {minimal_path}")

    aic_dir = os.path.join(args.out_dir, "aic")
    os.makedirs(aic_dir, exist_ok=True)
    if args.principal_cert and args.principal_key and args.client_config:
        cmd = [
            "client", args.client_config, "aic", "issue",
            "--user-cert", args.principal_cert,
            "--user-key", args.principal_key,
            "--agent", args.agent_id,
            "--ou", args.ou,
            "--from-claims", minimal_path,
            "--out", aic_dir,
        ]
        print("\n== 5. Principal signs DA -> CA issues AIC ==")
        print("  " + " ".join(cmd))
        if args.execute:
            run(cmd)
            cert = os.path.join(aic_dir, f"{args.agent_id}.pem")
            if os.path.exists(cert):
                print(f"\n  AIC issued: {cert}")
                print("  verify: client <config> cert show --cert " + cert)
        else:
            print("\n  (add --execute to run; client binary must be in PATH)")
    else:
        print("\n== 5. Principal signs DA -> CA issues AIC ==")
        print("  skip: pass --principal-cert/--principal-key/--client-config")
        print("  (and --execute) to run issuance")


if __name__ == "__main__":
    main()
