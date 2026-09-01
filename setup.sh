#!/usr/bin/env bash
# Generate gateway.json from the template using your local CA/cert paths.
# Usage: ./setup.sh --gateway-cert CERT --gateway-key KEY --jwt-ca CA [--port 9443]
set -euo pipefail
CERT=""; KEY=""; JWTCA=""; PORT=9443
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gateway-cert) CERT="$2"; shift 2;;
    --gateway-key)  KEY="$2";  shift 2;;
    --jwt-ca)       JWTCA="$2"; shift 2;;
    --port)         PORT="$2"; shift 2;;
    *) echo "unknown arg $1"; exit 2;;
  esac
done
[[ -n "$CERT" && -n "$KEY" && -n "$JWTCA" ]] || { echo "required: --gateway-cert --gateway-key --jwt-ca"; exit 2; }
sed -e "s|\${GATEWAY_CERT}|$CERT|g" \
    -e "s|\${GATEWAY_KEY}|$KEY|g" \
    -e "s|\${JWT_CA}|$JWTCA|g" \
    -e "s|127.0.0.1:9443|127.0.0.1:$PORT|g" \
    gateway.json.template > gateway.json
echo "gateway.json written (run gateway-http from this directory so relative capdata paths resolve)"
