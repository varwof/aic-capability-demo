#!/usr/bin/env bash
# Build the four binaries needed to run this demo from pinned commits.
# Outputs ./bin/{gen-capability,client,varwof,gateway-http}.
# Requires Go 1.26+ and git. Binaries resolve from published modules (no
# local replaces needed).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEPS="$ROOT/deps"
BIN="$ROOT/bin"
mkdir -p "$DEPS" "$BIN"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOFLAGS=-buildvcs=false

# Pinned commits (README §5)
PIN_TYPES=4868765
PIN_REGISTER=71c0f39
PIN_CLIENT=9dbd21e
PIN_CORE=ed42b00
PIN_GATEWAY_CORE=v0.4.6
PIN_GATEWAY=a35d9c6

clone_pin() {
  local repo="$1" pin="$2"
  if [ ! -d "$DEPS/$repo/.git" ]; then
    git clone --quiet "https://github.com/varwof/$repo.git" "$DEPS/$repo"
  fi
  git -C "$DEPS/$repo" fetch --quiet --tags origin
  git -C "$DEPS/$repo" checkout --quiet "$pin"
}

echo "== cloning varwof ecosystem at pinned commits =="
clone_pin types      "$PIN_TYPES"
clone_pin register   "$PIN_REGISTER"
clone_pin client     "$PIN_CLIENT"
clone_pin core       "$PIN_CORE"
clone_pin gateway-core "$PIN_GATEWAY_CORE"
clone_pin gateway    "$PIN_GATEWAY"

echo "== build gen-capability (register) =="
(cd "$DEPS/register" && go build -o "$BIN/gen-capability" ./cmd/gen-capability)
echo "== build client =="
(cd "$DEPS/client" && go build -o "$BIN/client" .)
echo "== build core (varwof) =="
(cd "$DEPS/core" && go build -o "$BIN/varwof" ./cmd/pki)
echo "== build gateway-http =="
(cd "$DEPS/gateway" && go build -o "$BIN/gateway-http" ./cmd/http)

echo
echo "done. Add ./bin to your PATH and follow QUICKSTART.md:"
echo "  export PATH=\"$BIN:\$PATH\""
