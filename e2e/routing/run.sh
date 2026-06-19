#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

tmpdir="$(mktemp -d)"
cleanup() {
	rm -rf "$tmpdir"
	rm -f ./routing-e2e
}
trap cleanup EXIT

echo "building routing e2e binary"
CGO_ENABLED=0 go build -o "$tmpdir/routing-e2e" ./e2e/routing

cp "$tmpdir/routing-e2e" ./routing-e2e

image="sysnet-linux-routing-e2e:latest"
echo "building $image"
docker build \
	-f e2e/routing/Dockerfile \
	-t "$image" \
	.

echo "running routing e2e"
docker run --rm --privileged "$image"
