#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

tmpdir="$(mktemp -d)"
cleanup() {
	rm -rf "$tmpdir"
	rm -f ./system-e2e
}
trap cleanup EXIT

echo "building system e2e binary"
CGO_ENABLED=0 go build -o "$tmpdir/system-e2e" ./e2e/system

cp "$tmpdir/system-e2e" ./system-e2e

image="sysnet-linux-system-e2e:latest"
echo "building $image"
docker build \
	-f e2e/system/Dockerfile \
	-t "$image" \
	.

echo "running system e2e"
docker run --rm --privileged "$image"
