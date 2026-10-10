#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

tmpdir="$(mktemp -d)"
cleanup() {
	rm -rf "$tmpdir"
	rm -f ./currentnamespace-e2e
}
trap cleanup EXIT

echo "building current-namespace e2e binary"
CGO_ENABLED=0 go build -o "$tmpdir/currentnamespace-e2e" ./e2e/currentnamespace
cp "$tmpdir/currentnamespace-e2e" ./currentnamespace-e2e

image="sysnet-linux-currentnamespace-e2e:latest"
echo "building $image"
docker build \
	-f e2e/currentnamespace/Dockerfile \
	-t "$image" \
	.

echo "running current-namespace e2e without procfs or CAP_SYS_ADMIN"
docker run --rm --privileged --entrypoint /bin/sh "$image" -c \
	'umount /proc && exec setpriv --bounding-set=-sys_admin -- /usr/local/bin/currentnamespace-e2e'
