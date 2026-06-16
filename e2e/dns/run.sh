#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if [[ $# -eq 0 ]]; then
	cases=(
		direct
		direct-no-upstream
		debian-resolvconf
		debian-resolvconf-no-upstream
		openresolv
		openresolv-no-upstream
		systemd-resolved
		systemd-resolved-no-upstream
	)
else
	cases=("$@")
fi

tmpdir="$(mktemp -d)"
cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT

echo "building debug binary for DNS e2e"
CGO_ENABLED=0 go build -o "$tmpdir/debug" ./cmd/debug

cp "$tmpdir/debug" ./debug
trap 'rm -rf "$tmpdir"; rm -f ./debug' EXIT

for case_name in "${cases[@]}"; do
	flavor="${case_name%-no-upstream}"
	image="sysnet-linux-dns-e2e:${case_name}"
	echo "building $image"
	docker build \
		--build-arg "FLAVOR=$flavor" \
		-f e2e/dns/Dockerfile \
		-t "$image" \
		.

	echo "running DNS e2e case: $case_name"
	docker run --rm --privileged "$image" "$case_name"
done
