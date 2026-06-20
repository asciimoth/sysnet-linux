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

if [[ $# -eq 0 ]]; then
	cases=(direct systemd-resolved)
else
	cases=("$@")
fi

for case_name in "${cases[@]}"; do
	image="sysnet-linux-system-e2e:${case_name}"
	echo "building $image"
	docker build \
		--build-arg "FLAVOR=$case_name" \
		-f e2e/system/Dockerfile \
		-t "$image" \
		.

	echo "running system e2e: $case_name"
	if [[ "$case_name" == "systemd-resolved" ]]; then
		docker run --rm --privileged "$image" systemd-resolved
	else
		docker run --rm --privileged "$image"
	fi
done
