#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

fuzz_time=${1:-1m}

image="sysnet-linux-privileged-fuzz:latest"
echo "building $image"
docker build \
	-f e2e/fuzz/Dockerfile \
	-t "$image" \
	.

echo "running privileged fuzzing for $fuzz_time"
docker run --rm --privileged \
	-e SYSNET_PRIVILEGED_FUZZ_CONTAINER=1 \
	-e GOMAXPROCS=1 \
	"$image" \
	-run '^$' \
	-fuzz '^FuzzUntrustedInput$' \
	-fuzztime "$fuzz_time" \
	-parallel 1
