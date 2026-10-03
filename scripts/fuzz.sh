#!/usr/bin/env bash

set -uo pipefail

if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  echo "Fuzzing is disabled in GitHub Actions."
  exit 0
fi

fuzz_time=${FUZZ_TIME:-1m}
packages=(
  .
  ./cmd/debug
  ./connmark
  ./dns
  ./dns/dnsname
  ./dns/resolvconffile
  ./killswitch
  ./routing
  ./subnet
  ./tun
)
pids=()

stop_fuzzers() {
  if ((${#pids[@]} > 0)); then
    kill "${pids[@]}" 2>/dev/null || true
  fi
}
trap stop_fuzzers INT TERM EXIT

echo "Fuzzing ${#packages[@]} packages for a total wall-clock budget of ${fuzz_time}."
for package in "${packages[@]}"; do
  GOMAXPROCS=1 go test "$package" \
    -run '^$' \
    -fuzz '^FuzzUntrustedInput$' \
    -fuzztime "$fuzz_time" \
    -parallel 1 &
  pids+=("$!")
done

if [[ "${FUZZ_PRIVILEGED:-0}" == "1" ]]; then
  echo "Privileged fuzzing is enabled in an isolated Docker container."
  ./e2e/fuzz/run.sh "$fuzz_time" &
  pids+=("$!")
fi

status=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    status=1
  fi
done
pids=()
trap - INT TERM EXIT
exit "$status"
