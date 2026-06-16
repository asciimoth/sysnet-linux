# DNS Docker e2e tests

These tests run the real `cmd/debug` binary with the `dns` subcommand inside
Docker containers. Each container emulates one DNS manager setup and asserts
that `DnsMode` selects the matching `DNSProvider` implementation:

- `direct`: plain `/etc/resolv.conf`, expected mode `direct`.
- `debian-resolvconf`: resolvconf-owned file with Debian resolvconf installed,
  expected mode `debian-resolvconf`.
- `openresolv`: resolvconf-owned file with openresolv installed, expected mode
  `openresolv`.
- `systemd-resolved`: D-Bus plus systemd-resolved with `/etc/resolv.conf`
  pointing at `127.0.0.53`, expected mode `systemd-resolved`.

Every case starts a deterministic original DNS upstream, then starts
`debug dns`. Most cases use `127.0.0.54:53`; `systemd-resolved` uses the
container's `eth0` address because resolved rejects loopback DNS servers on a
non-loopback link. The test runs `dig` through the system resolver and expects
the debug binary to log the request and return the upstream answer
`203.0.113.10`. That proves both detection and provider setup worked: normal
system DNS traffic was redirected to the debug DNS server, while provider
forwarding still used the original upstream.

The Docker runs are privileged because the debug resolved path creates a TUN
interface and all providers bind or rewrite system DNS state inside the
container.
