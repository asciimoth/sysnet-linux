# DNS Docker e2e tests

These tests run the real `cmd/debug` binary with the `dns` subcommand inside
Docker containers. Each container emulates one DNS manager setup and asserts
that `DnsMode` selects the matching `DNSProvider` implementation:

- `direct`: plain `/etc/resolv.conf`, expected mode `direct`.
- `direct-no-upstream`: plain `/etc/resolv.conf` with no nameservers,
  expected mode `direct`.
- `debian-resolvconf`: resolvconf-owned file with Debian resolvconf installed,
  expected mode `debian-resolvconf`.
- `debian-resolvconf-no-upstream`: Debian resolvconf-owned file with no
  nameservers, expected mode `debian-resolvconf`.
- `openresolv`: resolvconf-owned file with openresolv installed, expected mode
  `openresolv`.
- `openresolv-no-upstream`: openresolv-owned file with no nameservers, expected
  mode `openresolv`.
- `systemd-resolved`: D-Bus plus systemd-resolved with `/etc/resolv.conf`
  pointing at `127.0.0.53`, expected mode `systemd-resolved`.
- `systemd-resolved-no-upstream`: systemd-resolved with no configured link or
  global DNS servers, expected mode `systemd-resolved`.
- `systemd-resolved-split`: systemd-resolved with two route-only domains on
  separate links, expected mode `systemd-resolved`.

Every case starts a deterministic DNS upstream, then starts `debug dns`. In the
regular cases that server is configured as the original upstream. In
`*-no-upstream` cases it is passed to the DNSProvider constructor as a fallback
address, while the emulated host DNS manager reports no original upstreams.
Most cases use `127.0.0.54:53`; `systemd-resolved` uses the container's `eth0`
address because resolved rejects loopback DNS servers on a non-loopback link.
The test runs `dig` through the system resolver and expects the debug binary to
log the request and return the upstream answer `203.0.113.10`. That proves both
detection and provider setup worked: normal system DNS traffic was redirected
to the debug DNS server, while provider forwarding still used either the
original upstream or the constructor fallback.
The split resolved case uses two upstreams with different answers and verifies
that `corp.test` and `public.test` requests reach the matching upstream.

The Docker runs are privileged because the debug resolved path creates a TUN
interface and all providers bind or rewrite system DNS state inside the
container.
