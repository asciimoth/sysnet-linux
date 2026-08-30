# sysnet-linux

`sysnet-linux` implements the [`sysnet.System`](https://pkg.go.dev/github.com/asciimoth/gonnect/sysnet#System) interface from the [`gonnect`](https://github.com/asciimoth/gonnect) library for Linux.

The primary application for this package is [Almagest](https://github.com/asciimoth/almagest). You can also use it as the Linux backend of another VPN application that needs one cross-platform system-networking abstraction.

> [!WARNING]
> This project is experimental. APIs and behavior can change without notice.
> Do not use it for production systems without your own review and tests.

> [!NOTE]
> Parts of the DNS implementation include code borrowed from the [Tailscale project](https://github.com/tailscale/tailscale).

## Features

- Creates native Linux TUN interfaces.
- Configures TUN names, MTUs, IPv4 and IPv6 addresses, and routes.
- Builds and updates a default-route TUN for full-tunnel VPN operation.
- Uses separate policy-routing tables instead of adding VPN default routes to the main table.
- Supports strict, include, and exclude routing modes.
- Marks VPN transport sockets so that they bypass the VPN and do not create routing loops.
- Mirrors packet marks through conntrack to support reverse-path filtering.
- Controls system DNS and restores the previous configuration when the VPN closes.
- Detects and supports direct `/etc/resolv.conf`, `systemd-resolved`, openresolv, and Debian resolvconf setups.
- Provides process rules for command names, executable paths, command lines, PIDs, users, UIDs, groups, and GIDs.
- Supports socket-owner matching and optional eBPF-based process marking through [`p-mark`](https://github.com/asciimoth/p-mark).
- Integrates with the killswitch daemon through its administration socket.
- Allocates IPv4 and IPv6 addresses and subnets without conflicting with active local interfaces.
- Reports the effective feature set at runtime and degrades optional features when the host does not support them.
- Supports dependency injection for tests and custom integrations.

## Requirements

- Linux
- Go 1.25.5 or later
- `/dev/net/tun` and `CAP_NET_ADMIN` for TUN and routing operations
- Permission to control the selected system DNS service for DNS integration
- nftables support for connection-mark handling
- A mounted BPF filesystem and a configured pin path for process-based TUN rules
- A compatible killswitch daemon for killswitch integration

You do not need all optional integrations. The high-level constructor probes the current environment and disables unavailable features. Always use `Features()` and `ListRules()` to determine what the created system supports.

## Installation

```sh
go get github.com/asciimoth/sysnet-linux
```

The package name is `linux`, so it is useful to use an explicit import alias:

```go
import linux "github.com/asciimoth/sysnet-linux"
```

## Quick start

Use `New` for normal application integration. The zero configuration requests all features and enables the features that are available on the host.

```go
package main

import (
	"log"

	"github.com/asciimoth/gonnect/sysnet"
	linux "github.com/asciimoth/sysnet-linux"
)

func main() {
	var system sysnet.System

	linuxSystem, err := linux.New(linux.SystemConfig{
		Logf: log.Printf,
	})
	if err != nil {
		log.Fatal(err)
	}
	system = linuxSystem
	defer system.Close()

	features := system.Features()
	log.Printf("TUN: %t, default TUN: %t", features.Tun, features.DefaultTun)
}
```

Set `SystemConfig.Pmark.PinPath` to enable process-based include and exclude rules. You can also select a DNS backend, configure packet marks, set a killswitch socket path, and register lifecycle callbacks.

Use `NewSystem` when the application must supply its own DNS provider, routing manager, TUN factory, process marker, killswitch client, or other low-level component. This constructor is also useful for deterministic tests.

## How it fits into a cross-platform VPN

Application code can depend on `gonnect/sysnet.System` instead of Linux-specific networking APIs. Select the platform implementation at the application boundary:

```go
func runVPN(system sysnet.System) error {
	// The VPN core uses the common gonnect sysnet interface.
	return nil
}
```

`sysnet-linux` supplies that interface on Linux. The VPN core can use another `sysnet.System` implementation on each other operating system without changing its main networking logic.

## Packages

- `dns`: system DNS detection, configuration, forwarding, and rollback
- `routing`: fail-closed Linux policy-routing reconciliation
- `tun`: native TUN creation and configuration
- `subnet`: Linux-aware address and subnet allocation
- `connmark`: nftables packet-mark and connection-mark synchronization
- `killswitch`: reconnecting client for temporary killswitch rules

## Development

Run the unit tests:

```sh
go test ./...
```

Run all checks and privileged end-to-end tests with [`just`](https://github.com/casey/just) and Docker:

```sh
just check
```

The end-to-end tests create network interfaces, change routes, and test DNS providers in privileged containers.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
