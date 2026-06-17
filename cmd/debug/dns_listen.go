// nolint
package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/asciimoth/gonnect"
)

func listenDNS(
	ctx context.Context,
	listenNetwork gonnect.Network,
	ip netip.Addr,
) (net.PacketConn, error) {
	addr := net.JoinHostPort(ip.String(), "53")
	pc, err := listenNetwork.ListenPacket(ctx, "udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp DNS on %s: %w", addr, err)
	}

	tcp, err := listenNetwork.Listen(ctx, "tcp4", addr)
	if err == nil {
		_ = tcp.Close()
		return pc, nil
	}
	_ = pc.Close()
	return nil, fmt.Errorf("listen tcp DNS check on %s: %w", addr, err)
}
