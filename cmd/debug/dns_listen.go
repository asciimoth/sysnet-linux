// nolint
package main

import (
	"fmt"
	"net"
	"net/netip"
)

func listenDNS(ip netip.Addr) (net.PacketConn, error) {
	addr := net.JoinHostPort(ip.String(), "53")
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp DNS on %s: %w", addr, err)
	}

	tcp, err := net.Listen("tcp4", addr)
	if err == nil {
		_ = tcp.Close()
		return pc, nil
	}
	_ = pc.Close()
	return nil, fmt.Errorf("listen tcp DNS check on %s: %w", addr, err)
}
