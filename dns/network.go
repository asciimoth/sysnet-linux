//go:build linux

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/asciimoth/gonnect"
)

func requireDNSNetworks(
	provider string,
	listenNetwork gonnect.Network,
	dialNetwork gonnect.Network,
) error {
	if listenNetwork == nil {
		return fmt.Errorf("%s: %w", provider, errors.New("nil listen network"))
	}
	if dialNetwork == nil {
		return fmt.Errorf("%s: %w", provider, errors.New("nil dial network"))
	}
	return nil
}

func upstreamDNSDial(network gonnect.Network) gonnect.Dial {
	return func(ctx context.Context, dialNetwork, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addr, err := resolveDialAddr(ctx, network, dialNetwork, host, port)
		if err != nil {
			return nil, err
		}
		return network.Dial(ctx, dialNetwork, addr)
	}
}

func resolveDialAddr(
	ctx context.Context,
	network gonnect.Network,
	dialNetwork string,
	host string,
	port string,
) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(addr.String(), port), nil
	}

	if _, err := strconv.Atoi(port); err != nil {
		n, lookupErr := network.LookupPort(ctx, dialNetwork, port)
		if lookupErr != nil {
			return "", lookupErr
		}
		port = strconv.Itoa(n)
	}

	ips, err := network.LookupNetIP(ctx, lookupNetwork(dialNetwork), host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses", host)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

func lookupNetwork(network string) string {
	switch network {
	case "tcp4", "udp4", "ip4":
		return "ip4"
	case "tcp6", "udp6", "ip6":
		return "ip6"
	default:
		return "ip"
	}
}
