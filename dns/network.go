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
		addr, err := resolveDialAddr(dialNetwork, host, port)
		if err != nil {
			return nil, err
		}
		return network.Dial(ctx, dialNetwork, addr)
	}
}

func resolveDialAddr(
	dialNetwork string,
	host string,
	port string,
) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(addr.String(), port), nil
	}

	if _, err := strconv.Atoi(port); err != nil {
		_, lookupErr := gonnect.LookupPortOffline(dialNetwork, port)
		if lookupErr != nil {
			return "", lookupErr
		}
	}

	return "", errors.New("recursive resolver call")
}
