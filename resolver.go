//go:build linux

package linux

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/asciimoth/gonnect"
)

const defaultHostsFile = "/etc/hosts"

var _ gonnect.Resolver = (*localThenDNSResolver)(nil)

// localThenDNSResolver resolves address records from local host data before it
// uses its DNS resolver. Other record types use the DNS resolver directly.
type localThenDNSResolver struct {
	gonnect.Resolver
	hostsFile string
}

func newLocalThenDNSResolver(
	hostsFile string,
	dnsResolver gonnect.Resolver,
) *localThenDNSResolver {
	if hostsFile == "" {
		hostsFile = defaultHostsFile
	}
	return &localThenDNSResolver{
		Resolver:  dnsResolver,
		hostsFile: hostsFile,
	}
}

func (r *localThenDNSResolver) LookupIP(
	ctx context.Context,
	network, host string,
) ([]net.IP, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	addresses, literal, err := lookupLocalHost(r.hostsFile, network, host)
	if err != nil {
		return nil, err
	}
	if literal || len(addresses) != 0 {
		return netIPs(addresses), nil
	}
	if network == "ip" {
		return r.lookupBothDNSFamilies(ctx, host)
	}
	return r.Resolver.LookupIP(ctx, network, host)
}

func (r *localThenDNSResolver) lookupBothDNSFamilies(
	ctx context.Context,
	host string,
) ([]net.IP, error) {
	var addresses []net.IP
	var lookupErr error
	for _, network := range []string{"ip4", "ip6"} {
		ips, err := r.Resolver.LookupIP(ctx, network, host)
		if err != nil {
			lookupErr = err
			if ctx != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		addresses = append(addresses, ips...)
	}
	if len(addresses) != 0 {
		return addresses, nil
	}
	if lookupErr == nil {
		lookupErr = localNoSuchHost(host)
	}
	return nil, lookupErr
}

func (r *localThenDNSResolver) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	addresses := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, net.IPAddr{IP: ip})
	}
	return addresses, nil
}

func (r *localThenDNSResolver) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	ips, err := r.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		address, ok := netip.AddrFromSlice(ip)
		if ok {
			addresses = append(addresses, address.Unmap())
		}
	}
	return addresses, nil
}

func (r *localThenDNSResolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, ip.String())
	}
	return addresses, nil
}

func lookupLocalHost(
	hostsFile, network, host string,
) ([]netip.Addr, bool, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !addressMatchesNetwork(address, network) {
			return nil, true, localNoSuchHost(host)
		}
		return []netip.Addr{address}, true, nil
	}

	name := normalizeHostName(host)
	addresses := make([]netip.Addr, 0, 2)
	seen := make(map[netip.Addr]struct{})
	appendAddress := func(address netip.Addr) {
		address = address.Unmap()
		if !addressMatchesNetwork(address, network) {
			return
		}
		if _, found := seen[address]; found {
			return
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}

	if name == "localhost" {
		appendAddress(netip.AddrFrom4([4]byte{127, 0, 0, 1}))
		appendAddress(netip.IPv6Loopback())
	}

	// #nosec G304 -- HostsFile is an explicit configuration value.
	data, _ := os.ReadFile(hostsFile)
	for line := range strings.SplitSeq(string(data), "\n") {
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		for _, alias := range fields[1:] {
			if normalizeHostName(alias) == name {
				appendAddress(address)
				break
			}
		}
	}
	return addresses, false, nil
}

func normalizeHostName(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func addressMatchesNetwork(address netip.Addr, network string) bool {
	if strings.HasSuffix(network, "4") {
		return address.Is4()
	}
	if strings.HasSuffix(network, "6") {
		return address.Is6()
	}
	return true
}

func localNoSuchHost(host string) *net.DNSError {
	return &net.DNSError{
		Name:       host,
		Err:        "no such host",
		IsNotFound: true,
	}
}

func netIPs(addresses []netip.Addr) []net.IP {
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, net.IP(append([]byte(nil), address.AsSlice()...)))
	}
	return ips
}
