// nolint
package subnet

import (
	"errors"
	"math/rand"
	"net"
	"testing"
)

func FuzzUntrustedInput(f *testing.F) {
	f.Add([]byte{192, 0, 2, 1}, []byte{255, 255, 255, 0})
	f.Add([]byte{0, 1, 2}, []byte{255})
	f.Fuzz(func(t *testing.T, ipBytes, maskBytes []byte) {
		if len(ipBytes) > net.IPv6len {
			ipBytes = ipBytes[:net.IPv6len]
		}
		if len(maskBytes) > net.IPv6len {
			maskBytes = maskBytes[:net.IPv6len]
		}
		ip := net.IP(append([]byte(nil), ipBytes...))
		network := &net.IPNet{
			IP:   ip,
			Mask: net.IPMask(append([]byte(nil), maskBytes...)),
		}
		system := newSystemNetworks([]net.Addr{network, &net.IPAddr{IP: ip}})
		_ = system.usesIP(ip)
		_ = system.usesSubnet(network)
		_, _ = addrIPNet(network)
		_ = normalizeIP(ip)
		_ = normalizeIPNet(network)
		fuzzAllocatorState(ipBytes, maskBytes, network)
	})
}

func fuzzAllocatorState(ipBytes, operations []byte, candidate *net.IPNet) {
	localAddrs := make([]net.Addr, 0, 10)
	for offset := 0; offset < len(ipBytes) && len(localAddrs) < 8; offset += 4 {
		chunk := append(
			[]byte(nil),
			ipBytes[offset:min(offset+4, len(ipBytes))]...)
		if len(chunk) == net.IPv4len {
			ip := net.IPv4(chunk[0], chunk[1], chunk[2], chunk[3])
			localAddrs = append(localAddrs, &net.IPNet{
				IP: ip, Mask: net.CIDRMask(int(chunk[3]%33), 32),
			})
		}
	}
	localAddrs = append(localAddrs, candidate)
	providerCalls := 0
	provider := func() ([]net.Addr, error) {
		providerCalls++
		if len(operations) > 0 && operations[0]&1 != 0 && providerCalls%3 == 0 {
			return nil, errors.New("fuzz interface enumeration failure")
		}
		return localAddrs, nil
	}
	config := DefaultAllocatorConfig{
		Rng: rand.New(
			rand.NewSource(1),
		), //nolint:gosec // Determinism is required.
		IPFilter: func(ip net.IP) bool {
			return len(operations) == 0 || len(ip) == 0 ||
				ip[len(ip)-1]&1 == operations[0]&1
		},
		SubnetFilter: func(network *net.IPNet) bool {
			return network != nil &&
				(len(operations) == 0 || len(network.IP) == 0 ||
					network.IP[len(network.IP)-1]&1 == operations[0]&1)
		},
	}
	allocator := newDefaultAllocatorWithAddrProvider(config, provider)
	var ips []net.IP
	var networks []*net.IPNet
	for _, operation := range operations[:min(len(operations), 32)] {
		switch operation % 10 {
		case 0:
			ip, network := allocator.AllocIP4()
			ips = append(ips, ip)
			networks = append(networks, network)
		case 1:
			ip, network := allocator.AllocIP6()
			ips = append(ips, ip)
			networks = append(networks, network)
		case 2:
			networks = append(
				networks,
				allocator.AllocSubnet4(int(operation%33)),
			)
		case 3:
			networks = append(
				networks,
				allocator.AllocSubnet6(int(operation%129)),
			)
		case 4:
			allocator.ReserveIP(net.IP(append([]byte(nil), ipBytes...)))
		case 5:
			allocator.ReserveSubnet(candidate)
		case 6:
			if len(ips) != 0 {
				allocator.FreeIP(ips[int(operation)%len(ips)])
			}
		case 7:
			if len(networks) != 0 {
				allocator.FreeSubnet(networks[int(operation)%len(networks)])
			}
		case 8:
			allocator.FreeAllIP()
		case 9:
			allocator.FreeAllSubnets()
		}
	}
}
