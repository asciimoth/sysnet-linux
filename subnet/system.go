package subnet

import (
	"net"
)

type systemNetworks struct {
	ips      []net.IP
	networks []*net.IPNet
}

func newSystemNetworks(addrs []net.Addr) systemNetworks {
	var system systemNetworks
	for _, addr := range addrs {
		ip, network := addrIPNet(addr)
		if ip == nil || network == nil {
			continue
		}
		system.ips = append(system.ips, copyIP(ip))
		system.networks = append(system.networks, copyIPNet(network))
	}
	return system
}

func (s systemNetworks) usesIP(ip net.IP) bool {
	normalized := normalizeIP(ip)
	if normalized == nil {
		return false
	}
	for _, localIP := range s.ips {
		if localIP.Equal(normalized) {
			return true
		}
	}
	return false
}

func (s systemNetworks) usesSubnet(candidate *net.IPNet) bool {
	candidate = normalizeIPNet(candidate)
	if candidate == nil {
		return false
	}

	for _, localIP := range s.ips {
		if sameFamily(candidate.IP, localIP) && candidate.Contains(localIP) {
			return true
		}
	}
	for _, localNetwork := range s.networks {
		if sameSubnet(candidate, localNetwork) {
			return true
		}
		if ignoredBroadOverlapNetwork(localNetwork) {
			continue
		}
		if overlap(candidate, localNetwork) {
			return true
		}
	}
	return false
}

func addrIPNet(addr net.Addr) (net.IP, *net.IPNet) {
	switch addr := addr.(type) {
	case *net.IPNet:
		if addr == nil {
			return nil, nil
		}
		network := normalizeIPNet(addr)
		if network == nil {
			return nil, nil
		}
		ip := normalizeIP(addr.IP)
		if ip == nil {
			return nil, nil
		}
		return ip, network
	case *net.IPAddr:
		if addr == nil {
			return nil, nil
		}
		ip := normalizeIP(addr.IP)
		if ip == nil {
			return nil, nil
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		return ip, &net.IPNet{IP: copyIP(ip), Mask: net.CIDRMask(bits, bits)}
	default:
		return nil, nil
	}
}

func normalizeIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return copyIP(ip4)
	}
	if ip16 := ip.To16(); ip16 != nil {
		return copyIP(ip16)
	}
	return nil
}

func normalizeIPNet(network *net.IPNet) *net.IPNet {
	if network == nil {
		return nil
	}
	ones, bits := network.Mask.Size()
	if ones < 0 || (bits != 32 && bits != 128) {
		return nil
	}

	ip := network.IP
	if bits == 32 {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}
	if ip == nil {
		return nil
	}

	mask := make(net.IPMask, len(network.Mask))
	copy(mask, network.Mask)
	return &net.IPNet{IP: copyIP(ip.Mask(mask)), Mask: mask}
}

func ignoredBroadOverlapNetwork(network *net.IPNet) bool {
	ones, _ := network.Mask.Size()
	return ones < 8
}

func sameSubnet(a, b *net.IPNet) bool {
	onesA, bitsA := a.Mask.Size()
	onesB, bitsB := b.Mask.Size()
	return bitsA == bitsB && onesA == onesB && a.IP.Equal(b.IP)
}

func overlap(a, b *net.IPNet) bool {
	return sameFamily(a.IP, b.IP) && (a.Contains(b.IP) || b.Contains(a.IP))
}

func sameFamily(a, b net.IP) bool {
	return (a.To4() == nil) == (b.To4() == nil)
}

func copyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	copied := make(net.IP, len(ip))
	copy(copied, ip)
	return copied
}

func copyIPNet(network *net.IPNet) *net.IPNet {
	if network == nil {
		return nil
	}
	mask := make(net.IPMask, len(network.Mask))
	copy(mask, network.Mask)
	return &net.IPNet{IP: copyIP(network.IP), Mask: mask}
}
