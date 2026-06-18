// Package subnet provides Linux-aware wrappers around gonnect subnet
// allocation.
package subnet

import (
	"net"

	gonnectsubnet "github.com/asciimoth/gonnect/subnet"
)

// IPFilter decides whether an IP address may be allocated.
type IPFilter = gonnectsubnet.IPFilter

// SubnetFilter decides whether a subnet may be allocated.
type SubnetFilter = gonnectsubnet.SubnetFilter

// DefaultAllocatorConfig configures NewDefaultAllocator.
type DefaultAllocatorConfig = gonnectsubnet.DefaultAllocatorConfig

// CombinedAllocator allocates both subnets and IP addresses.
type CombinedAllocator = gonnectsubnet.CombinedAllocator

// NewDefaultAllocator creates a gonnect default allocator that avoids address
// space currently used by local network interfaces.
//
// The returned allocator wraps config.IPFilter and config.SubnetFilter. A nil
// caller filter is treated as allowing all candidates that pass the system
// checks.
//
// IP candidates are rejected when the same address is assigned to any local
// network interface.
//
// Subnet candidates are rejected when they exactly match a local interface
// network, when they contain any local interface address, or when they overlap
// a local interface network. Only the overlap check ignores local interface
// networks broader than /8, because networks such as 0.0.0.0/0 and ::/0 are
// too broad to be useful blockers and would collide with almost every
// allocation.
//
// The local interface state is checked for each candidate allocation try. If
// interface enumeration fails, the allocator falls back to the caller-provided
// filters only for that candidate.
func NewDefaultAllocator(config DefaultAllocatorConfig) *CombinedAllocator {
	return newDefaultAllocatorWithAddrProvider(config, interfaceAddrs)
}

func newDefaultAllocatorWithAddrs(
	config DefaultAllocatorConfig,
	addrs []net.Addr,
) *CombinedAllocator {
	system := newSystemNetworks(addrs)
	config.IPFilter = wrapIPFilter(config.IPFilter, system)
	config.SubnetFilter = wrapSubnetFilter(config.SubnetFilter, system)
	return gonnectsubnet.NewDefaultAllocator(config)
}

type interfaceAddrProvider func() ([]net.Addr, error)

func newDefaultAllocatorWithAddrProvider(
	config DefaultAllocatorConfig,
	provider interfaceAddrProvider,
) *CombinedAllocator {
	config.IPFilter = wrapDynamicIPFilter(config.IPFilter, provider)
	config.SubnetFilter = wrapDynamicSubnetFilter(config.SubnetFilter, provider)
	return gonnectsubnet.NewDefaultAllocator(config)
}

func wrapIPFilter(
	filter IPFilter,
	system systemNetworks,
) IPFilter {
	return func(ip net.IP) bool {
		if system.usesIP(ip) {
			return false
		}
		return filter == nil || filter(ip)
	}
}

func wrapSubnetFilter(
	filter SubnetFilter,
	system systemNetworks,
) SubnetFilter {
	return func(network *net.IPNet) bool {
		if system.usesSubnet(network) {
			return false
		}
		return filter == nil || filter(network)
	}
}

func wrapDynamicIPFilter(
	filter IPFilter,
	provider interfaceAddrProvider,
) IPFilter {
	return func(ip net.IP) bool {
		system, ok := currentSystemNetworks(provider)
		if ok && system.usesIP(ip) {
			return false
		}
		return filter == nil || filter(ip)
	}
}

func wrapDynamicSubnetFilter(
	filter SubnetFilter,
	provider interfaceAddrProvider,
) SubnetFilter {
	return func(network *net.IPNet) bool {
		system, ok := currentSystemNetworks(provider)
		if ok && system.usesSubnet(network) {
			return false
		}
		return filter == nil || filter(network)
	}
}

func currentSystemNetworks(
	provider interfaceAddrProvider,
) (systemNetworks, bool) {
	if provider == nil {
		return systemNetworks{}, false
	}
	addrs, err := provider()
	if err != nil {
		return systemNetworks{}, false
	}
	return newSystemNetworks(addrs), true
}

func interfaceAddrs() ([]net.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var addrs []net.Addr
	for _, iface := range ifaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, ifaceAddrs...)
	}
	return addrs, nil
}
