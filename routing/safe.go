//go:build linux

package routing

import "net/netip"

// SafeClassification is the route classifier result.
type SafeClassification int

const (
	RouteIgnored SafeClassification = iota
	RouteSafe
	RouteUnsafe
)

// ClassifySafeRoute classifies a main-table route for possible replay into the
// safe table. Unsafe routes are excluded because allowing them would create a
// direct leak path around the VPN.
func ClassifySafeRoute(route Route, tunIndex int) SafeClassification {
	if route.Type != RouteTypeUnicast {
		return RouteIgnored
	}
	if !route.Dst.IsValid() {
		return RouteIgnored
	}
	if route.Dst.Bits() == 0 {
		return RouteUnsafe
	}
	if route.LinkIndex == tunIndex {
		return RouteUnsafe
	}
	if len(route.Multipath) > 0 {
		for _, hop := range route.Multipath {
			hopRoute := route
			hopRoute.LinkIndex = hop.LinkIndex
			hopRoute.Gateway = hop.Gateway
			hopRoute.Multipath = nil
			if ClassifySafeRoute(hopRoute, tunIndex) != RouteSafe {
				return RouteUnsafe
			}
		}
		return RouteSafe
	}
	if route.Gateway.IsValid() && !privateOrLocalPrefix(route.Dst) {
		return RouteUnsafe
	}
	return RouteSafe
}

func privateOrLocalPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	for _, allowed := range safeDestinationPrefixes(prefix.Addr()) {
		if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func safeDestinationPrefixes(addr netip.Addr) []netip.Prefix {
	if addr.Is4() {
		return []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("169.254.0.0/16"),
		}
	}
	return []netip.Prefix{
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
	}
}
