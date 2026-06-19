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
	if route.Gateway.IsValid() && route.Dst.Addr().IsGlobalUnicast() &&
		!privateOrLocalPrefix(route.Dst) {
		return RouteUnsafe
	}
	return RouteSafe
}

func privateOrLocalPrefix(prefix netip.Prefix) bool {
	addr := prefix.Addr()
	if !addr.IsValid() {
		return false
	}
	return addr.IsPrivate() || addr.IsLinkLocalUnicast()
}
