// nolint
package routing

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestClassifySafeRoute(t *testing.T) {
	const tunIndex = 9

	tests := []struct {
		name  string
		route Route
		want  SafeClassification
	}{
		{
			name:  "default IPv4 route is unsafe",
			route: routeWithDst(unix.AF_INET, "0.0.0.0/0"),
			want:  RouteUnsafe,
		},
		{
			name:  "default IPv6 route is unsafe",
			route: routeWithDst(unix.AF_INET6, "::/0"),
			want:  RouteUnsafe,
		},
		{
			name:  "direct RFC1918 route is safe",
			route: routeWithDst(unix.AF_INET, "192.168.1.0/24"),
			want:  RouteSafe,
		},
		{
			name:  "Docker bridge route is safe",
			route: routeWithDst(unix.AF_INET, "172.17.0.0/16"),
			want:  RouteSafe,
		},
		{
			name:  "IPv6 link local route is safe",
			route: routeWithDst(unix.AF_INET6, "fe80::/64"),
			want:  RouteSafe,
		},
		{
			name:  "IPv6 ULA route is safe",
			route: routeWithDst(unix.AF_INET6, "fd00::/8"),
			want:  RouteSafe,
		},
		{
			name: "public route via gateway is unsafe",
			route: routeWithGateway(
				unix.AF_INET,
				"203.0.113.0/24",
				"192.168.1.1",
			),
			want: RouteUnsafe,
		},
		{
			name:  "public route without gateway is safe",
			route: routeWithDst(unix.AF_INET, "203.0.113.0/24"),
			want:  RouteSafe,
		},
		{
			name: "route through owned TUN is unsafe",
			route: Route{
				Family:    unix.AF_INET,
				Dst:       netip.MustParsePrefix("10.0.0.0/24"),
				LinkIndex: tunIndex,
				Type:      RouteTypeUnicast,
			},
			want: RouteUnsafe,
		},
		{
			name: "multipath route with unsafe nexthop is unsafe",
			route: Route{
				Family: unix.AF_INET,
				Dst:    netip.MustParsePrefix("198.51.100.0/24"),
				Type:   RouteTypeUnicast,
				Multipath: []Nexthop{
					{LinkIndex: 2},
					{
						LinkIndex: 3,
						Gateway:   netip.MustParseAddr("192.168.1.1"),
					},
				},
			},
			want: RouteUnsafe,
		},
		{
			name: "unsupported type is ignored",
			route: Route{
				Family: unix.AF_INET,
				Dst:    netip.MustParsePrefix("10.0.0.0/24"),
				Type:   RouteTypeUnsupported,
			},
			want: RouteIgnored,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifySafeRoute(tt.route, tunIndex)
			if got != tt.want {
				t.Fatalf("ClassifySafeRoute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifySafeRouteChecksWholeGatewayPrefix(t *testing.T) {
	tests := []struct {
		prefix string
		want   SafeClassification
	}{
		{"10.0.0.0/8", RouteSafe},
		{"10.0.0.0/7", RouteUnsafe},
		{"172.16.0.0/12", RouteSafe},
		{"172.16.0.0/11", RouteUnsafe},
		{"192.168.0.0/16", RouteSafe},
		{"192.168.0.0/15", RouteUnsafe},
		{"169.254.0.0/16", RouteSafe},
		{"169.254.0.0/15", RouteUnsafe},
		{"0.0.0.0/1", RouteUnsafe},
		{"fc00::/7", RouteSafe},
		{"fc00::/6", RouteUnsafe},
		{"fe80::/10", RouteSafe},
		{"fe80::/9", RouteUnsafe},
		{"::/1", RouteUnsafe},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			prefix := netip.MustParsePrefix(test.prefix)
			gateway := "192.168.1.1"
			family := unix.AF_INET
			if prefix.Addr().Is6() {
				gateway = "fe80::1"
				family = unix.AF_INET6
			}
			route := routeWithGateway(family, test.prefix, gateway)
			if got := ClassifySafeRoute(route, 9); got != test.want {
				t.Fatalf("ClassifySafeRoute() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestClassifySafeRouteKeepsConnectedPublicPrefix(t *testing.T) {
	route := routeWithDst(unix.AF_INET, "203.0.113.0/24")
	if got := ClassifySafeRoute(route, 9); got != RouteSafe {
		t.Fatalf("connected route = %v, want safe", got)
	}
}

func routeWithDst(family int, dst string) Route {
	return Route{
		Family:    family,
		Dst:       netip.MustParsePrefix(dst),
		LinkIndex: 2,
		Type:      RouteTypeUnicast,
	}
}

func routeWithGateway(family int, dst, gateway string) Route {
	route := routeWithDst(family, dst)
	route.Gateway = netip.MustParseAddr(gateway)
	return route
}
