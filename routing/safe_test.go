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
