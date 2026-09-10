//go:build linux

//nolint:testpackage // Tests cover package-private netlink conversions.
package routing

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestRoutePreferredSourceNetlinkRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		family int
		dst    string
		source string
	}{
		{
			name:   "IPv4",
			family: unix.AF_INET,
			dst:    "100.64.0.0/10",
			source: "100.64.0.2",
		},
		{
			name:   "IPv6",
			family: unix.AF_INET6,
			dst:    "2001:db8:64::/48",
			source: "2001:db8::2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := Route{
				Family:          test.family,
				Table:           300,
				Dst:             netip.MustParsePrefix(test.dst),
				PreferredSource: netip.MustParseAddr(test.source),
				LinkIndex:       7,
				Type:            RouteTypeUnicast,
			}

			nlRoute, err := routeToNetlink(want)
			if err != nil {
				t.Fatalf("routeToNetlink() error = %v", err)
			}
			if !nlRoute.Src.Equal(net.ParseIP(test.source)) {
				t.Fatalf(
					"netlink source = %v, want %s",
					nlRoute.Src,
					test.source,
				)
			}

			got, ok := routeFromNetlink(nlRoute)
			if !ok {
				t.Fatal("routeFromNetlink() ok = false")
			}
			if !sameRoute(got, want) {
				t.Fatalf("routeFromNetlink() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestRoutePreferredSourceConversionHandlesAbsentValues(t *testing.T) {
	nlRoute, err := routeToNetlink(Route{
		Family: unix.AF_INET6,
		Table:  300,
		Dst:    netip.MustParsePrefix("::/0"),
		Type:   RouteTypeUnicast,
	})
	if err != nil {
		t.Fatalf("routeToNetlink() error = %v", err)
	}
	if nlRoute.Src != nil {
		t.Fatalf("netlink source = %v, want nil", nlRoute.Src)
	}
	invalidRoute := Route{
		Family:          unix.AF_INET,
		Table:           300,
		Dst:             netip.MustParsePrefix("0.0.0.0/0"),
		PreferredSource: netip.MustParseAddr("0.0.0.0"),
		Type:            RouteTypeUnicast,
	}
	nlRoute, err = routeToNetlink(invalidRoute)
	if err != nil {
		t.Fatalf("routeToNetlink(invalid source) error = %v", err)
	}
	if nlRoute.Src != nil {
		t.Fatalf("invalid netlink source = %v, want nil", nlRoute.Src)
	}

	got, ok := routeFromNetlink(netlink.Route{
		Family: unix.AF_INET6,
		Table:  300,
		Dst: &net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, 128),
		},
	})
	if !ok {
		t.Fatal("routeFromNetlink() ok = false")
	}
	if got.PreferredSource.IsValid() {
		t.Fatalf("preferred source = %v, want invalid", got.PreferredSource)
	}

	got, ok = routeFromNetlink(netlink.Route{
		Family: unix.AF_INET,
		Table:  300,
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		},
		Src: net.IPv4zero,
	})
	if !ok {
		t.Fatal("routeFromNetlink(invalid source) ok = false")
	}
	if got.PreferredSource.IsValid() {
		t.Fatalf(
			"invalid netlink preferred source = %v, want invalid",
			got.PreferredSource,
		)
	}
}

func TestRoutePreferredSourceConversionRejectsFamilyMismatch(t *testing.T) {
	tests := []struct {
		name   string
		family int
		dst    string
		source string
	}{
		{
			name:   "IPv4 route with IPv6 source",
			family: unix.AF_INET,
			dst:    "0.0.0.0/0",
			source: "2001:db8::2",
		},
		{
			name:   "IPv6 route with IPv4 source",
			family: unix.AF_INET6,
			dst:    "::/0",
			source: "192.0.2.2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nlRoute, err := routeToNetlink(Route{
				Family:          test.family,
				Table:           300,
				Dst:             netip.MustParsePrefix(test.dst),
				PreferredSource: netip.MustParseAddr(test.source),
				Type:            RouteTypeUnicast,
			})
			if err != nil {
				t.Fatalf("routeToNetlink() error = %v", err)
			}
			if nlRoute.Src != nil {
				t.Fatalf("netlink source = %v, want nil", nlRoute.Src)
			}

			input := netlink.Route{
				Family: test.family,
				Table:  300,
				Dst:    nlRoute.Dst,
				Src:    net.ParseIP(test.source),
			}
			got, ok := routeFromNetlink(input)
			if !ok {
				t.Fatal("routeFromNetlink() ok = false")
			}
			if got.PreferredSource.IsValid() {
				t.Fatalf(
					"preferred source = %v, want invalid",
					got.PreferredSource,
				)
			}
		})
	}
}

func TestRouteFromNetlinkIgnoresMalformedPreferredSource(t *testing.T) {
	got, ok := routeFromNetlink(netlink.Route{
		Family: unix.AF_INET,
		Table:  300,
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		},
		Src: net.IP{1, 2, 3},
	})
	if !ok {
		t.Fatal("routeFromNetlink() ok = false")
	}
	if got.PreferredSource.IsValid() {
		t.Fatalf("preferred source = %v, want invalid", got.PreferredSource)
	}
}

func TestRouteConversionRejectsIPv4MappedDestination(t *testing.T) {
	prefix := netip.MustParsePrefix("::ffff:192.0.2.0/120")
	if _, err := routeToNetlink(Route{
		Family: unix.AF_INET6,
		Table:  300,
		Dst:    prefix,
		Type:   RouteTypeUnicast,
	}); err == nil {
		t.Fatal("routeToNetlink() error = nil")
	}

	_, ok := routeFromNetlink(netlink.Route{
		Family: unix.AF_INET6,
		Table:  300,
		Dst: &net.IPNet{
			IP:   net.ParseIP("::ffff:192.0.2.0"),
			Mask: net.CIDRMask(120, 128),
		},
	})
	if ok {
		t.Fatal("routeFromNetlink(mapped destination) ok = true")
	}
}

func TestRouteConversionRejectsDestinationFamilyMismatch(t *testing.T) {
	tests := []struct {
		name   string
		family int
		dst    string
	}{
		{
			name:   "IPv4 family with IPv6 destination",
			family: unix.AF_INET,
			dst:    "2001:db8::/32",
		},
		{
			name:   "IPv6 family with IPv4 destination",
			family: unix.AF_INET6,
			dst:    "192.0.2.0/24",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix(test.dst)
			if _, err := routeToNetlink(Route{
				Family: test.family,
				Table:  300,
				Dst:    prefix,
				Type:   RouteTypeUnicast,
			}); err == nil {
				t.Fatal("routeToNetlink() error = nil")
			}
			dst, err := ipNetFromPrefix(prefix)
			if err != nil {
				t.Fatalf("ipNetFromPrefix() error = %v", err)
			}
			if _, ok := routeFromNetlink(netlink.Route{
				Family: test.family,
				Table:  300,
				Dst:    dst,
			}); ok {
				t.Fatal("routeFromNetlink() ok = true")
			}
		})
	}
}

func TestRouteFromNetlinkRejectsDestinationMaskWidthMismatch(t *testing.T) {
	_, ok := routeFromNetlink(netlink.Route{
		Family: unix.AF_INET,
		Table:  300,
		Dst: &net.IPNet{
			IP:   net.ParseIP("2001:db8::"),
			Mask: net.CIDRMask(24, 32),
		},
	})
	if ok {
		t.Fatal("routeFromNetlink() ok = true")
	}
}

func TestSameRouteIncludesPreferredSource(t *testing.T) {
	left := Route{
		Family:          unix.AF_INET,
		Table:           300,
		Dst:             netip.MustParsePrefix("0.0.0.0/0"),
		PreferredSource: netip.MustParseAddr("10.20.0.2"),
		Type:            RouteTypeUnicast,
	}
	right := left
	right.PreferredSource = netip.MustParseAddr("100.64.0.2")
	if sameRoute(left, right) {
		t.Fatal("routes with different preferred sources compare equal")
	}
}
