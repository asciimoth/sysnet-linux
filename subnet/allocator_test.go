// nolint
package subnet

import (
	"errors"
	"net"
	"testing"
)

func TestNewDefaultAllocatorRejectsLocalInterfaceIP(t *testing.T) {
	reference := NewDefaultAllocator(DefaultAllocatorConfig{})
	localIP, _ := reference.AllocIP4()
	if localIP == nil {
		t.Fatal("reference AllocIP4() returned nil")
	}

	alloc := newDefaultAllocatorWithAddrs(
		DefaultAllocatorConfig{},
		[]net.Addr{ipAddr(localIP)},
	)

	got, _ := alloc.AllocIP4()
	if got == nil {
		t.Fatal("AllocIP4() returned nil")
	}
	if got.Equal(localIP) {
		t.Fatalf(
			"AllocIP4() = %v, want address other than local %v",
			got,
			localIP,
		)
	}
}

func TestNewDefaultAllocatorRejectsLocalInterfaceSubnet(t *testing.T) {
	localSubnet := mustCIDR(t, "10.200.0.0/16")

	alloc := newDefaultAllocatorWithAddrs(
		DefaultAllocatorConfig{
			SubnetFilter: func(candidate *net.IPNet) bool {
				return candidate.String() == localSubnet.String()
			},
		},
		[]net.Addr{mustCIDR(t, "10.200.0.10/16")},
	)

	if got := alloc.AllocSubnet4(16); got != nil {
		t.Fatalf("AllocSubnet4(16) = %v, want nil for local subnet", got)
	}
}

func TestNewDefaultAllocatorChecksLocalInterfacesDuringSubnetAllocation(
	t *testing.T,
) {
	localSubnet := mustCIDR(t, "10.200.0.0/16")
	var calls int

	alloc := newDefaultAllocatorWithAddrProvider(
		DefaultAllocatorConfig{
			SubnetFilter: func(candidate *net.IPNet) bool {
				return candidate.String() == localSubnet.String()
			},
		},
		func() ([]net.Addr, error) {
			calls++
			return []net.Addr{mustCIDR(t, "10.200.0.10/16")}, nil
		},
	)

	if calls != 0 {
		t.Fatalf(
			"interface provider called during construction, want allocation-time checks",
		)
	}
	if got := alloc.AllocSubnet4(16); got != nil {
		t.Fatalf("AllocSubnet4(16) = %v, want nil for local subnet", got)
	}
	if calls == 0 {
		t.Fatal("interface provider was not called during subnet allocation")
	}
}

func TestDynamicSubnetFilterRefreshesLocalInterfacesForEachTry(t *testing.T) {
	localSubnet := mustCIDR(t, "10.200.0.0/16")
	calls := 0
	filter := wrapDynamicSubnetFilter(
		nil,
		func() ([]net.Addr, error) {
			calls++
			if calls == 1 {
				return nil, nil
			}
			return []net.Addr{mustCIDR(t, "10.200.0.10/16")}, nil
		},
	)

	if !filter(localSubnet) {
		t.Fatal(
			"first subnet filter call rejected subnet, want allowed before interface appears",
		)
	}
	if filter(localSubnet) {
		t.Fatal(
			"second subnet filter call allowed subnet after interface appeared",
		)
	}
}

func TestDynamicSubnetFilterFallsBackToProvidedFilterOnInterfaceError(
	t *testing.T,
) {
	var called bool
	filter := wrapDynamicSubnetFilter(
		func(*net.IPNet) bool {
			called = true
			return false
		},
		func() ([]net.Addr, error) {
			return nil, errors.New("interface enumeration failed")
		},
	)

	if filter(mustCIDR(t, "10.200.0.0/16")) {
		t.Fatal("subnet filter returned true, want caller rejection")
	}
	if !called {
		t.Fatal("caller subnet filter was not called after interface error")
	}
}

func TestWrappedFiltersStillCallProvidedFilters(t *testing.T) {
	t.Run("ip", func(t *testing.T) {
		var called bool
		filter := wrapIPFilter(func(net.IP) bool {
			called = true
			return false
		}, newSystemNetworks(nil))

		if filter(net.ParseIP("10.0.0.1")) {
			t.Fatal("IP filter returned true, want caller rejection")
		}
		if !called {
			t.Fatal("caller IP filter was not called")
		}
	})

	t.Run("subnet", func(t *testing.T) {
		var called bool
		filter := wrapSubnetFilter(func(*net.IPNet) bool {
			called = true
			return false
		}, newSystemNetworks(nil))

		if filter(mustCIDR(t, "10.0.0.0/24")) {
			t.Fatal("subnet filter returned true, want caller rejection")
		}
		if !called {
			t.Fatal("caller subnet filter was not called")
		}
	})
}

func TestWrappedFiltersDoNotCallProvidedFiltersForLocalCandidates(
	t *testing.T,
) {
	t.Run("ip", func(t *testing.T) {
		var called bool
		filter := wrapIPFilter(func(net.IP) bool {
			called = true
			return true
		}, newSystemNetworks([]net.Addr{ipAddr(net.ParseIP("10.0.0.1"))}))

		if filter(net.ParseIP("10.0.0.1")) {
			t.Fatal("IP filter returned true for local address")
		}
		if called {
			t.Fatal("caller IP filter was called for rejected local address")
		}
	})

	t.Run("subnet", func(t *testing.T) {
		var called bool
		filter := wrapSubnetFilter(func(*net.IPNet) bool {
			called = true
			return true
		}, newSystemNetworks([]net.Addr{mustCIDR(t, "10.5.0.8/24")}))

		if filter(mustCIDR(t, "10.5.0.0/24")) {
			t.Fatal("subnet filter returned true for local subnet")
		}
		if called {
			t.Fatal("caller subnet filter was called for rejected local subnet")
		}
	})
}

func TestSystemNetworksUseSubnet(t *testing.T) {
	system := newSystemNetworks([]net.Addr{
		mustCIDR(t, "10.20.30.40/24"),
		mustCIDR(t, "2001:db8:1::10/64"),
	})

	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{
			name: "same IPv4 local network",
			cidr: "10.20.30.0/24",
			want: true,
		},
		{
			name: "contains IPv4 local address",
			cidr: "10.20.0.0/16",
			want: true,
		},
		{
			name: "overlaps IPv4 local network",
			cidr: "10.20.30.128/25",
			want: true,
		},
		{
			name: "separate IPv4 network",
			cidr: "10.20.31.0/24",
			want: false,
		},
		{
			name: "same IPv6 local network",
			cidr: "2001:db8:1::/64",
			want: true,
		},
		{
			name: "contains IPv6 local address",
			cidr: "2001:db8:1::/48",
			want: true,
		},
		{
			name: "separate IPv6 network",
			cidr: "2001:db8:2::/64",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := system.usesSubnet(mustCIDR(t, tt.cidr)); got != tt.want {
				t.Fatalf("usesSubnet(%s) = %v, want %v", tt.cidr, got, tt.want)
			}
		})
	}
}

func TestSystemNetworksIgnoreBroadSubnetsForOverlapOnly(t *testing.T) {
	system := newSystemNetworks([]net.Addr{
		mustCIDR(t, "0.0.0.0/0"),
		mustCIDR(t, "::/0"),
		mustCIDR(t, "10.0.0.1/7"),
	})

	if system.usesSubnet(mustCIDR(t, "10.9.0.0/16")) {
		t.Fatal(
			"IPv4 subnet rejected only because it overlaps a broad local subnet",
		)
	}
	if system.usesSubnet(mustCIDR(t, "fd00:1::/64")) {
		t.Fatal(
			"IPv6 subnet rejected only because it overlaps a broad local subnet",
		)
	}
	if !system.usesSubnet(mustCIDR(t, "0.0.0.0/0")) {
		t.Fatal("exact 0.0.0.0/0 local subnet match was not rejected")
	}
	if !system.usesSubnet(mustCIDR(t, "::/0")) {
		t.Fatal("exact ::/0 local subnet match was not rejected")
	}
	if !system.usesSubnet(mustCIDR(t, "10.0.0.0/7")) {
		t.Fatal("exact broad local subnet match was not rejected")
	}
}

func TestSystemNetworksUsesPrefixEightForOverlap(t *testing.T) {
	system := newSystemNetworks([]net.Addr{
		mustCIDR(t, "10.0.0.1/8"),
	})

	if !system.usesSubnet(mustCIDR(t, "10.9.0.0/16")) {
		t.Fatal("IPv4 subnet overlapping local /8 was not rejected")
	}
}

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return network
}

func ipAddr(ip net.IP) net.Addr {
	return &net.IPAddr{IP: ip}
}
