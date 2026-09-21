//go:build linux

//nolint:testpackage // Tests inspect the effective DefaultTun configuration.
package linux

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	gonnectsubnet "github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
)

func TestNormalizeTunAddrsFallbackHostCollision(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []string
		dnsIP   string
		want    []string
		wantDNS netip.Addr
	}{
		{
			name:    "different prefix lengths",
			addrs:   []string{"10.250.0.1/32"},
			want:    []string{"10.250.0.1/32"},
			wantDNS: netip.MustParseAddr("10.250.0.1"),
		},
		{
			name:    "exact duplicate",
			addrs:   []string{"10.250.0.1/24"},
			want:    []string{"10.250.0.1/24"},
			wantDNS: netip.MustParseAddr("10.250.0.1"),
		},
		{
			name:    "different host in same subnet",
			addrs:   []string{"10.250.0.2/32"},
			want:    []string{"10.250.0.2/32", "10.250.0.1/24"},
			wantDNS: netip.MustParseAddr("10.250.0.1"),
		},
		{
			name: "caller DNS",
			addrs: []string{
				"10.250.0.1/32",
				"192.0.2.1/24",
			},
			dnsIP: "192.0.2.53",
			want: []string{
				"10.250.0.1/32",
				"192.0.2.1/24",
			},
			wantDNS: netip.MustParseAddr("192.0.2.53"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotDNS, err := normalizeTunAddrs(
				test.addrs,
				"10.250.0.1/24",
				test.dnsIP,
			)
			if err != nil {
				t.Fatalf("normalizeTunAddrs error = %v", err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("addresses = %v, want %v", got, test.want)
			}
			if gotDNS != test.wantDNS {
				t.Fatalf("DNS address = %s, want %s", gotDNS, test.wantDNS)
			}
		})
	}
}

func TestDefaultTunFallbackHostCollision(t *testing.T) {
	factory := &fakeTUNFactory{}
	tunConfig := &fakeTunConfig{}
	dnsProvider := newFakeDNSProvider()
	_, ipv4, err := net.ParseCIDR("10.250.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	allocator := gonnectsubnet.NewCombinedAllocator(
		ipv4,
		nil,
		24,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:           true,
			DefaultTun:    true,
			DynTun:        true,
			DynDefaultTun: true,
			DNSControl:    true,
			Routing:       true,
		},
		Allocator:      allocator,
		DNSProvider:    dnsProvider,
		RoutingManager: &fakeRouting{},
		TUNFactory:     factory,
		TunConfig:      tunConfig,
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close test system: %v", err)
		}
	})
	if s.defaultTunCIDR != "10.250.0.1/24" {
		t.Fatalf(
			"reserved DefaultTun address = %s, want 10.250.0.1/24",
			s.defaultTunCIDR,
		)
	}

	opts := sysnet.DefaultTunOpts{TunAddrs: []string{"10.250.0.1/32"}}
	if err := s.VerifyDefaultTunOpts(opts); err != nil {
		t.Fatalf("VerifyDefaultTunOpts error = %v", err)
	}
	dt, err := s.BuildDefaultTun(opts)
	if err != nil {
		t.Fatalf("BuildDefaultTun error = %v", err)
	}
	native := factory.created[0]
	want := []string{"10.250.0.1/32"}
	if got := tunConfig.addrs[native]; !slices.Equal(got, want) {
		t.Fatalf("created DefaultTun addresses = %v, want %v", got, want)
	}
	if got := dnsProvider.setDNS; got != netip.MustParseAddr("10.250.0.1") {
		t.Fatalf("created DefaultTun DNS address = %s, want 10.250.0.1", got)
	}

	if err := s.SetTunAddrs(dt, []string{"10.250.0.2/32"}); err != nil {
		t.Fatalf("SetTunAddrs with different host error = %v", err)
	}
	want = []string{"10.250.0.2/32", "10.250.0.1/24"}
	if got := tunConfig.addrs[native]; !slices.Equal(got, want) {
		t.Fatalf("different-host addresses = %v, want %v", got, want)
	}

	if err := s.SetTunAddrs(dt, []string{"10.250.0.1/32"}); err != nil {
		t.Fatalf("SetTunAddrs with fallback host error = %v", err)
	}
	want = []string{"10.250.0.1/32"}
	if got := tunConfig.addrs[native]; !slices.Equal(got, want) {
		t.Fatalf("updated DefaultTun addresses = %v, want %v", got, want)
	}
	if got := dnsProvider.setDNS; got != netip.MustParseAddr("10.250.0.1") {
		t.Fatalf("updated DefaultTun DNS address = %s, want 10.250.0.1", got)
	}
}
