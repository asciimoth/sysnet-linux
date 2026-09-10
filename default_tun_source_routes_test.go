//go:build linux

//nolint:testpackage // Tests cover package-private option normalization.
package linux

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/sysnet-linux/routing"
)

func TestNormalizeTunSourceRoutes(t *testing.T) {
	v4Source := netip.MustParseAddr("10.20.0.2")
	v6Source := netip.MustParseAddr("2001:db8:1::2")

	got, err := normalizeTunSourceRoutes(
		[]string{"10.20.0.2/24", "2001:db8:1::2/64"},
		[]sysnet.TunSourceRoute{
			{
				Destination: netip.MustParsePrefix("192.0.2.1/24"),
				Source:      v4Source,
			},
			{
				Destination: netip.MustParsePrefix("192.0.2.200/24"),
				Source:      v4Source,
			},
			{
				Destination: netip.MustParsePrefix("fd00:1234::abcd/48"),
				Source:      v6Source,
			},
		},
	)
	if err != nil {
		t.Fatalf("normalizeTunSourceRoutes() error = %v", err)
	}
	want := []routing.SourceRoute{
		{
			Destination: netip.MustParsePrefix("192.0.2.0/24"),
			Source:      v4Source,
		},
		{
			Destination: netip.MustParsePrefix("fd00:1234::/48"),
			Source:      v6Source,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeTunSourceRoutes() = %+v, want %+v", got, want)
	}
}

func TestNormalizeTunSourceRoutesAcceptsLinkLocalSources(t *testing.T) {
	got, err := normalizeTunSourceRoutes(
		[]string{"169.254.10.2/16", "fe80::2/64"},
		[]sysnet.TunSourceRoute{
			{
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
				Source:      netip.MustParseAddr("169.254.10.2"),
			},
			{
				Destination: netip.MustParsePrefix("2001:db8:10::/48"),
				Source:      netip.MustParseAddr("fe80::2"),
			},
		},
	)
	if err != nil {
		t.Fatalf("normalizeTunSourceRoutes() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("normalizeTunSourceRoutes() = %+v, want two routes", got)
	}
}

func TestNormalizeTunSourceRoutesRejectsInvalidPolicy(t *testing.T) {
	v4Source := netip.MustParseAddr("10.20.0.2")
	v6Source := netip.MustParseAddr("2001:db8:1::2")
	tests := []struct {
		name   string
		addrs  []string
		routes []sysnet.TunSourceRoute
	}{
		{
			name:  "invalid destination",
			addrs: []string{"10.20.0.2/32"},
			routes: []sysnet.TunSourceRoute{{
				Source: v4Source,
			}},
		},
		{
			name:  "invalid source",
			addrs: []string{"10.20.0.2/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
			}},
		},
		{
			name:  "unspecified source",
			addrs: []string{"0.0.0.0/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      netip.MustParseAddr("0.0.0.0"),
			}},
		},
		{
			name:  "multicast source",
			addrs: []string{"224.0.0.1/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      netip.MustParseAddr("224.0.0.1"),
			}},
		},
		{
			name:  "broadcast source",
			addrs: []string{"255.255.255.255/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      netip.MustParseAddr("255.255.255.255"),
			}},
		},
		{
			name:  "loopback source",
			addrs: []string{"127.0.0.2/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      netip.MustParseAddr("127.0.0.2"),
			}},
		},
		{
			name:  "mixed families",
			addrs: []string{"2001:db8:1::2/128"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      v6Source,
			}},
		},
		{
			name:  "unassigned source",
			addrs: []string{"10.20.0.3/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      v4Source,
			}},
		},
		{
			name:  "source only contained by assigned prefix",
			addrs: []string{"10.20.0.3/24"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      v4Source,
			}},
		},
		{
			name:  "zoned source",
			addrs: []string{"fe80::2/64"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("::/0"),
				Source:      netip.MustParseAddr("fe80::2%tun0"),
			}},
		},
		{
			name:  "IPv4-mapped source",
			addrs: []string{"::ffff:10.20.0.2/128"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("::/0"),
				Source:      netip.MustParseAddr("::ffff:10.20.0.2"),
			}},
		},
		{
			name:  "IPv4-mapped destination",
			addrs: []string{"2001:db8::2/128"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("::ffff:192.0.2.0/120"),
				Source:      netip.MustParseAddr("2001:db8::2"),
			}},
		},
		{
			name:  "conflicting masked destination",
			addrs: []string{"10.20.0.2/32", "100.64.0.2/32"},
			routes: []sysnet.TunSourceRoute{
				{
					Destination: netip.MustParsePrefix("192.0.2.1/24"),
					Source:      v4Source,
				},
				{
					Destination: netip.MustParsePrefix("192.0.2.200/24"),
					Source:      netip.MustParseAddr("100.64.0.2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeTunSourceRoutes(
				test.addrs,
				test.routes,
			); err == nil {
				t.Fatal("normalizeTunSourceRoutes() error = nil")
			}
		})
	}
}

func TestNormalizeTunSourceRoutesUsesEffectiveFallbackAddress(t *testing.T) {
	addrs, _, err := normalizeTunAddrs(nil, "10.70.0.2/32", "")
	if err != nil {
		t.Fatalf("normalizeTunAddrs() error = %v", err)
	}
	got, err := normalizeTunSourceRoutes(addrs, []sysnet.TunSourceRoute{{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      netip.MustParseAddr("10.70.0.2"),
	}})
	if err != nil {
		t.Fatalf("normalizeTunSourceRoutes() error = %v", err)
	}
	if len(got) != 1 || got[0].Source != netip.MustParseAddr("10.70.0.2") {
		t.Fatalf("normalized source routes = %+v", got)
	}
}

func TestNormalizeTunSourceRoutesPreservesNilAndEmpty(t *testing.T) {
	nilRoutes, err := normalizeTunSourceRoutes(nil, nil)
	if err != nil {
		t.Fatalf("normalizeTunSourceRoutes(nil) error = %v", err)
	}
	if nilRoutes != nil {
		t.Fatalf("normalizeTunSourceRoutes(nil) = %#v, want nil", nilRoutes)
	}
	emptyRoutes, err := normalizeTunSourceRoutes(
		nil,
		[]sysnet.TunSourceRoute{},
	)
	if err != nil {
		t.Fatalf("normalizeTunSourceRoutes(empty) error = %v", err)
	}
	if emptyRoutes == nil || len(emptyRoutes) != 0 {
		t.Fatalf(
			"normalizeTunSourceRoutes(empty) = %#v, want non-nil empty",
			emptyRoutes,
		)
	}
}

func TestBuildDefaultTunSourceRoutesReplaceAndClose(t *testing.T) {
	routingManager := &fakeRouting{}
	factory := &fakeTUNFactory{}
	system, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: routingManager,
		TUNFactory:     factory,
		TunConfig:      &fakeTunConfig{},
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = system.Close() })

	firstRoutes := []sysnet.TunSourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("100.64.1.1/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		},
	}
	first, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:     []string{"10.20.0.2/32", "100.64.0.2/32"},
		SourceRoutes: firstRoutes,
		DnsIP:        "10.20.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	firstRoutes[0].Source = netip.MustParseAddr("100.64.0.2")
	wantFirst := []routing.SourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("100.64.0.0/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		},
	}
	if !reflect.DeepEqual(routingManager.applied.SourceRoutes, wantFirst) {
		t.Fatalf(
			"first source routes = %+v, want %+v",
			routingManager.applied.SourceRoutes,
			wantFirst,
		)
	}

	secondSource := netip.MustParseAddr("100.64.0.2")
	second, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.2/32", "100.64.0.2/32"},
		SourceRoutes: []sysnet.TunSourceRoute{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      secondSource,
		}},
		DnsIP: "10.20.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("rebuild returned the same generation wrapper")
	}
	wantSecond := []routing.SourceRoute{{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      secondSource,
	}}
	if !reflect.DeepEqual(routingManager.applied.SourceRoutes, wantSecond) {
		t.Fatalf(
			"replacement source routes = %+v, want %+v",
			routingManager.applied.SourceRoutes,
			wantSecond,
		)
	}

	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(routingManager.rollback.SourceRoutes, wantSecond) {
		t.Fatalf(
			"rollback source routes = %+v, want %+v",
			routingManager.rollback.SourceRoutes,
			wantSecond,
		)
	}
}

func TestBuildDefaultTunClearsSourceRoutePolicyWithExplicitEmpty(t *testing.T) {
	routingManager := &fakeRouting{}
	factory := &fakeTUNFactory{}
	system, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: routingManager,
		TUNFactory:     factory,
		TunConfig:      &fakeTunConfig{},
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = system.Close() })

	first, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.2/32", "100.64.0.2/32"},
		SourceRoutes: []sysnet.TunSourceRoute{{
			Destination: netip.MustParsePrefix("100.64.0.0/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		}},
		DnsIP: "10.20.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:     []string{"10.20.0.2/32", "100.64.0.2/32"},
		SourceRoutes: []sysnet.TunSourceRoute{},
		DnsIP:        "10.20.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if routingManager.applied.SourceRoutes == nil ||
		len(routingManager.applied.SourceRoutes) != 0 {
		t.Fatalf(
			"applied source routes = %#v, want non-nil empty slice",
			routingManager.applied.SourceRoutes,
		)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("stale Close error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if routingManager.rollback.SourceRoutes == nil ||
		len(routingManager.rollback.SourceRoutes) != 0 {
		t.Fatalf(
			"rollback source routes = %#v, want non-nil empty slice",
			routingManager.rollback.SourceRoutes,
		)
	}

	third, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.2/32"},
		DnsIP:    "10.20.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if routingManager.applied.SourceRoutes != nil {
		t.Fatalf(
			"nil source policy applied as %#v",
			routingManager.applied.SourceRoutes,
		)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
	if routingManager.rollback.SourceRoutes != nil {
		t.Fatalf(
			"nil source policy rolled back as %#v",
			routingManager.rollback.SourceRoutes,
		)
	}
}

func TestBuildDefaultTunSourceRouteCallbacksCannotMutateRollback(t *testing.T) {
	routingManager := &fakeRouting{}
	var routingCallback, configuredCallback bool
	system, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: routingManager,
		TUNFactory:     &fakeTUNFactory{},
		TunConfig:      &fakeTunConfig{},
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
		Callbacks: Callbacks{
			RoutingApplied: func(config routing.Config) {
				routingCallback = true
				config.SourceRoutes[0].Source = netip.MustParseAddr(
					"100.64.0.2",
				)
			},
			DefaultTunConfigured: func(
				_ sysnet.DefaultTun,
				opts sysnet.DefaultTunOpts,
			) {
				configuredCallback = true
				opts.SourceRoutes[0].Source = netip.MustParseAddr(
					"100.64.0.2",
				)
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = system.Close() })

	wantSource := netip.MustParseAddr("10.20.0.2")
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.2/32", "100.64.0.2/32"},
		SourceRoutes: []sysnet.TunSourceRoute{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      wantSource,
		}},
		DnsIP: "10.20.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !routingCallback || !configuredCallback {
		t.Fatal("source-route callbacks were not called")
	}
	if err := dt.Close(); err != nil {
		t.Fatal(err)
	}
	if got := routingManager.rollback.SourceRoutes[0].Source; got != wantSource {
		t.Fatalf("rollback source = %v, want %v", got, wantSource)
	}
}

func TestInvalidSourceRouteRebuildPreservesActiveGeneration(t *testing.T) {
	routingManager := &fakeRouting{}
	factory := &fakeTUNFactory{}
	tunConfig := &fakeTunConfig{}
	packetListen := &fakePacketListen{}
	system, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: routingManager,
		TUNFactory:     factory,
		TunConfig:      tunConfig,
		PacketListen:   packetListen.listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = system.Close() })

	first, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.2/32"},
		SourceRoutes: []sysnet.TunSourceRoute{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		}},
		DnsIP: "10.20.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantAddrs := append([]string(nil), tunConfig.addrs[factory.created[0]]...)
	wantRoutes := append([]string(nil), tunConfig.routes[factory.created[0]]...)

	_, err = system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.2/32"},
		SourceRoutes: []sysnet.TunSourceRoute{{
			Destination: netip.MustParsePrefix("100.64.0.0/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		}},
		DnsIP: "10.20.0.2",
	})
	if err == nil {
		t.Fatal("invalid rebuild error = nil")
	}
	if len(factory.created) != 1 || factory.created[0].closed ||
		len(routingManager.appliedConfigs) != 1 ||
		len(packetListen.addrs) != 1 ||
		!reflect.DeepEqual(tunConfig.addrs[factory.created[0]], wantAddrs) ||
		!reflect.DeepEqual(tunConfig.routes[factory.created[0]], wantRoutes) {
		t.Fatal("invalid rebuild changed the active DefaultTun")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if len(routingManager.rollbackConfigs) != 1 ||
		routingManager.rollbackConfigs[0].SourceRoutes[0].Source !=
			netip.MustParseAddr("10.20.0.2") {
		t.Fatalf(
			"rollback configs = %+v, want original source policy",
			routingManager.rollbackConfigs,
		)
	}
}

func TestBuildDefaultTunRejectsSourceRoutesBeforeHostChanges(t *testing.T) {
	routingManager := &fakeRouting{}
	factory := &fakeTUNFactory{}
	tunConfig := &fakeTunConfig{}
	packetListen := &fakePacketListen{}
	system, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: routingManager,
		TUNFactory:     factory,
		TunConfig:      tunConfig,
		PacketListen:   packetListen.listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = system.Close() })

	_, err = system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.3/32"},
		SourceRoutes: []sysnet.TunSourceRoute{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		}},
		DnsIP: "10.20.0.3",
	})
	if err == nil {
		t.Fatal("BuildDefaultTun() error = nil")
	}
	if len(factory.created) != 0 || routingManager.applied != nil ||
		len(packetListen.addrs) != 0 || tunConfig.mtu != nil {
		t.Fatal("invalid source routes changed host-facing components")
	}
}
