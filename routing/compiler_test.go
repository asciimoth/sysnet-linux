// nolint
package routing

import (
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCompileDesiredStateModeRules(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		strictness Strictness
		want       []Rule
	}{
		{
			name:       "exclude strict",
			mode:       ModeExclude,
			strictness: Strict,
			want: []Rule{
				appLookupRule(100),
				appUnreachableRule(101),
				userLookupRule(103, unix.RT_TABLE_MAIN),
				userUnreachableRule(104),
				plainLookupRule(105, 300),
				plainUnreachableRule(106),
			},
		},
		{
			name:       "exclude non-strict",
			mode:       ModeExclude,
			strictness: NonStrict,
			want: []Rule{
				appLookupRule(100),
				appUnreachableRule(101),
				userLookupRule(103, unix.RT_TABLE_MAIN),
				userUnreachableRule(104),
				plainLookupRule(105, 301),
				plainLookupRule(106, 300),
				plainUnreachableRule(107),
			},
		},
		{
			name:       "include strict",
			mode:       ModeInclude,
			strictness: Strict,
			want: []Rule{
				appLookupRule(100),
				appUnreachableRule(101),
				userLookupRule(103, 300),
				userUnreachableRule(104),
				plainUnreachableRule(105),
			},
		},
		{
			name:       "include non-strict",
			mode:       ModeInclude,
			strictness: NonStrict,
			want: []Rule{
				appLookupRule(100),
				appUnreachableRule(101),
				plainLookupRule(103, 301),
				userLookupRule(104, 300),
				userUnreachableRule(105),
				plainLookupRule(106, unix.RT_TABLE_MAIN),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := compilerTestConfig()
			cfg.Mode = tt.mode
			cfg.Strictness = tt.strictness

			got, err := CompileDesiredState(cfg, Snapshot{})
			if err != nil {
				t.Fatalf("CompileDesiredState() error = %v", err)
			}
			if !reflect.DeepEqual(got.Rules, tt.want) {
				t.Fatalf("rules = %#v, want %#v", got.Rules, tt.want)
			}
		})
	}
}

func TestCompileDesiredStateRoutes(t *testing.T) {
	cfg := compilerTestConfig()
	cfg.Families = BothFamilies
	cfg.Strictness = NonStrict

	safeMainRoute := Route{
		Family:    unix.AF_INET,
		Dst:       netip.MustParsePrefix("10.20.0.0/16"),
		LinkIndex: 2,
		Table:     unix.RT_TABLE_MAIN,
		Priority:  50,
		Type:      RouteTypeUnicast,
	}
	unsafeMainRoute := Route{
		Family:    unix.AF_INET,
		Dst:       netip.MustParsePrefix("0.0.0.0/0"),
		LinkIndex: 2,
		Table:     unix.RT_TABLE_MAIN,
		Scope:     unix.RT_SCOPE_LINK,
		Type:      RouteTypeUnicast,
	}

	got, err := CompileDesiredState(cfg, Snapshot{
		MainRoutes: []Route{safeMainRoute, unsafeMainRoute},
	})
	if err != nil {
		t.Fatalf("CompileDesiredState() error = %v", err)
	}

	wantVPNRoutes := []Route{
		{
			Family:    unix.AF_INET,
			Dst:       netip.MustParsePrefix("0.0.0.0/0"),
			LinkIndex: 7,
			Table:     300,
			Type:      RouteTypeUnicast,
		},
		{
			Family:    unix.AF_INET6,
			Dst:       netip.MustParsePrefix("::/0"),
			LinkIndex: 7,
			Table:     300,
			Type:      RouteTypeUnicast,
		},
	}
	if !reflect.DeepEqual(got.VPNRoutes, wantVPNRoutes) {
		t.Fatalf("VPNRoutes = %#v, want %#v", got.VPNRoutes, wantVPNRoutes)
	}

	safeMainRoute.Table = 301
	if !reflect.DeepEqual(got.SafeRoutes, []Route{safeMainRoute}) {
		t.Fatalf(
			"SafeRoutes = %#v, want %#v",
			got.SafeRoutes,
			[]Route{safeMainRoute},
		)
	}
}

func TestCompileDesiredStateSourceRoutes(t *testing.T) {
	cfg := compilerTestConfig()
	cfg.Families = BothFamilies
	cfg.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("100.64.0.0/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("fd00:64::/48"),
			Source:      netip.MustParseAddr("fd00::2"),
		},
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("::/0"),
			Source:      netip.MustParseAddr("2001:db8::2"),
		},
	}

	got, err := CompileDesiredState(cfg, Snapshot{})
	if err != nil {
		t.Fatalf("CompileDesiredState() error = %v", err)
	}
	want := []Route{
		{
			Family:          unix.AF_INET,
			Table:           cfg.VPNTable,
			Dst:             netip.MustParsePrefix("0.0.0.0/0"),
			PreferredSource: netip.MustParseAddr("10.20.0.2"),
			LinkIndex:       cfg.TUNIndex,
			Type:            RouteTypeUnicast,
		},
		{
			Family:          unix.AF_INET,
			Table:           cfg.VPNTable,
			Dst:             netip.MustParsePrefix("100.64.0.0/10"),
			PreferredSource: netip.MustParseAddr("100.64.0.2"),
			LinkIndex:       cfg.TUNIndex,
			Type:            RouteTypeUnicast,
		},
		{
			Family:          unix.AF_INET6,
			Table:           cfg.VPNTable,
			Dst:             netip.MustParsePrefix("::/0"),
			PreferredSource: netip.MustParseAddr("2001:db8::2"),
			LinkIndex:       cfg.TUNIndex,
			Type:            RouteTypeUnicast,
		},
		{
			Family:          unix.AF_INET6,
			Table:           cfg.VPNTable,
			Dst:             netip.MustParsePrefix("fd00:64::/48"),
			PreferredSource: netip.MustParseAddr("fd00::2"),
			LinkIndex:       cfg.TUNIndex,
			Type:            RouteTypeUnicast,
		},
	}
	if !reflect.DeepEqual(got.VPNRoutes, want) {
		t.Fatalf("VPNRoutes = %#v, want %#v", got.VPNRoutes, want)
	}
}

func TestCompileDesiredStateCopiesSourceRouteConfig(t *testing.T) {
	cfg := compilerTestConfig()
	wantSource := netip.MustParseAddr("10.20.0.2")
	cfg.SourceRoutes = []SourceRoute{{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      wantSource,
	}}

	got, err := CompileDesiredState(cfg, Snapshot{})
	if err != nil {
		t.Fatalf("CompileDesiredState() error = %v", err)
	}
	cfg.SourceRoutes[0].Source = netip.MustParseAddr("10.20.0.3")
	if got.Config.SourceRoutes[0].Source != wantSource {
		t.Fatalf(
			"desired config source = %v, want %v",
			got.Config.SourceRoutes[0].Source,
			wantSource,
		)
	}
}

func TestCompileDesiredStateNestedSourceRoutesAreDeterministic(t *testing.T) {
	cfg := compilerTestConfig()
	cfg.Families = BothFamilies
	cfg.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("10.20.30.0/24"),
			Source:      netip.MustParseAddr("192.0.2.24"),
		},
		{
			Destination: netip.MustParsePrefix("2001:db8:10:20::/64"),
			Source:      netip.MustParseAddr("2001:db8::64"),
		},
		{
			Destination: netip.MustParsePrefix("10.20.30.40/32"),
			Source:      netip.MustParseAddr("192.0.2.32"),
		},
		{
			Destination: netip.MustParsePrefix("2001:db8:10:20::40/128"),
			Source:      netip.MustParseAddr("2001:db8::128"),
		},
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("192.0.2.1"),
		},
		{
			Destination: netip.MustParsePrefix("10.0.0.0/8"),
			Source:      netip.MustParseAddr("192.0.2.8"),
		},
		{
			Destination: netip.MustParsePrefix("2001:db8::/32"),
			Source:      netip.MustParseAddr("2001:db8::32"),
		},
		{
			Destination: netip.MustParsePrefix("10.20.0.0/16"),
			Source:      netip.MustParseAddr("192.0.2.16"),
		},
		{
			Destination: netip.MustParsePrefix("::/0"),
			Source:      netip.MustParseAddr("2001:db8::1"),
		},
		{
			Destination: netip.MustParsePrefix("2001:db8:10::/48"),
			Source:      netip.MustParseAddr("2001:db8::48"),
		},
	}

	first, err := CompileDesiredState(cfg, Snapshot{})
	if err != nil {
		t.Fatalf("CompileDesiredState() error = %v", err)
	}
	for left, right := 0, len(cfg.SourceRoutes)-1; left < right; left, right = left+1, right-1 {
		cfg.SourceRoutes[left], cfg.SourceRoutes[right] =
			cfg.SourceRoutes[right], cfg.SourceRoutes[left]
	}
	second, err := CompileDesiredState(cfg, Snapshot{})
	if err != nil {
		t.Fatalf("CompileDesiredState(reversed) error = %v", err)
	}
	if !reflect.DeepEqual(first.VPNRoutes, second.VPNRoutes) {
		t.Fatalf(
			"route order depends on source policy order:\nfirst = %#v\nsecond = %#v",
			first.VPNRoutes,
			second.VPNRoutes,
		)
	}

	wantDestinations := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("10.20.30.0/24"),
		netip.MustParsePrefix("10.20.30.40/32"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8:10::/48"),
		netip.MustParsePrefix("2001:db8:10:20::/64"),
		netip.MustParsePrefix("2001:db8:10:20::40/128"),
	}
	if len(first.VPNRoutes) != len(wantDestinations) {
		t.Fatalf(
			"VPNRoutes len = %d, want %d",
			len(first.VPNRoutes),
			len(wantDestinations),
		)
	}
	for i, want := range wantDestinations {
		if first.VPNRoutes[i].Dst != want {
			t.Fatalf(
				"VPNRoutes[%d].Dst = %s, want %s",
				i,
				first.VPNRoutes[i].Dst,
				want,
			)
		}
		if first.VPNRoutes[i].LinkIndex != cfg.TUNIndex {
			t.Fatalf(
				"VPNRoutes[%d].LinkIndex = %d, want %d",
				i,
				first.VPNRoutes[i].LinkIndex,
				cfg.TUNIndex,
			)
		}
	}
}

func TestCompileDesiredStateClearsCopiedSafeRouteStateFlags(t *testing.T) {
	cfg := compilerTestConfig()
	cfg.Strictness = NonStrict

	got, err := CompileDesiredState(cfg, Snapshot{
		MainRoutes: []Route{
			{
				Family: unix.AF_INET,
				Dst:    netip.MustParsePrefix("172.17.0.0/16"),
				Table:  unix.RT_TABLE_MAIN,
				Flags: unix.RTNH_F_LINKDOWN |
					unix.RTNH_F_DEAD |
					unix.RTNH_F_ONLINK,
				Type: RouteTypeUnicast,
			},
			{
				Family: unix.AF_INET,
				Dst:    netip.MustParsePrefix("47.47.47.0/24"),
				Table:  unix.RT_TABLE_MAIN,
				Type:   RouteTypeUnicast,
				Multipath: []Nexthop{
					{
						LinkIndex: 2,
						Flags: unix.RTNH_F_LINKDOWN |
							unix.RTNH_F_OFFLOAD |
							unix.RTNH_F_ONLINK,
					},
					{
						LinkIndex: 3,
						Flags: unix.RTNH_F_UNRESOLVED |
							unix.RTNH_F_TRAP |
							unix.RTNH_F_PERVASIVE,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CompileDesiredState() error = %v", err)
	}
	if len(got.SafeRoutes) != 2 {
		t.Fatalf("SafeRoutes = %#v, want 2 routes", got.SafeRoutes)
	}

	connected := safeRouteByPrefix(got.SafeRoutes, "172.17.0.0/16")
	if connected.Flags != unix.RTNH_F_ONLINK {
		t.Fatalf("safe route flags = %#x, want ONLINK only", connected.Flags)
	}

	multipath := safeRouteByPrefix(got.SafeRoutes, "47.47.47.0/24")
	if len(multipath.Multipath) != 2 {
		t.Fatalf("multipath nexthops = %#v, want 2", multipath.Multipath)
	}
	if multipath.Multipath[0].Flags != unix.RTNH_F_ONLINK {
		t.Fatalf(
			"first nexthop flags = %#x, want ONLINK only",
			multipath.Multipath[0].Flags,
		)
	}
	if multipath.Multipath[1].Flags != unix.RTNH_F_PERVASIVE {
		t.Fatalf(
			"second nexthop flags = %#x, want PERVASIVE only",
			multipath.Multipath[1].Flags,
		)
	}
}

func safeRouteByPrefix(routes []Route, prefix string) Route {
	dst := netip.MustParsePrefix(prefix)
	for _, route := range routes {
		if route.Dst == dst {
			return route
		}
	}
	return Route{}
}

func TestCompileDesiredStateInstallsGatewayFreeSafeRoutesFirst(t *testing.T) {
	cfg := compilerTestConfig()
	cfg.Strictness = NonStrict

	gatewayRoute := Route{
		Family:    unix.AF_INET,
		Dst:       netip.MustParsePrefix("10.88.0.0/16"),
		Gateway:   netip.MustParseAddr("192.168.1.1"),
		LinkIndex: 2,
		Table:     unix.RT_TABLE_MAIN,
		Type:      RouteTypeUnicast,
	}
	connectedRoute := Route{
		Family:    unix.AF_INET,
		Dst:       netip.MustParsePrefix("192.168.1.0/24"),
		LinkIndex: 2,
		Table:     unix.RT_TABLE_MAIN,
		Scope:     unix.RT_SCOPE_LINK,
		Type:      RouteTypeUnicast,
	}

	got, err := CompileDesiredState(cfg, Snapshot{
		MainRoutes: []Route{gatewayRoute, connectedRoute},
	})
	if err != nil {
		t.Fatalf("CompileDesiredState() error = %v", err)
	}

	connectedRoute.Table = cfg.SafeTable
	gatewayRoute.Table = cfg.SafeTable
	want := []Route{connectedRoute, gatewayRoute}
	if !reflect.DeepEqual(got.SafeRoutes, want) {
		t.Fatalf("SafeRoutes = %#v, want %#v", got.SafeRoutes, want)
	}
}

func TestTransitionGuardRules(t *testing.T) {
	cfg := compilerTestConfig()
	cfg.Families = BothFamilies

	got, err := TransitionGuardRules(cfg)
	if err != nil {
		t.Fatalf("TransitionGuardRules() error = %v", err)
	}
	want := []Rule{
		{
			Family:   unix.AF_INET,
			Priority: 102,
			Action:   RuleUnreachable,
		},
		{
			Family:   unix.AF_INET6,
			Priority: 102,
			Action:   RuleUnreachable,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TransitionGuardRules() = %#v, want %#v", got, want)
	}
}

func compilerTestConfig() Config {
	return configForTest()
}

func appLookupRule(priority int) Rule {
	return Rule{
		Family:   unix.AF_INET,
		Priority: priority,
		Action:   RuleLookup,
		Table:    unix.RT_TABLE_MAIN,
		Mark:     0x100,
		Mask:     0xff00,
	}
}

func appUnreachableRule(priority int) Rule {
	return Rule{
		Family:   unix.AF_INET,
		Priority: priority,
		Action:   RuleUnreachable,
		Mark:     0x100,
		Mask:     0xff00,
	}
}

func userLookupRule(priority int, table int) Rule {
	return Rule{
		Family:   unix.AF_INET,
		Priority: priority,
		Action:   RuleLookup,
		Table:    table,
		Mark:     0x200,
		Mask:     0xff00,
	}
}

func userUnreachableRule(priority int) Rule {
	return Rule{
		Family:   unix.AF_INET,
		Priority: priority,
		Action:   RuleUnreachable,
		Mark:     0x200,
		Mask:     0xff00,
	}
}

func plainLookupRule(priority int, table int) Rule {
	return Rule{
		Family:   unix.AF_INET,
		Priority: priority,
		Action:   RuleLookup,
		Table:    table,
	}
}

func plainUnreachableRule(priority int) Rule {
	return Rule{
		Family:   unix.AF_INET,
		Priority: priority,
		Action:   RuleUnreachable,
	}
}
