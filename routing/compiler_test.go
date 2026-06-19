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
