//go:build linux

// nolint
package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagerApplyInstallsRoutesAndRules(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.routes = append(adapter.routes, route("192.168.1.0/24"))
	manager := newManagerWithAdapter(adapter)

	config := testConfig()
	config.Strictness = NonStrict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}

	if !hasRoute(adapter.routes, config.VPNTable, "0.0.0.0/0") {
		t.Fatal("VPN default route was not installed")
	}
	if !hasRoute(adapter.routes, config.SafeTable, "192.168.1.0/24") {
		t.Fatal("safe route was not installed")
	}
	if hasPriority(
		adapter.rules,
		config.PriorityBase+ruleOffsetTransitionGuard,
	) {
		t.Fatal("transition guard still installed after successful apply")
	}
	if !hasPriority(adapter.rules, config.PriorityBase+ruleOffsetAppMain) {
		t.Fatal("app bypass rule was not installed")
	}
}

func TestManagerApplySwitchingDeletesStaleRules(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.Strictness = NonStrict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("first Apply error = %v", err)
	}
	config.Mode = ModeInclude
	config.Strictness = Strict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("second Apply error = %v", err)
	}
	if hasPriority(adapter.rules, config.PriorityBase+8) {
		t.Fatal("stale exclude non-strict rule survived mode switch")
	}
	if !hasPriority(adapter.rules, config.PriorityBase+5) {
		t.Fatal("include strict final drop rule missing")
	}
}

func TestManagerApplyReplacesSourceRoutes(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("100.64.0.0/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		},
	}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("first Apply error = %v", err)
	}

	config.SourceRoutes = []SourceRoute{{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      netip.MustParseAddr("100.64.0.2"),
	}}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("second Apply error = %v", err)
	}

	var vpnRoutes []Route
	for _, route := range adapter.routes {
		if route.Table == config.VPNTable {
			vpnRoutes = append(vpnRoutes, route)
		}
	}
	if len(vpnRoutes) != 1 {
		t.Fatalf("VPN routes = %+v, want one replacement route", vpnRoutes)
	}
	if vpnRoutes[0].Dst != netip.MustParsePrefix("0.0.0.0/0") ||
		vpnRoutes[0].PreferredSource != netip.MustParseAddr("100.64.0.2") {
		t.Fatalf("replacement VPN route = %+v", vpnRoutes[0])
	}
}

func TestManagerApplyClearsEntireSourceRoutePolicy(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("100.64.0.0/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		},
	}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("first Apply error = %v", err)
	}

	config.SourceRoutes = []SourceRoute{}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("second Apply error = %v", err)
	}
	var vpnRoutes []Route
	for _, route := range adapter.routes {
		if route.Table == config.VPNTable {
			vpnRoutes = append(vpnRoutes, route)
		}
	}
	if len(vpnRoutes) != 1 ||
		vpnRoutes[0].Dst != netip.MustParsePrefix("0.0.0.0/0") ||
		vpnRoutes[0].PreferredSource.IsValid() {
		t.Fatalf("VPN routes after clearing policy = %+v", vpnRoutes)
	}
	status, ok := manager.Status()
	if !ok {
		t.Fatal("Status ok = false")
	}
	if status.Config.SourceRoutes == nil ||
		len(status.Config.SourceRoutes) != 0 {
		t.Fatalf(
			"status source routes = %#v, want non-nil empty slice",
			status.Config.SourceRoutes,
		)
	}
}

func TestManagerApplyRemovesDisabledSourceRouteFamily(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.Families = BothFamilies
	config.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("::/0"),
			Source:      netip.MustParseAddr("fd00::2"),
		},
		{
			Destination: netip.MustParsePrefix("fd64::/16"),
			Source:      netip.MustParseAddr("fd64::2"),
		},
	}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("first Apply error = %v", err)
	}

	config.Families = FamilySet{IPv4: true}
	config.SourceRoutes = config.SourceRoutes[:1]
	if err := manager.Apply(config); err != nil {
		t.Fatalf("second Apply error = %v", err)
	}
	for _, route := range adapter.routes {
		if route.Family == unix.AF_INET6 &&
			(route.Table == config.VPNTable || route.Table == config.SafeTable) {
			t.Fatalf("disabled IPv6 family left route %+v", route)
		}
	}
	for _, rule := range adapter.rules {
		if rule.Family == unix.AF_INET6 &&
			rule.Priority >= config.PriorityBase &&
			rule.Priority < config.PriorityBase+config.PrioritySpan {
			t.Fatalf("disabled IPv6 family left rule %+v", rule)
		}
	}
}

func TestManagerApplyReconcilesChangedOwnership(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.links[11] = true
	manager := newManagerWithAdapter(adapter)
	oldConfig := testConfig()
	oldConfig.Families = BothFamilies
	oldConfig.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("fd64::/16"),
			Source:      netip.MustParseAddr("fd64::2"),
		},
	}
	if err := manager.Apply(oldConfig); err != nil {
		t.Fatalf("first Apply error = %v", err)
	}

	newConfig := oldConfig
	newConfig.VPNTable = 400
	newConfig.SafeTable = 401
	newConfig.PriorityBase = 200
	newConfig.TUNIndex = 11
	newConfig.Families = FamilySet{IPv4: true}
	newConfig.SourceRoutes = []SourceRoute{{
		Destination: netip.MustParsePrefix("198.51.100.0/24"),
		Source:      netip.MustParseAddr("10.20.0.2"),
	}}
	if err := manager.Apply(newConfig); err != nil {
		t.Fatalf("second Apply error = %v", err)
	}

	assertNoOwnedRoutingState(t, adapter, oldConfig)
	want, err := CompileDesiredState(newConfig, Snapshot{})
	if err != nil {
		t.Fatalf("CompileDesiredState() error = %v", err)
	}
	for _, route := range want.VPNRoutes {
		if !slices.ContainsFunc(adapter.routes, func(got Route) bool {
			return sameRoute(got, route)
		}) {
			t.Fatalf("new VPN route %+v was not installed", route)
		}
	}
	for _, route := range adapter.routes {
		if route.PreferredSource.IsValid() &&
			route.Table != newConfig.VPNTable {
			t.Fatalf("preferred-source route escaped VPN table: %+v", route)
		}
	}
	for _, rule := range want.Rules {
		if !slices.Contains(adapter.rules, rule) {
			t.Fatalf("new rule %+v was not installed", rule)
		}
	}
}

func TestManagerFailedOwnershipChangeRollbackCleansAllState(t *testing.T) {
	adapter := newFakeAdapter()
	externalRoute := route("203.0.113.0/24")
	externalRule := Rule{Family: unix.AF_INET, Priority: 50}
	adapter.routes = append(adapter.routes, externalRoute)
	adapter.rules = append(adapter.rules, externalRule)
	manager := newManagerWithAdapter(adapter)
	oldConfig := testConfig()
	oldConfig.Families = BothFamilies
	oldConfig.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("::/0"),
			Source:      netip.MustParseAddr("fd00::2"),
		},
	}
	if err := manager.Apply(oldConfig); err != nil {
		t.Fatalf("first Apply error = %v", err)
	}

	newConfig := oldConfig
	newConfig.VPNTable = 400
	newConfig.SafeTable = 401
	newConfig.PriorityBase = 200
	newConfig.Families = FamilySet{IPv4: true}
	newConfig.SourceRoutes = []SourceRoute{{
		Destination: netip.MustParsePrefix("100.64.0.0/10"),
		Source:      netip.MustParseAddr("100.64.0.2"),
	}}
	adapter.replaceRouteErr = errBoom
	err := manager.Apply(newConfig)
	if !errors.Is(err, ErrApplyFailedGuardActive) {
		t.Fatalf("second Apply error = %v, want ErrApplyFailedGuardActive", err)
	}
	adapter.replaceRouteErr = nil
	if err := manager.Rollback(newConfig); err != nil {
		t.Fatalf("Rollback error = %v", err)
	}
	assertNoOwnedRoutingState(t, adapter, oldConfig)
	assertNoOwnedRoutingState(t, adapter, newConfig)
	if _, ok := manager.Status(); ok {
		t.Fatal("Status ok = true after rollback")
	}
	if !slices.ContainsFunc(adapter.routes, func(route Route) bool {
		return sameRoute(route, externalRoute)
	}) {
		t.Fatal("rollback removed external main-table route")
	}
	if !slices.Contains(adapter.rules, externalRule) {
		t.Fatal("rollback removed external rule")
	}
}

func assertNoOwnedRoutingState(
	t *testing.T,
	adapter *fakeAdapter,
	config Config,
) {
	t.Helper()
	for _, route := range adapter.routes {
		if route.Table == config.VPNTable || route.Table == config.SafeTable {
			t.Fatalf("owned route remains after reconciliation: %+v", route)
		}
	}
	for _, rule := range adapter.rules {
		if rule.Priority >= config.PriorityBase &&
			rule.Priority < config.PriorityBase+config.PrioritySpan {
			t.Fatalf("owned rule remains after reconciliation: %+v", rule)
		}
	}
}

func TestManagerApplyKeepsDesiredRuleThatMatchesOldGuard(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.Mode = ModeExclude
	config.Strictness = Strict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("first Apply error = %v", err)
	}

	config.PriorityBase -= 4
	if err := manager.Apply(config); err != nil {
		t.Fatalf("second Apply error = %v", err)
	}
	want := Rule{
		Family:   unix.AF_INET,
		Priority: config.PriorityBase + 6,
		Action:   RuleUnreachable,
	}
	if !slices.Contains(adapter.rules, want) {
		t.Fatalf(
			"rules = %+v, want desired final drop %+v",
			adapter.rules,
			want,
		)
	}
}

func TestDeleteOwnedRulesKeepsKernelNormalizedGuard(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	guard := transitionGuard(config, unix.AF_INET)
	normalizedGuard := listedRule(guard)
	stale := normalizedGuard
	stale.Mark = 1
	adapter.rules = []Rule{normalizedGuard, stale}

	if err := manager.deleteOwnedRules(
		config,
		unix.AF_INET,
		[]Rule{guard},
	); err != nil {
		t.Fatalf("deleteOwnedRules() error = %v", err)
	}
	if !slices.Equal(adapter.rules, []Rule{normalizedGuard}) {
		t.Fatalf(
			"rules = %+v, want only normalized guard %+v",
			adapter.rules,
			normalizedGuard,
		)
	}
}

func TestManagerApplyPriorityShiftDoesNotKeepStaleRules(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		strictness Strictness
	}{
		{name: "exclude_strict", mode: ModeExclude, strictness: Strict},
		{name: "exclude_non-strict", mode: ModeExclude, strictness: NonStrict},
		{name: "include_strict", mode: ModeInclude, strictness: Strict},
		{name: "include_non-strict", mode: ModeInclude, strictness: NonStrict},
	}
	for _, test := range tests {
		for _, shift := range []int{-7, -4, -1, 1, 4, 7} {
			t.Run(
				fmt.Sprintf("%s_shift_%+d", test.name, shift),
				func(t *testing.T) {
					adapter := newFakeAdapter()
					manager := newManagerWithAdapter(adapter)
					config := testConfig()
					config.Mode = test.mode
					config.Strictness = test.strictness
					if err := manager.Apply(config); err != nil {
						t.Fatalf("first Apply error = %v", err)
					}

					config.PriorityBase += shift
					if err := manager.Apply(config); err != nil {
						t.Fatalf("second Apply error = %v", err)
					}
					want, err := CompileDesiredState(config, Snapshot{})
					if err != nil {
						t.Fatalf("CompileDesiredState() error = %v", err)
					}
					if len(adapter.rules) != len(want.Rules) {
						t.Fatalf(
							"rules = %+v, want exactly %+v",
							adapter.rules,
							want.Rules,
						)
					}
					for _, rule := range want.Rules {
						if !slices.Contains(adapter.rules, rule) {
							t.Fatalf(
								"rules = %+v, missing %+v",
								adapter.rules,
								rule,
							)
						}
					}
				},
			)
		}
	}
}

func TestManagerApplySwitchesSourceRouteFamily(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.SourceRoutes = []SourceRoute{{
		Destination: netip.MustParsePrefix("100.64.0.0/10"),
		Source:      netip.MustParseAddr("100.64.0.2"),
	}}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("IPv4 Apply error = %v", err)
	}

	config.Families = FamilySet{IPv6: true}
	config.SourceRoutes = []SourceRoute{{
		Destination: netip.MustParsePrefix("fd64::/16"),
		Source:      netip.MustParseAddr("fd64::2"),
	}}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("IPv6 Apply error = %v", err)
	}
	for _, route := range adapter.routes {
		if route.Table != config.VPNTable {
			continue
		}
		if route.Family != unix.AF_INET6 {
			t.Fatalf("IPv4 VPN route survived family switch: %+v", route)
		}
	}
	if !slices.ContainsFunc(adapter.routes, func(route Route) bool {
		return route.Table == config.VPNTable &&
			route.Dst == netip.MustParsePrefix("fd64::/16") &&
			route.PreferredSource == netip.MustParseAddr("fd64::2")
	}) {
		t.Fatal("IPv6 preferred-source route was not installed")
	}
}

func TestManagerStatusCopiesSourceRoutes(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	wantSource := netip.MustParseAddr("10.20.0.2")
	config.SourceRoutes = []SourceRoute{{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      wantSource,
	}}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}

	config.SourceRoutes[0].Source = netip.MustParseAddr("10.20.0.3")
	first, ok := manager.Status()
	if !ok {
		t.Fatal("Status ok = false")
	}
	if first.Config.SourceRoutes[0].Source != wantSource {
		t.Fatalf(
			"stored source = %v, want %v",
			first.Config.SourceRoutes[0].Source,
			wantSource,
		)
	}
	first.Config.SourceRoutes[0].Source = netip.MustParseAddr("10.20.0.4")
	second, ok := manager.Status()
	if !ok || second.Config.SourceRoutes[0].Source != wantSource {
		t.Fatalf("second Status = %+v, %v", second, ok)
	}
}

func TestManagerApplyFailureLeavesTransitionGuard(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.replaceRouteErr = errBoom
	manager := newManagerWithAdapter(adapter)

	err := manager.Apply(testConfig())
	if !errors.Is(err, ErrApplyFailedGuardActive) {
		t.Fatalf("Apply error = %v, want ErrApplyFailedGuardActive", err)
	}
	if !hasPriority(
		adapter.rules,
		testConfig().PriorityBase+ruleOffsetTransitionGuard,
	) {
		t.Fatal("transition guard was not left active after failed apply")
	}
}

func TestManagerApplySecondGuardFailureReportsActiveGuard(t *testing.T) {
	adapter := newFakeAdapter()
	config := testConfig()
	config.Families = BothFamilies
	adapter.addRuleErr = func(rule Rule) error {
		if rule.Priority == config.PriorityBase+ruleOffsetTransitionGuard &&
			rule.Family == unix.AF_INET6 {
			return errBoom
		}
		return nil
	}
	manager := newManagerWithAdapter(adapter)

	err := manager.Apply(config)
	if !errors.Is(err, ErrApplyFailedGuardActive) {
		t.Fatalf("Apply error = %v, want ErrApplyFailedGuardActive", err)
	}
	if !hasPriority(
		adapter.rules,
		config.PriorityBase+ruleOffsetTransitionGuard,
	) {
		t.Fatal("first transition guard was not left active after failed apply")
	}
}

func TestManagerRefreshInstallsAndRemovesTransitionGuard(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.routes = append(adapter.routes, route("192.168.1.0/24"))
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.Strictness = NonStrict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}

	adapter.routes = append(adapter.routes, route("10.44.0.0/24"))
	if err := manager.Refresh(); err != nil {
		t.Fatalf("Refresh error = %v", err)
	}

	if hasPriority(
		adapter.rules,
		config.PriorityBase+ruleOffsetTransitionGuard,
	) {
		t.Fatal("transition guard still installed after successful refresh")
	}
	if !hasRoute(adapter.routes, config.SafeTable, "10.44.0.0/24") {
		t.Fatal("refreshed safe route was not installed")
	}
}

func TestManagerRefreshPreservesSourceRoutes(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("100.64.0.0/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		},
	}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}
	if err := manager.Refresh(); err != nil {
		t.Fatalf("Refresh error = %v", err)
	}

	for _, sourceRoute := range config.SourceRoutes {
		if !slices.ContainsFunc(adapter.routes, func(route Route) bool {
			return route.Table == config.VPNTable &&
				route.Dst == sourceRoute.Destination &&
				route.PreferredSource == sourceRoute.Source
		}) {
			t.Fatalf("source route %+v was not preserved", sourceRoute)
		}
	}
}

func TestManagerRefreshFailureLeavesTransitionGuard(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.routes = append(adapter.routes, route("192.168.1.0/24"))
	manager := newManagerWithAdapter(adapter)
	config := testConfig()
	config.Strictness = NonStrict
	config.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("100.64.0.0/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		},
	}
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}
	before, ok := manager.Status()
	if !ok {
		t.Fatal("Status ok = false before Refresh")
	}
	adapter.replaceRouteErr = errBoom

	err := manager.Refresh()
	if !errors.Is(err, ErrApplyFailedGuardActive) {
		t.Fatalf("Refresh error = %v, want ErrApplyFailedGuardActive", err)
	}
	if !hasPriority(
		adapter.rules,
		config.PriorityBase+ruleOffsetTransitionGuard,
	) {
		t.Fatal("transition guard was not left active after failed refresh")
	}
	after, ok := manager.Status()
	if !ok || !slices.EqualFunc(
		before.VPNRoutes,
		after.VPNRoutes,
		func(a, b Route) bool { return sameRoute(a, b) },
	) {
		t.Fatalf(
			"Status changed after failed Refresh: before=%+v after=%+v",
			before,
			after,
		)
	}
	for _, sourceRoute := range config.SourceRoutes {
		if !slices.ContainsFunc(adapter.routes, func(route Route) bool {
			return route.Table == config.VPNTable &&
				route.Dst == sourceRoute.Destination &&
				route.PreferredSource == sourceRoute.Source
		}) {
			t.Fatalf("failed Refresh changed VPN source route %+v", sourceRoute)
		}
	}
}

func TestManagerRollbackDeletesOwnedRulesAndTablesOnly(t *testing.T) {
	adapter := newFakeAdapter()
	config := testConfig()
	adapter.rules = []Rule{
		{Family: unix.AF_INET, Priority: config.PriorityBase + 1},
		{
			Family:   unix.AF_INET,
			Priority: config.PriorityBase + config.PrioritySpan,
		},
	}
	adapter.routes = []Route{
		{
			Family: unix.AF_INET,
			Table:  config.VPNTable,
			Dst:    netipMust("0.0.0.0/0"),
			Type:   RouteTypeUnicast,
		},
		{
			Family:          unix.AF_INET,
			Table:           config.VPNTable,
			Dst:             netipMust("100.64.0.0/10"),
			PreferredSource: netip.MustParseAddr("100.64.0.2"),
			Type:            RouteTypeUnicast,
		},
		{
			Family: unix.AF_INET,
			Table:  unix.RT_TABLE_MAIN,
			Dst:    netipMust("10.0.0.0/24"),
			Type:   RouteTypeUnicast,
		},
	}
	manager := newManagerWithAdapter(adapter)

	if err := manager.Rollback(config); err != nil {
		t.Fatalf("Rollback error = %v", err)
	}
	if hasPriority(adapter.rules, config.PriorityBase+1) {
		t.Fatal("owned rule was not deleted")
	}
	if !hasPriority(adapter.rules, config.PriorityBase+config.PrioritySpan) {
		t.Fatal("outside-range rule was deleted")
	}
	if hasRoute(adapter.routes, config.VPNTable, "0.0.0.0/0") {
		t.Fatal("VPN table route was not flushed")
	}
	if hasRoute(adapter.routes, config.VPNTable, "100.64.0.0/10") {
		t.Fatal("VPN source route was not flushed")
	}
	if !hasRoute(adapter.routes, unix.RT_TABLE_MAIN, "10.0.0.0/24") {
		t.Fatal("main table route was deleted")
	}
}

func TestManagerRollbackClearsRouteStateFlagsBeforeDelete(t *testing.T) {
	adapter := newFakeAdapter()
	config := testConfig()
	adapter.routes = []Route{
		{
			Family:          unix.AF_INET,
			Table:           config.SafeTable,
			Dst:             netipMust("172.17.0.0/16"),
			PreferredSource: netip.MustParseAddr("172.17.0.1"),
			Flags: unix.RTNH_F_LINKDOWN |
				unix.RTNH_F_DEAD |
				unix.RTNH_F_ONLINK,
			Type: RouteTypeUnicast,
			Multipath: []Nexthop{
				{
					LinkIndex: 2,
					Flags: unix.RTNH_F_UNRESOLVED |
						unix.RTNH_F_TRAP |
						unix.RTNH_F_PERVASIVE,
				},
			},
		},
	}
	adapter.deleteRouteErr = func(route Route) error {
		if route.PreferredSource != netip.MustParseAddr("172.17.0.1") {
			t.Fatalf(
				"delete preferred source = %v, want 172.17.0.1",
				route.PreferredSource,
			)
		}
		if route.Flags != 0 {
			t.Fatalf("delete route flags = %#x, want 0", route.Flags)
		}
		for i, hop := range route.Multipath {
			if hop.Flags != 0 {
				t.Fatalf(
					"delete nexthop %d flags = %#x, want 0",
					i,
					hop.Flags,
				)
			}
		}
		return nil
	}
	manager := newManagerWithAdapter(adapter)

	if err := manager.Rollback(config); err != nil {
		t.Fatalf("Rollback error = %v", err)
	}
	if hasRoute(adapter.routes, config.SafeTable, "172.17.0.0/16") {
		t.Fatal("safe table route was not deleted")
	}
}

func hasPriority(rules []Rule, priority int) bool {
	return slices.ContainsFunc(rules, func(rule Rule) bool {
		return rule.Priority == priority
	})
}

func hasRoute(routes []Route, table int, prefix string) bool {
	dst := netipMust(prefix)
	return slices.ContainsFunc(routes, func(route Route) bool {
		return route.Table == table && route.Dst == dst
	})
}

func netipMust(prefix string) netip.Prefix {
	return netip.MustParsePrefix(prefix)
}
