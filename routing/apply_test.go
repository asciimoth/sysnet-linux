//go:build linux

// nolint
package routing

import (
	"errors"
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
	if !hasRoute(adapter.routes, unix.RT_TABLE_MAIN, "10.0.0.0/24") {
		t.Fatal("main table route was deleted")
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
