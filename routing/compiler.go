//go:build linux

package routing

import (
	"cmp"
	"slices"

	"golang.org/x/sys/unix"
)

// CompileDesiredState turns a validated config and main-table snapshot into a
// deterministic desired state. It does not mutate kernel state.
func CompileDesiredState(
	config Config,
	snapshot Snapshot,
) (DesiredState, error) {
	if err := config.validate(); err != nil {
		return DesiredState{}, err
	}

	state := DesiredState{Config: config}
	for _, family := range familyConstants(config.Families) {
		state.Rules = append(state.Rules, compileRules(config, family)...)
		state.VPNRoutes = append(state.VPNRoutes, Route{
			Family:    family,
			Table:     config.VPNTable,
			Dst:       familyDefaultPrefix(family),
			LinkIndex: config.TUNIndex,
			Type:      RouteTypeUnicast,
		})
	}

	for _, route := range snapshot.MainRoutes {
		if !familyEnabled(config.Families, route.Family) {
			continue
		}
		if ClassifySafeRoute(route, config.TUNIndex) != RouteSafe {
			continue
		}
		state.SafeRoutes = append(
			state.SafeRoutes,
			safeTableRoute(route, config.SafeTable),
		)
	}
	sortSafeRoutesForInstall(state.SafeRoutes)
	return state, nil
}

func safeTableRoute(route Route, table int) Route {
	copied := route
	copied.Table = table
	copied.Flags = desiredNexthopFlags(route.Flags)
	if len(route.Multipath) > 0 {
		copied.Multipath = append([]Nexthop(nil), route.Multipath...)
		for i := range copied.Multipath {
			copied.Multipath[i].Flags = desiredNexthopFlags(
				copied.Multipath[i].Flags,
			)
		}
	}
	return copied
}

func desiredNexthopFlags(flags int) int {
	// Kernel route snapshots can include transient nexthop state such as
	// LINKDOWN, DEAD, UNRESOLVED, OFFLOAD, and TRAP. Only replay caller-owned
	// route intent into the safe table.
	return flags & (unix.RTNH_F_ONLINK | unix.RTNH_F_PERVASIVE)
}

func sortSafeRoutesForInstall(routes []Route) {
	slices.SortStableFunc(routes, func(a, b Route) int {
		if aDepends, bDepends := routeDependsOnGateway(
			a,
		), routeDependsOnGateway(
			b,
		); aDepends != bDepends {
			if aDepends {
				return 1
			}
			return -1
		}
		if n := cmp.Compare(a.Family, b.Family); n != 0 {
			return n
		}
		if n := a.Dst.Addr().Compare(b.Dst.Addr()); n != 0 {
			return n
		}
		return cmp.Compare(a.Dst.Bits(), b.Dst.Bits())
	})
}

func routeDependsOnGateway(route Route) bool {
	if route.Gateway.IsValid() {
		return true
	}
	for _, hop := range route.Multipath {
		if hop.Gateway.IsValid() {
			return true
		}
	}
	return false
}

func compileRules(config Config, family int) []Rule {
	nextPriority := config.PriorityBase + ruleOffsetUserFirst
	rules := []Rule{
		markRule(
			family,
			config.PriorityBase+ruleOffsetAppMain,
			RuleLookup,
			unix.RT_TABLE_MAIN,
			config.AppBypassMark,
			config.AppBypassMask,
		),
		markRule(
			family,
			config.PriorityBase+ruleOffsetAppUnreachable,
			RuleUnreachable,
			0,
			config.AppBypassMark,
			config.AppBypassMask,
		),
	}

	add := func(rule Rule) {
		rule.Priority = nextPriority
		nextPriority++
		rules = append(rules, rule)
	}
	all := func(action RuleAction, table int) Rule {
		return Rule{Family: family, Action: action, Table: table}
	}
	user := func(action RuleAction, table int) Rule {
		return Rule{
			Family: family,
			Action: action,
			Table:  table,
			Mark:   config.UserMark,
			Mask:   config.UserMarkMask,
		}
	}

	switch {
	case config.Mode == ModeExclude && config.Strictness == Strict:
		add(user(RuleLookup, unix.RT_TABLE_MAIN))
		add(user(RuleUnreachable, 0))
		add(all(RuleLookup, config.VPNTable))
		add(all(RuleUnreachable, 0))
	case config.Mode == ModeExclude && config.Strictness == NonStrict:
		add(user(RuleLookup, unix.RT_TABLE_MAIN))
		add(user(RuleUnreachable, 0))
		add(all(RuleLookup, config.SafeTable))
		add(all(RuleLookup, config.VPNTable))
		add(all(RuleUnreachable, 0))
	case config.Mode == ModeInclude && config.Strictness == Strict:
		add(user(RuleLookup, config.VPNTable))
		add(user(RuleUnreachable, 0))
		add(all(RuleUnreachable, 0))
	case config.Mode == ModeInclude && config.Strictness == NonStrict:
		add(all(RuleLookup, config.SafeTable))
		add(user(RuleLookup, config.VPNTable))
		add(user(RuleUnreachable, 0))
		add(all(RuleLookup, unix.RT_TABLE_MAIN))
	}
	return rules
}

func markRule(
	family, priority int,
	action RuleAction,
	table int,
	mark, mask uint32,
) Rule {
	return Rule{
		Family:   family,
		Priority: priority,
		Action:   action,
		Table:    table,
		Mark:     mark,
		Mask:     mask,
	}
}

func transitionGuard(config Config, family int) Rule {
	return Rule{
		Family:   family,
		Priority: config.PriorityBase + ruleOffsetTransitionGuard,
		Action:   RuleUnreachable,
	}
}

// TransitionGuardRules returns the temporary fail-closed guards for config.
func TransitionGuardRules(config Config) ([]Rule, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	rules := make([]Rule, 0, 2)
	for _, family := range familyConstants(config.Families) {
		rules = append(rules, transitionGuard(config, family))
	}
	return rules, nil
}

func familyEnabled(families FamilySet, family int) bool {
	return (family == unix.AF_INET && families.IPv4) ||
		(family == unix.AF_INET6 && families.IPv6)
}
