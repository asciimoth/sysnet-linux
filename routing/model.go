//go:build linux

package routing

import "net/netip"

// RuleAction is the operation performed by a policy rule.
type RuleAction int

const (
	RuleLookup RuleAction = iota
	RuleUnreachable
)

// Rule is the package's normalized policy-rule model.
type Rule struct {
	Family   int
	Priority int
	Action   RuleAction
	Table    int
	Mark     uint32
	Mask     uint32
}

// RouteType describes the subset of kernel route types the classifier accepts.
type RouteType int

const (
	RouteTypeUnicast RouteType = iota
	RouteTypeUnsupported
)

// Nexthop is the normalized subset of multipath nexthop fields relevant to
// safety decisions and route replay.
type Nexthop struct {
	LinkIndex int
	Gateway   netip.Addr
	Flags     int
}

// Route is the package's normalized route model.
type Route struct {
	Family    int
	Table     int
	Dst       netip.Prefix
	Gateway   netip.Addr
	LinkIndex int
	Priority  int
	Scope     int
	Flags     int
	Type      RouteType
	Multipath []Nexthop
}

// Snapshot contains the direct host routing view copied from main.
type Snapshot struct {
	MainRoutes []Route
}

// DesiredState is the complete result of compiling a validated config.
type DesiredState struct {
	Config     Config
	Rules      []Rule
	VPNRoutes  []Route
	SafeRoutes []Route
}

func cloneRules(in []Rule) []Rule {
	out := make([]Rule, len(in))
	copy(out, in)
	return out
}

func cloneRoutes(in []Route) []Route {
	out := make([]Route, len(in))
	for i := range in {
		out[i] = in[i]
		if len(in[i].Multipath) > 0 {
			out[i].Multipath = append([]Nexthop(nil), in[i].Multipath...)
		}
	}
	return out
}
