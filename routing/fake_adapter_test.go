//go:build linux

// nolint
package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/sys/unix"
)

type fakeAdapter struct {
	links map[int]bool

	routes []Route
	rules  []Rule
	ops    []string

	replaceRouteErr error
}

func newFakeAdapter() *fakeAdapter {
	return &fakeAdapter{links: map[int]bool{10: true}}
}

func testConfig() Config {
	config := configForTest()
	config.TUNIndex = 10
	return config
}

func route(prefix string) Route {
	return Route{
		Family:    unix.AF_INET,
		Table:     unix.RT_TABLE_MAIN,
		Dst:       netip.MustParsePrefix(prefix),
		LinkIndex: 2,
		Type:      RouteTypeUnicast,
	}
}

func (f *fakeAdapter) LinkByIndex(index int) error {
	if !f.links[index] {
		return ErrTUNLinkNotFound
	}
	return nil
}

func (f *fakeAdapter) ListRoutes(family, table int) ([]Route, error) {
	var out []Route
	for _, route := range f.routes {
		if route.Family == family && route.Table == table {
			out = append(out, route)
		}
	}
	return cloneRoutes(out), nil
}

func (f *fakeAdapter) ReplaceRoute(route Route) error {
	f.ops = append(
		f.ops,
		fmt.Sprintf("replace-route:%d:%s", route.Table, route.Dst),
	)
	if f.replaceRouteErr != nil {
		return f.replaceRouteErr
	}
	f.routes = appendWithoutRoute(f.routes, route)
	f.routes = append(f.routes, route)
	return nil
}

func (f *fakeAdapter) DeleteRoute(route Route) error {
	f.ops = append(
		f.ops,
		fmt.Sprintf("delete-route:%d:%s", route.Table, route.Dst),
	)
	f.routes = appendWithoutRoute(f.routes, route)
	return nil
}

func (f *fakeAdapter) ListRules(family int) ([]Rule, error) {
	var out []Rule
	for _, rule := range f.rules {
		if rule.Family == family {
			out = append(out, rule)
		}
	}
	return cloneRules(out), nil
}

func (f *fakeAdapter) AddRule(rule Rule) error {
	f.ops = append(f.ops, fmt.Sprintf("add-rule:%d", rule.Priority))
	f.rules = appendWithoutRule(f.rules, rule)
	f.rules = append(f.rules, rule)
	return nil
}

func (f *fakeAdapter) DeleteRule(rule Rule) error {
	f.ops = append(f.ops, fmt.Sprintf("delete-rule:%d", rule.Priority))
	f.rules = appendWithoutRule(f.rules, rule)
	return nil
}

func (f *fakeAdapter) Close() error { return nil }

func appendWithoutRoute(routes []Route, remove Route) []Route {
	return slices.DeleteFunc(routes, func(route Route) bool {
		return sameRoute(route, remove)
	})
}

func appendWithoutRule(rules []Rule, remove Rule) []Rule {
	return slices.DeleteFunc(rules, func(rule Rule) bool {
		return rule == remove
	})
}

func sameRoute(a, b Route) bool {
	if a.Family != b.Family ||
		a.Table != b.Table ||
		a.Dst != b.Dst ||
		a.Gateway != b.Gateway ||
		a.LinkIndex != b.LinkIndex ||
		a.Priority != b.Priority ||
		a.Scope != b.Scope ||
		a.Flags != b.Flags ||
		a.Type != b.Type ||
		len(a.Multipath) != len(b.Multipath) {
		return false
	}
	for i := range a.Multipath {
		if a.Multipath[i] != b.Multipath[i] {
			return false
		}
	}
	return true
}

var errBoom = errors.New("boom")
