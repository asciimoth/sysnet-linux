//go:build linux

package routing

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type netlinkAdapter interface {
	LinkByIndex(index int) error
	ListRoutes(family, table int) ([]Route, error)
	ReplaceRoute(route Route) error
	DeleteRoute(route Route) error
	ListRules(family int) ([]Rule, error)
	AddRule(rule Rule) error
	DeleteRule(rule Rule) error
	Close() error
}

type realAdapter struct {
	handle *netlink.Handle
}

func newRealAdapter() (*realAdapter, error) {
	handle, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("open netlink handle: %w", err)
	}
	return &realAdapter{handle: handle}, nil
}

func (a *realAdapter) LinkByIndex(index int) error {
	_, err := a.handle.LinkByIndex(index)
	if errors.As(err, new(netlink.LinkNotFoundError)) {
		return ErrTUNLinkNotFound
	}
	return err
}

func (a *realAdapter) ListRoutes(family, table int) ([]Route, error) {
	routes, err := a.handle.RouteListFiltered(
		family,
		&netlink.Route{Table: table},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return nil, err
	}
	out := make([]Route, 0, len(routes))
	for _, route := range routes {
		normalized, ok := routeFromNetlink(route)
		if ok {
			out = append(out, normalized)
		}
	}
	return out, nil
}

func (a *realAdapter) ReplaceRoute(route Route) error {
	nlRoute, err := routeToNetlink(route)
	if err != nil {
		return err
	}
	return a.handle.RouteReplace(&nlRoute)
}

func (a *realAdapter) DeleteRoute(route Route) error {
	nlRoute, err := routeToNetlink(route)
	if err != nil {
		return err
	}
	if err := a.handle.RouteDel(
		&nlRoute,
	); err != nil &&
		!errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

func (a *realAdapter) ListRules(family int) ([]Rule, error) {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, ruleFromNetlink(rule))
	}
	return out, nil
}

func (a *realAdapter) AddRule(rule Rule) error {
	nlRule := ruleToNetlink(rule)
	if err := a.handle.RuleAdd(
		&nlRule,
	); err != nil &&
		!errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func (a *realAdapter) DeleteRule(rule Rule) error {
	nlRule := ruleToNetlink(rule)
	if err := a.handle.RuleDel(
		&nlRule,
	); err != nil &&
		!errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

func (a *realAdapter) Close() error {
	a.handle.Close()
	return nil
}

func routeFromNetlink(route netlink.Route) (Route, bool) {
	if route.NewDst != nil || route.Encap != nil || route.Via != nil ||
		route.MPLSDst != nil {
		return Route{Type: RouteTypeUnsupported}, true
	}
	normalized := Route{
		Family:    route.Family,
		Table:     route.Table,
		LinkIndex: route.LinkIndex,
		Priority:  route.Priority,
		Scope:     int(route.Scope),
		Flags:     route.Flags,
		Type:      RouteTypeUnicast,
	}
	if route.Type != 0 && route.Type != unix.RTN_UNICAST {
		normalized.Type = RouteTypeUnsupported
	}
	if route.Dst != nil {
		prefix, ok := prefixFromIPNet(route.Dst)
		if !ok {
			return Route{}, false
		}
		normalized.Dst = prefix
	} else {
		normalized.Dst = familyDefaultPrefix(route.Family)
	}
	if len(route.Gw) > 0 {
		addr, ok := addrFromIP(route.Gw)
		if !ok {
			return Route{}, false
		}
		normalized.Gateway = addr
	}
	for _, hop := range route.MultiPath {
		if hop == nil || hop.NewDst != nil || hop.Encap != nil ||
			hop.Via != nil {
			normalized.Type = RouteTypeUnsupported
			continue
		}
		nh := Nexthop{
			LinkIndex: hop.LinkIndex,
			Flags:     hop.Flags,
		}
		if len(hop.Gw) > 0 {
			addr, ok := addrFromIP(hop.Gw)
			if !ok {
				return Route{}, false
			}
			nh.Gateway = addr
		}
		normalized.Multipath = append(normalized.Multipath, nh)
	}
	return normalized, true
}

func routeToNetlink(route Route) (netlink.Route, error) {
	dst, err := ipNetFromPrefix(route.Dst)
	if err != nil {
		return netlink.Route{}, err
	}
	if route.Scope < 0 || route.Scope > 255 {
		return netlink.Route{}, fmt.Errorf(
			"route scope %d outside netlink uint8 range",
			route.Scope,
		)
	}
	out := netlink.Route{
		Family:    route.Family,
		Table:     route.Table,
		Dst:       dst,
		Gw:        netIPFromAddr(route.Gateway),
		LinkIndex: route.LinkIndex,
		Priority:  route.Priority,
		Scope:     netlink.Scope(route.Scope),
		Flags:     route.Flags,
		Type:      unix.RTN_UNICAST,
	}
	for _, hop := range route.Multipath {
		out.MultiPath = append(out.MultiPath, &netlink.NexthopInfo{
			LinkIndex: hop.LinkIndex,
			Gw:        netIPFromAddr(hop.Gateway),
			Flags:     hop.Flags,
		})
	}
	return out, nil
}

func ruleFromNetlink(rule netlink.Rule) Rule {
	out := Rule{
		Family:   rule.Family,
		Priority: rule.Priority,
		Table:    rule.Table,
		Mark:     rule.Mark,
		Action:   RuleLookup,
	}
	if rule.Mask != nil {
		out.Mask = *rule.Mask
	}
	if rule.Type == unix.FR_ACT_UNREACHABLE {
		out.Action = RuleUnreachable
		out.Table = 0
	}
	return out
}

func ruleToNetlink(rule Rule) netlink.Rule {
	out := *netlink.NewRule()
	out.Family = rule.Family
	out.Priority = rule.Priority
	out.Mark = rule.Mark
	if rule.Mask != 0 {
		mask := rule.Mask
		out.Mask = &mask
	}
	if rule.Action == RuleUnreachable {
		out.Type = unix.FR_ACT_UNREACHABLE
		return out
	}
	out.Table = rule.Table
	return out
}

func prefixFromIPNet(network *net.IPNet) (netip.Prefix, bool) {
	ones, bits := network.Mask.Size()
	if ones < 0 {
		return netip.Prefix{}, false
	}
	addr, ok := addrFromIP(network.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	if bits == 32 {
		addr = addr.Unmap()
	}
	return netip.PrefixFrom(addr, ones).Masked(), true
}

func ipNetFromPrefix(prefix netip.Prefix) (*net.IPNet, error) {
	if !prefix.IsValid() {
		return nil, fmt.Errorf("%w: invalid route prefix", ErrInvalidConfig)
	}
	addr := netIPFromAddr(prefix.Addr())
	bits := 128
	if prefix.Addr().Is4() {
		bits = 32
	}
	return &net.IPNet{
		IP:   addr.Mask(net.CIDRMask(prefix.Bits(), bits)),
		Mask: net.CIDRMask(prefix.Bits(), bits),
	}, nil
}

func addrFromIP(ip net.IP) (netip.Addr, bool) {
	if ip4 := ip.To4(); ip4 != nil {
		addr, ok := netip.AddrFromSlice(ip4)
		return addr, ok
	}
	if ip16 := ip.To16(); ip16 != nil {
		addr, ok := netip.AddrFromSlice(ip16)
		return addr, ok
	}
	return netip.Addr{}, false
}
