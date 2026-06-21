//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	defaultTunMTU = 1420
	minTunMTU     = 576
)

// SetTunMTU updates MTU of provided Tun.
//
// The Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is
// returned. Values lower than the IPv4 minimum MTU are replaced with a sensible
// default of 1420 bytes.
func SetTunMTU(tun gtun.Tun, mtu int) error {
	if mtu < minTunMTU {
		mtu = defaultTunMTU
	}

	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetMTU(info.link, mtu); err != nil {
		return fmt.Errorf("set MTU of %s: %w", info.name, err)
	}
	return nil
}

// SetTunAddrs updates list off addrs of provided Tun.
//
// Existing interface addresses are removed before the new CIDR addresses are
// added. The Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is
// returned.
func SetTunAddrs(tun gtun.Tun, addrs []string) error {
	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	prefixes, err := parseTunAddrPrefixes(addrs)
	if err != nil {
		return err
	}

	current, err := netlink.AddrList(info.link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, addr := range current {
		if err := netlink.AddrDel(info.link, &addr); err != nil {
			return err
		}
	}
	for i, prefix := range prefixes {
		addr, err := netlinkAddrFromPrefix(prefix)
		if err != nil {
			return err
		}
		if err := netlink.AddrReplace(info.link, addr); err != nil {
			return fmt.Errorf("update address %s: %w", addrs[i], err)
		}
	}
	return nil
}

// AddTunAddr updates list off addrs of provided Tun.
//
// The address must be a CIDR prefix such as "10.0.0.1/32" or "fd00::1/128".
// The Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is
// returned.
func AddTunAddr(tun gtun.Tun, addr string) error {
	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	nlAddr, err := netlinkAddrFromString(addr)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(info.link, nlAddr); err != nil {
		return fmt.Errorf("update address %s: %w", addr, err)
	}
	return nil
}

// GetTunAddrs returns list off addrs of provided Tun.
//
// Returned entries are CIDR prefixes assigned to the interface. The Tun must
// expose a non-nil File; otherwise sysnet.ErrUnknownTun is returned.
func GetTunAddrs(tun gtun.Tun) ([]string, error) {
	info, err := tunFileInfo(tun)
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(info.link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("get addresses: %w", err)
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		out = append(out, addr.IPNet.String())
	}
	return out, nil
}

// SetTunRoutes updates list off routes of provided Tun.
//
// Existing main-table routes whose output interface is the Tun are removed
// before the provided CIDR routes are added. The Tun must expose a non-nil
// File; otherwise sysnet.ErrUnknownTun is returned.
func SetTunRoutes(tun gtun.Tun, routes []string) error {
	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	prefixes, err := parseTunRoutePrefixes(routes)
	if err != nil {
		return err
	}

	current, err := netlink.RouteListFiltered(
		netlink.FAMILY_ALL,
		&netlink.Route{Table: unix.RT_TABLE_MAIN, LinkIndex: info.index},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF,
	)
	if err != nil {
		return err
	}
	for _, route := range current {
		if err := netlink.RouteDel(&route); err != nil &&
			!errors.Is(err, unix.ESRCH) {
			return err
		}
	}
	for i, prefix := range prefixes {
		route, err := netlinkRouteFromPrefix(info.index, prefix)
		if err != nil {
			return err
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("update route %s: %w", routes[i], err)
		}
	}
	return nil
}

// AddTunRoute updates list off routes of provided Tun.
//
// The route must be a CIDR prefix such as "10.0.0.0/24" or "fd00::/64". The
// Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is returned.
func AddTunRoute(tun gtun.Tun, route string) error {
	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	prefix, err := parseTunRoutePrefix(route)
	if err != nil {
		return err
	}
	nlRoute, err := netlinkRouteFromPrefix(info.index, prefix)
	if err != nil {
		return err
	}
	if err := netlink.RouteReplace(nlRoute); err != nil {
		return fmt.Errorf("update route %s: %w", route, err)
	}
	return nil
}

// GetTunRotue returns list off routes of provided Tun.
//
// The misspelling is kept to match the gonnect sysnet.System interface. The Tun
// must expose a non-nil File; otherwise sysnet.ErrUnknownTun is returned.
func GetTunRotue(tun gtun.Tun) ([]string, error) {
	info, err := tunFileInfo(tun)
	if err != nil {
		return nil, err
	}
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_ALL,
		&netlink.Route{Table: unix.RT_TABLE_MAIN, LinkIndex: info.index},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF,
	)
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		if route.Table != unix.RT_TABLE_MAIN ||
			(route.Type != 0 && route.Type != unix.RTN_UNICAST) {
			continue
		}
		prefix, ok := prefixFromIPNet(route.Dst, route.Family)
		if !ok {
			continue
		}
		out = append(out, prefix.String())
	}
	return out, nil
}

// SetTunName updates name of provided Tun.
//
// The Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is
// returned.
func SetTunName(tun gtun.Tun, name string) ([]string, error) {
	info, err := tunFileInfo(tun)
	if err != nil {
		return nil, err
	}
	wasUp := info.link.Attrs().Flags&net.FlagUp != 0
	if wasUp {
		if err := netlink.LinkSetDown(info.link); err != nil {
			return nil, fmt.Errorf("set interface %s down: %w", info.name, err)
		}
	}
	if err := netlink.LinkSetName(info.link, name); err != nil {
		if wasUp {
			_ = netlink.LinkSetUp(info.link)
		}
		return nil, fmt.Errorf(
			"rename interface %s to %s: %w",
			info.name,
			name,
			err,
		)
	}
	renamed, err := tunFileInfo(tun)
	if err != nil {
		return nil, err
	}
	if wasUp {
		if err := netlink.LinkSetUp(renamed.link); err != nil {
			return nil, fmt.Errorf("set interface %s up: %w", renamed.name, err)
		}
	}
	return []string{renamed.name}, nil
}

type tunInfo struct {
	name  string
	index int
	link  netlink.Link
}

func tunFileInfo(tun gtun.Tun) (tunInfo, error) {
	if tun == nil {
		return tunInfo{}, sysnet.ErrUnknownTun
	}
	file := tun.File()
	if file == nil {
		return tunInfo{}, sysnet.ErrUnknownTun
	}

	ifr, err := unix.NewIfreq("")
	if err != nil {
		return tunInfo{}, fmt.Errorf("create TUNGETIFF ifreq: %w", err)
	}
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNGETIFF, ifr); err != nil {
		return tunInfo{}, fmt.Errorf("TUNGETIFF: %w", err)
	}

	link, err := netlink.LinkByName(ifr.Name())
	if err != nil {
		return tunInfo{}, fmt.Errorf("lookup interface %s: %w", ifr.Name(), err)
	}
	return tunInfo{name: ifr.Name(), index: link.Attrs().Index, link: link}, nil
}

func netlinkAddrFromString(addr string) (*netlink.Addr, error) {
	prefix, err := parseTunAddrPrefix(addr)
	if err != nil {
		return nil, err
	}
	return netlinkAddrFromPrefix(prefix)
}

func netlinkAddrFromPrefix(prefix netip.Prefix) (*netlink.Addr, error) {
	ipNet, err := ipNetFromPrefix(prefix)
	if err != nil {
		return nil, err
	}
	return &netlink.Addr{IPNet: ipNet}, nil
}

func netlinkRouteFromPrefix(
	index int,
	prefix netip.Prefix,
) (*netlink.Route, error) {
	dst, err := ipNetFromPrefix(prefix.Masked())
	if err != nil {
		return nil, err
	}
	if prefix.Bits() == 0 {
		dst = nil
	}
	return &netlink.Route{
		LinkIndex: index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       dst,
		Protocol:  unix.RTPROT_STATIC,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
	}, nil
}

func parseTunAddrPrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := parseTunAddrPrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseTunRoutePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := parseTunRoutePrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseTunAddrPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err == nil {
		return prefix, nil
	}
	addr, addrErr := netip.ParseAddr(value)
	if addrErr != nil {
		return netip.Prefix{}, fmt.Errorf(
			"parse CIDR prefix %q: %w",
			value,
			err,
		)
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func parseTunRoutePrefix(value string) (netip.Prefix, error) {
	prefix, err := parseTunAddrPrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return prefix.Masked(), nil
}

func ipNetFromPrefix(prefix netip.Prefix) (*net.IPNet, error) {
	if !prefix.IsValid() {
		return nil, errors.New("invalid prefix")
	}
	addr := prefix.Addr()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return &net.IPNet{
		IP:   netIPFromAddr(addr),
		Mask: net.CIDRMask(prefix.Bits(), bits),
	}, nil
}

func netIPFromAddr(addr netip.Addr) net.IP {
	if !addr.IsValid() {
		return nil
	}
	if addr.Is4() {
		v := addr.As4()
		return net.IPv4(v[0], v[1], v[2], v[3])
	}
	v := addr.As16()
	return net.IP(v[:])
}

func prefixFromIPNet(network *net.IPNet, family int) (netip.Prefix, bool) {
	if network == nil {
		switch family {
		case netlink.FAMILY_V4:
			return netip.MustParsePrefix("0.0.0.0/0"), true
		case netlink.FAMILY_V6:
			return netip.MustParsePrefix("::/0"), true
		default:
			return netip.Prefix{}, false
		}
	}
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

func addrFromIP(ip net.IP) (netip.Addr, bool) {
	if ip4 := ip.To4(); ip4 != nil {
		addr, ok := netip.AddrFromSlice(ip4)
		return addr, ok
	}
	addr, ok := netip.AddrFromSlice(ip)
	return addr, ok
}
