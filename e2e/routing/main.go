//go:build linux

// nolint
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/asciimoth/sysnet-linux/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	vpnLinkName  = "sysnet-vpn0"
	physLinkName = "sysnet-phys0"
	peerLinkName = "sysnet-peer0"
	safeLinkName = "sysnet-br0"
	safeAltName  = "sysnet-br1"
	wifiLinkName = "sysnet-wifi0"
	ethLinkName  = "sysnet-eth0"

	vpnTable  = 20010
	safeTable = 20011

	priorityBase = 12000
	prioritySpan = routing.DefaultPrioritySpan

	userMark = 0x4d000001
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatalf("routing e2e failed: %v", err)
	}
	log.Print("routing e2e passed")
}

func run() error {
	if err := setupLinksAndMainRoutes(); err != nil {
		return err
	}

	vpnLink, err := netlink.LinkByName(vpnLinkName)
	if err != nil {
		return fmt.Errorf("lookup VPN link: %w", err)
	}
	cfg := routing.DefaultConfig()
	cfg.TUNIndex = vpnLink.Attrs().Index
	cfg.VPNTable = vpnTable
	cfg.SafeTable = safeTable
	cfg.PriorityBase = priorityBase
	cfg.PrioritySpan = prioritySpan
	cfg.UserMark = userMark
	cfg.Families = routing.BothFamilies

	manager, err := routing.NewManager()
	if err != nil {
		return fmt.Errorf("create routing manager: %w", err)
	}
	defer manager.Close()
	defer func() {
		if err := manager.Rollback(cfg); err != nil {
			log.Printf("cleanup rollback failed: %v", err)
		}
	}()

	if err := checkExcludeStrict(manager, cfg); err != nil {
		return err
	}
	if err := checkAppBypassFailClosed(manager, cfg); err != nil {
		return err
	}
	if err := checkExcludeNonStrict(manager, cfg); err != nil {
		return err
	}
	if err := checkIncludeStrict(manager, cfg); err != nil {
		return err
	}
	if err := checkIncludeNonStrict(manager, cfg); err != nil {
		return err
	}
	if err := checkRollback(manager, cfg); err != nil {
		return err
	}

	return nil
}

func setupLinksAndMainRoutes() error {
	_ = ip("link", "del", vpnLinkName)
	_ = ip("link", "del", physLinkName)
	_ = ip("link", "del", safeLinkName)
	_ = ip("link", "del", safeAltName)
	_ = ip("link", "del", wifiLinkName)
	_ = ip("link", "del", ethLinkName)

	if err := ip("link", "add", vpnLinkName, "type", "dummy"); err != nil {
		return err
	}
	if err := ip(
		"link",
		"add",
		physLinkName,
		"type",
		"veth",
		"peer",
		"name",
		peerLinkName,
	); err != nil {
		return err
	}
	if err := ip("link", "add", safeLinkName, "type", "dummy"); err != nil {
		return err
	}
	if err := ip("link", "add", safeAltName, "type", "dummy"); err != nil {
		return err
	}

	for _, name := range []string{vpnLinkName, physLinkName, peerLinkName, safeLinkName, safeAltName} {
		if err := ip("link", "set", name, "up"); err != nil {
			return err
		}
	}

	for ip("route", "del", "default") == nil {
	}
	for ip("-6", "route", "del", "default") == nil {
	}

	commands := [][]string{
		{"addr", "add", "198.51.100.2/24", "dev", physLinkName},
		{"addr", "add", "198.51.100.1/24", "dev", peerLinkName},
		{"addr", "add", "172.28.0.1/16", "dev", safeLinkName},
		{"addr", "add", "172.29.0.1/16", "dev", safeAltName},
		{"-6", "addr", "add", "2001:db8:100::2/64", "dev", physLinkName},
		{"-6", "addr", "add", "fd00:28::1/64", "dev", safeLinkName},
		{"route", "add", "default", "dev", physLinkName, "metric", "100"},
		{"route", "add", "default", "dev", safeLinkName, "metric", "500"},
		{
			"route",
			"add",
			"9.9.9.0/24",
			"via",
			"198.51.100.1",
			"dev",
			physLinkName,
		},
		{
			"route",
			"add",
			"10.88.0.0/16",
			"via",
			"172.28.0.254",
			"dev",
			safeLinkName,
		},
		{"route", "add", "10.99.0.0/24", "dev", vpnLinkName},
		{"route", "add", "45.45.45.0/24", "dev", safeLinkName},
		{
			"route",
			"add",
			"46.46.46.0/24",
			"nexthop",
			"dev",
			safeLinkName,
			"nexthop",
			"via",
			"198.51.100.1",
			"dev",
			physLinkName,
		},
		{
			"route",
			"add",
			"47.47.47.0/24",
			"nexthop",
			"dev",
			safeLinkName,
			"nexthop",
			"dev",
			safeAltName,
		},
		{"route", "add", "blackhole", "10.77.0.0/24"},
		{
			"-6",
			"route",
			"add",
			"default",
			"via",
			"2001:db8:100::1",
			"dev",
			physLinkName,
			"metric",
			"100",
			"onlink",
		},
		{
			"-6",
			"route",
			"add",
			"2001:4860:4860::/48",
			"via",
			"2001:db8:100::1",
			"dev",
			physLinkName,
			"onlink",
		},
		{
			"-6",
			"route",
			"add",
			"fd00:88::/64",
			"via",
			"fd00:28::fe",
			"dev",
			safeLinkName,
		},
		{"-6", "route", "add", "fd00:99::/64", "dev", vpnLinkName},
		{"-6", "route", "add", "2001:db8:45::/64", "dev", safeLinkName},
	}
	for _, args := range commands {
		if err := ip(args...); err != nil {
			return err
		}
	}
	return nil
}

func checkExcludeStrict(manager *routing.Manager, cfg routing.Config) error {
	cfg.Mode = routing.ModeExclude
	cfg.Strictness = routing.Strict
	if err := manager.Apply(cfg); err != nil {
		return fmt.Errorf("apply exclude strict: %w", err)
	}
	if err := expectRoute(
		"exclude strict unmarked default",
		"8.8.8.8",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude strict user-marked default",
		"8.8.8.8",
		userMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude strict app-bypass default",
		"8.8.8.8",
		routing.DefaultAppBypassMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude strict IPv6 unmarked default",
		"2001:db8:ffff::8888",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude strict IPv6 user-marked default",
		"2001:db8:ffff::8888",
		userMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude strict IPv6 app-bypass default",
		"2001:db8:ffff::8888",
		routing.DefaultAppBypassMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude strict unmarked safe route",
		"172.28.9.9",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude strict marked safe route",
		"172.28.9.9",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := ip("route", "del", "default", "dev", physLinkName); err != nil {
		return fmt.Errorf(
			"delete primary default for exclude strict fallback check: %w",
			err,
		)
	}
	defer func() {
		if err := ip(
			"route",
			"add",
			"default",
			"dev",
			physLinkName,
			"metric",
			"100",
		); err != nil {
			log.Printf("restore primary default route failed: %v", err)
		}
	}()
	if err := expectRoute(
		"exclude strict marked traffic uses lower-priority direct default",
		"8.8.8.8",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude strict app-bypass uses lower-priority direct default",
		"8.8.8.8",
		routing.DefaultAppBypassMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude strict unmarked traffic still uses VPN with primary default removed",
		"8.8.8.8",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	return nil
}

func checkAppBypassFailClosed(
	manager *routing.Manager,
	cfg routing.Config,
) error {
	cfg.Mode = routing.ModeExclude
	cfg.Strictness = routing.Strict
	if err := manager.Apply(cfg); err != nil {
		return fmt.Errorf("apply app-bypass guard check: %w", err)
	}
	for ip("route", "del", "default") == nil {
	}
	for ip("-6", "route", "del", "default") == nil {
	}
	defer func() {
		if err := ip(
			"route",
			"add",
			"default",
			"dev",
			physLinkName,
			"metric",
			"100",
		); err != nil {
			log.Printf("restore primary default route failed: %v", err)
		}
		if err := ip(
			"route",
			"replace",
			"default",
			"dev",
			safeLinkName,
			"metric",
			"500",
		); err != nil {
			log.Printf("restore fallback default route failed: %v", err)
		}
		if err := ip(
			"-6",
			"route",
			"replace",
			"default",
			"via",
			"2001:db8:100::1",
			"dev",
			physLinkName,
			"metric",
			"100",
			"onlink",
		); err != nil {
			log.Printf("restore IPv6 default route failed: %v", err)
		}
	}()

	if err := expectUnreachable(
		"app-bypass without main default",
		"8.8.8.8",
		routing.DefaultAppBypassMark,
	); err != nil {
		return err
	}
	if err := expectUnreachable6(
		"IPv6 app-bypass without main default",
		"2001:db8:ffff::8888",
		routing.DefaultAppBypassMark,
	); err != nil {
		return err
	}
	if err := expectUnreachable(
		"exclude strict user-mark without main default",
		"8.8.8.8",
		userMark,
	); err != nil {
		return err
	}
	return expectRoute(
		"unmarked VPN route survives missing main default",
		"8.8.8.8",
		0,
		"dev "+vpnLinkName,
	)
}

func checkExcludeNonStrict(manager *routing.Manager, cfg routing.Config) error {
	cfg.Mode = routing.ModeExclude
	cfg.Strictness = routing.NonStrict
	if err := manager.Apply(cfg); err != nil {
		return fmt.Errorf("apply exclude non-strict: %w", err)
	}
	if err := expectRoute(
		"exclude non-strict safe bridge route",
		"172.28.9.9",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict unsafe public gateway route",
		"9.9.9.9",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict marked public gateway route",
		"9.9.9.9",
		userMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict direct public route",
		"45.45.45.42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict private route via gateway",
		"10.88.0.42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude non-strict IPv6 ULA route via gateway",
		"fd00:88::42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRouteAny(
		"exclude non-strict all-safe multipath route",
		"47.47.47.42",
		0,
		[]string{"dev " + safeLinkName, "dev " + safeAltName},
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict unsupported blackhole route ignored",
		"10.77.0.42",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict VPN-link main route not safe",
		"10.99.0.42",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict public multipath route not safe",
		"46.46.46.42",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude non-strict IPv6 ULA route",
		"fd00:28::42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude non-strict IPv6 unsafe public gateway route",
		"2001:4860:4860::42",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude non-strict IPv6 direct public route",
		"2001:db8:45::42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectNoTableRoute(
		"blackhole route not copied to safe table",
		safeTable,
		"10.77.0.0/24",
	); err != nil {
		return err
	}
	if err := expectNoTableRoute(
		"IPv4 default route not copied to safe table",
		safeTable,
		"0.0.0.0/0",
	); err != nil {
		return err
	}
	if err := expectNoTableRoute6(
		"IPv6 default route not copied to safe table",
		safeTable,
		"::/0",
	); err != nil {
		return err
	}
	if err := expectNoTableRoute(
		"VPN-link main route not copied to safe table",
		safeTable,
		"10.99.0.0/24",
	); err != nil {
		return err
	}
	if err := expectNoTableRoute(
		"public multipath route not copied to safe table",
		safeTable,
		"46.46.46.0/24",
	); err != nil {
		return err
	}
	if err := expectNoTableRoute6(
		"IPv6 public gateway route not copied to safe table",
		safeTable,
		"2001:4860:4860::/48",
	); err != nil {
		return err
	}
	if err := expectTableRoute(
		"safe bridge route copied to safe table",
		safeTable,
		"172.28.0.0/16",
	); err != nil {
		return err
	}
	if err := expectTableRoute(
		"safe private gateway route copied to safe table",
		safeTable,
		"10.88.0.0/16",
	); err != nil {
		return err
	}
	if err := expectTableRoute6(
		"IPv6 ULA gateway route copied to safe table",
		safeTable,
		"fd00:88::/64",
	); err != nil {
		return err
	}
	if err := ip("route", "flush", "table", fmt.Sprint(vpnTable)); err != nil {
		return fmt.Errorf(
			"flush VPN table for exclude non-strict guard check: %w",
			err,
		)
	}
	if err := ip(
		"-6",
		"route",
		"flush",
		"table",
		fmt.Sprint(vpnTable),
	); err != nil {
		return fmt.Errorf(
			"flush IPv6 VPN table for exclude non-strict guard check: %w",
			err,
		)
	}
	if err := expectUnreachable(
		"exclude non-strict unsafe traffic without VPN route",
		"8.8.8.8",
		0,
	); err != nil {
		return err
	}
	if err := expectUnreachable6(
		"exclude non-strict IPv6 unsafe traffic without VPN route",
		"2001:db8:ffff::8888",
		0,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict safe traffic survives missing VPN route",
		"172.28.9.9",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude non-strict private gateway route survives missing VPN route",
		"10.88.0.42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude non-strict IPv6 ULA gateway route survives missing VPN route",
		"fd00:88::42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRouteAny(
		"exclude non-strict all-safe multipath survives missing VPN route",
		"47.47.47.42",
		0,
		[]string{"dev " + safeLinkName, "dev " + safeAltName},
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"exclude non-strict IPv6 safe traffic survives missing VPN route",
		"fd00:28::42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := manager.Apply(cfg); err != nil {
		return fmt.Errorf(
			"restore exclude non-strict after guard check: %w",
			err,
		)
	}
	return checkDynamicSafeRouteRefresh(manager)
}

func checkDynamicSafeRouteRefresh(manager *routing.Manager) error {
	if err := createAddressedDummyLink(
		wifiLinkName,
		"10.44.0.1/24",
	); err != nil {
		return fmt.Errorf("create dynamic wifi link: %w", err)
	}
	defer func() { _ = ip("link", "del", wifiLinkName) }()

	if err := refreshAndExpectRoute(
		manager,
		"dynamic wifi create",
		"10.44.0.42",
		wifiLinkName,
	); err != nil {
		return err
	}

	if err := createAddressedDummyLink(
		ethLinkName,
		"10.55.0.1/24",
	); err != nil {
		return fmt.Errorf("create dynamic eth link: %w", err)
	}
	defer func() { _ = ip("link", "del", ethLinkName) }()

	if err := ip("link", "del", wifiLinkName); err != nil {
		return fmt.Errorf("delete migrated wifi link: %w", err)
	}
	if err := refreshAndExpectRoute(
		manager,
		"dynamic eth migration",
		"10.55.0.42",
		ethLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"dynamic wifi stale route removed",
		"10.44.0.42",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}

	if err := ip("addr", "flush", "dev", ethLinkName); err != nil {
		return fmt.Errorf("flush dynamic eth address: %w", err)
	}
	if err := ip(
		"addr",
		"add",
		"10.66.0.1/24",
		"dev",
		ethLinkName,
	); err != nil {
		return fmt.Errorf("update dynamic eth address: %w", err)
	}
	if err := refreshAndExpectRoute(
		manager,
		"dynamic eth address update",
		"10.66.0.42",
		ethLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"dynamic eth old prefix removed",
		"10.55.0.42",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}

	if err := ip("link", "del", ethLinkName); err != nil {
		return fmt.Errorf("delete dynamic eth link: %w", err)
	}
	if err := manager.Refresh(); err != nil {
		return fmt.Errorf("refresh after dynamic eth delete: %w", err)
	}
	if err := expectRoute(
		"dynamic eth deleted prefix removed",
		"10.66.0.42",
		0,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	return nil
}

func createAddressedDummyLink(name, cidr string) error {
	_ = ip("link", "del", name)
	if err := ip("link", "add", name, "type", "dummy"); err != nil {
		return err
	}
	if err := ip("link", "set", name, "up"); err != nil {
		return err
	}
	return ip("addr", "add", cidr, "dev", name)
}

func refreshAndExpectRoute(
	manager *routing.Manager,
	name, dst, linkName string,
) error {
	if err := manager.Refresh(); err != nil {
		return fmt.Errorf("%s refresh: %w", name, err)
	}
	return expectRoute(name, dst, 0, "dev "+linkName)
}

func checkIncludeStrict(manager *routing.Manager, cfg routing.Config) error {
	cfg.Mode = routing.ModeInclude
	cfg.Strictness = routing.Strict
	if err := manager.Apply(cfg); err != nil {
		return fmt.Errorf("apply include strict: %w", err)
	}
	if err := expectUnreachable(
		"include strict unmarked traffic",
		"8.8.8.8",
		0,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include strict marked traffic",
		"8.8.8.8",
		userMark,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectUnreachable6(
		"include strict IPv6 unmarked traffic",
		"2001:db8:ffff::8888",
		0,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"include strict IPv6 marked traffic",
		"2001:db8:ffff::8888",
		userMark,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectUnreachable(
		"include strict unmarked safe traffic",
		"172.28.9.9",
		0,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include strict loopback survives via local table",
		"127.0.0.1",
		0,
		"dev lo",
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include strict host address survives via local table",
		"198.51.100.2",
		0,
		"local 198.51.100.2",
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"include strict IPv6 loopback survives via local table",
		"::1",
		0,
		"local ::1",
	); err != nil {
		return err
	}
	return expectRoute(
		"include strict app-bypass traffic",
		"8.8.8.8",
		routing.DefaultAppBypassMark,
		"dev "+physLinkName,
	)
}

func checkIncludeNonStrict(manager *routing.Manager, cfg routing.Config) error {
	cfg.Mode = routing.ModeInclude
	cfg.Strictness = routing.NonStrict
	if err := manager.Apply(cfg); err != nil {
		return fmt.Errorf("apply include non-strict: %w", err)
	}
	if err := expectRoute(
		"include non-strict marked internet traffic",
		"8.8.8.8",
		userMark,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict unmarked internet traffic",
		"8.8.8.8",
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict marked safe traffic",
		"172.28.9.9",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict marked unsafe public gateway route",
		"9.9.9.9",
		userMark,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"include non-strict IPv6 marked unsafe public gateway route",
		"2001:4860:4860::42",
		userMark,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict unmarked safe traffic",
		"172.28.9.9",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"include non-strict IPv6 unmarked safe traffic",
		"fd00:28::42",
		0,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict marked direct public route",
		"45.45.45.42",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict marked private route via gateway",
		"10.88.0.42",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"include non-strict marked IPv6 ULA route via gateway",
		"fd00:88::42",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRouteAny(
		"include non-strict marked all-safe multipath route",
		"47.47.47.42",
		userMark,
		[]string{"dev " + safeLinkName, "dev " + safeAltName},
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"include non-strict IPv6 marked direct public route",
		"2001:db8:45::42",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict marked public multipath route not safe",
		"46.46.46.42",
		userMark,
		"dev "+vpnLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict app-bypass traffic",
		"8.8.8.8",
		routing.DefaultAppBypassMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict app-bypass safe traffic prefers main over safe table",
		"172.28.9.9",
		routing.DefaultAppBypassMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := ip("route", "flush", "table", fmt.Sprint(vpnTable)); err != nil {
		return fmt.Errorf(
			"flush VPN table for include non-strict guard check: %w",
			err,
		)
	}
	if err := ip(
		"-6",
		"route",
		"flush",
		"table",
		fmt.Sprint(vpnTable),
	); err != nil {
		return fmt.Errorf(
			"flush IPv6 VPN table for include non-strict guard check: %w",
			err,
		)
	}
	if err := expectUnreachable(
		"include non-strict marked unsafe traffic without VPN route",
		"8.8.8.8",
		userMark,
	); err != nil {
		return err
	}
	if err := expectUnreachable6(
		"include non-strict IPv6 marked unsafe traffic without VPN route",
		"2001:db8:ffff::8888",
		userMark,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict marked safe traffic survives missing VPN route",
		"172.28.9.9",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include non-strict marked private gateway route survives missing VPN route",
		"10.88.0.42",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"include non-strict marked IPv6 ULA gateway route survives missing VPN route",
		"fd00:88::42",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute6(
		"include non-strict IPv6 marked safe traffic survives missing VPN route",
		"fd00:28::42",
		userMark,
		"dev "+safeLinkName,
	); err != nil {
		return err
	}
	return expectRoute(
		"include non-strict unmarked traffic survives missing VPN route",
		"8.8.8.8",
		0,
		"dev "+physLinkName,
	)
}

func checkRollback(manager *routing.Manager, cfg routing.Config) error {
	if err := manager.Rollback(cfg); err != nil {
		return fmt.Errorf("rollback: %w", err)
	}

	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("list rules after rollback: %w", err)
		}
		for _, rule := range rules {
			if rule.Priority >= priorityBase &&
				rule.Priority < priorityBase+prioritySpan {
				return fmt.Errorf(
					"rollback left owned rule priority %d",
					rule.Priority,
				)
			}
		}
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		for _, table := range []int{vpnTable, safeTable} {
			routes, err := netlink.RouteListFiltered(
				family,
				&netlink.Route{Table: table},
				netlink.RT_FILTER_TABLE,
			)
			if err != nil {
				return fmt.Errorf(
					"list table %d family %d after rollback: %w",
					table,
					family,
					err,
				)
			}
			if len(routes) != 0 {
				return fmt.Errorf(
					"rollback left %d route(s) in owned table %d family %d",
					len(routes),
					table,
					family,
				)
			}
		}
	}
	return nil
}

func expectRoute(name, dst string, mark uint32, contains string) error {
	return expectRouteAny(name, dst, mark, []string{contains})
}

func expectRouteAny(name, dst string, mark uint32, containsAny []string) error {
	output, err := routeGet("-4", dst, mark)
	if err != nil {
		return fmt.Errorf(
			"%s: route get failed with output %q: %w",
			name,
			output,
			err,
		)
	}
	for _, contains := range containsAny {
		if strings.Contains(output, contains) {
			return nil
		}
	}
	return fmt.Errorf(
		"%s: route %q does not contain any of %q",
		name,
		output,
		containsAny,
	)
}

func expectRoute6(name, dst string, mark uint32, contains string) error {
	output, err := routeGet("-6", dst, mark)
	if err != nil {
		return fmt.Errorf(
			"%s: route get failed with output %q: %w",
			name,
			output,
			err,
		)
	}
	if !strings.Contains(output, contains) {
		return fmt.Errorf(
			"%s: route %q does not contain %q",
			name,
			output,
			contains,
		)
	}
	return nil
}

func expectUnreachable(name, dst string, mark uint32) error {
	output, err := routeGet("-4", dst, mark)
	if err == nil {
		return fmt.Errorf("%s: route unexpectedly resolved: %q", name, output)
	}
	if !strings.Contains(output, "Network is unreachable") {
		return fmt.Errorf(
			"%s: route get failed with unexpected output %q: %w",
			name,
			output,
			err,
		)
	}
	return nil
}

func expectUnreachable6(name, dst string, mark uint32) error {
	output, err := routeGet("-6", dst, mark)
	if err == nil {
		return fmt.Errorf("%s: route unexpectedly resolved: %q", name, output)
	}
	if !strings.Contains(output, "Network is unreachable") {
		return fmt.Errorf(
			"%s: route get failed with unexpected output %q: %w",
			name,
			output,
			err,
		)
	}
	return nil
}

func expectNoTableRoute(name string, table int, prefix string) error {
	return expectNoTableRouteFamily(name, netlink.FAMILY_V4, table, prefix)
}

func expectNoTableRoute6(name string, table int, prefix string) error {
	return expectNoTableRouteFamily(name, netlink.FAMILY_V6, table, prefix)
}

func expectTableRoute(name string, table int, prefix string) error {
	return expectTableRouteFamily(name, netlink.FAMILY_V4, table, prefix)
}

func expectTableRoute6(name string, table int, prefix string) error {
	return expectTableRouteFamily(name, netlink.FAMILY_V6, table, prefix)
}

func expectTableRouteFamily(
	name string,
	family, table int,
	prefix string,
) error {
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: table},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return fmt.Errorf("%s: list table %d: %w", name, table, err)
	}
	for _, route := range routes {
		if tableRoutePrefix(route, family) == prefix {
			return nil
		}
	}
	return fmt.Errorf("%s: table %d does not contain %s", name, table, prefix)
}

func expectNoTableRouteFamily(
	name string,
	family, table int,
	prefix string,
) error {
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: table},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return fmt.Errorf("%s: list table %d: %w", name, table, err)
	}
	for _, route := range routes {
		if tableRoutePrefix(route, family) == prefix {
			return fmt.Errorf(
				"%s: table %d unexpectedly contains %s",
				name,
				table,
				prefix,
			)
		}
	}
	return nil
}

func tableRoutePrefix(route netlink.Route, family int) string {
	if route.Dst != nil {
		return route.Dst.String()
	}
	if family == netlink.FAMILY_V6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}

func routeGet(familyFlag, dst string, mark uint32) (string, error) {
	args := []string{familyFlag, "route", "get", dst}
	if mark != 0 {
		args = append(args, "mark", fmt.Sprintf("0x%x", mark))
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("ip", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return strings.TrimSpace(stdout.String() + stderr.String()), err
}

func ip(args ...string) error {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("ip", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		output := strings.TrimSpace(stdout.String() + stderr.String())
		if output == "" {
			return fmt.Errorf("ip %s: %w", strings.Join(args, " "), err)
		}
		return fmt.Errorf(
			"ip %s: %w",
			strings.Join(args, " "),
			errors.Join(err, errors.New(output)),
		)
	}
	return nil
}
