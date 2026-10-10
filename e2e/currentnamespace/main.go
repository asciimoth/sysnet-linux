//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sysnet"
	linux "github.com/asciimoth/sysnet-linux"
	linuxdns "github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const monitorTimeout = 3 * time.Second

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatalf("current-namespace e2e failed: %v", err)
	}
	log.Print("current-namespace e2e passed")
}

func run() error {
	if _, err := os.Stat("/proc/self/ns/net"); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("procfs is available")
		}
		return fmt.Errorf("check procfs availability: %w", err)
	}
	if err := requireCapability(unix.CAP_NET_ADMIN, true); err != nil {
		return err
	}
	if err := requireCapability(unix.CAP_SYS_ADMIN, false); err != nil {
		return err
	}

	manager, err := routing.NewManagerCurrentNamespace()
	if err != nil {
		return fmt.Errorf("create routing manager: %w", err)
	}
	provider := newTestDNSProvider()
	system, err := linux.NewSystem(linux.Config{
		Features: linux.FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    provider,
		RoutingManager: manager,
	})
	if err != nil {
		_ = manager.Close()
		return fmt.Errorf("create system: %w", err)
	}
	defer func() { _ = system.Close() }()

	defaultTun, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.66.0.1/32"},
		DnsIP:    "10.66.0.1",
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf("build default TUN: %w", err)
	}
	defer func() { _ = defaultTun.Close() }()

	const linkName = "sn-current0"
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: linkName}}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("add monitor test link: %w", err)
	}
	defer func() { _ = netlink.LinkDel(link) }()
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set monitor test link up: %w", err)
	}
	prefix := netip.MustParsePrefix("198.18.0.0/24")
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       prefixToIPNet(prefix),
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("add monitor test route: %w", err)
	}
	if err := waitForSafeRoute(manager, prefix); err != nil {
		return err
	}

	if err := defaultTun.Close(); err != nil {
		return fmt.Errorf("close default TUN: %w", err)
	}
	if err := system.Close(); err != nil {
		return fmt.Errorf("close system: %w", err)
	}
	return nil
}

func requireCapability(capability int, want bool) error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read capabilities: %w", err)
	}
	has := data[capability/32].Effective&(uint32(1)<<(capability%32)) != 0
	if has != want {
		return fmt.Errorf(
			"capability %d present = %v, want %v",
			capability,
			has,
			want,
		)
	}
	return nil
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(prefix.Addr().AsSlice()),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func waitForSafeRoute(manager *routing.Manager, want netip.Prefix) error {
	deadline := time.Now().Add(monitorTimeout)
	for time.Now().Before(deadline) {
		state, ok := manager.Status()
		if ok {
			for _, route := range state.SafeRoutes {
				if route.Dst == want {
					return nil
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("route monitor did not refresh safe route %s", want)
}

type testDNSProvider struct {
	requests chan gdns.Request
}

var _ linuxdns.DNSProvider = (*testDNSProvider)(nil)

func newTestDNSProvider() *testDNSProvider {
	return &testDNSProvider{requests: make(chan gdns.Request)}
}

func (p *testDNSProvider) Requests() chan<- gdns.Request { return p.requests }
func (p *testDNSProvider) SetDNS(netip.Addr) error       { return nil }
func (p *testDNSProvider) UnsetDNS() error               { return nil }
func (p *testDNSProvider) Close() error                  { return nil }
