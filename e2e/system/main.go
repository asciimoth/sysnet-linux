//go:build linux

// nolint
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect-netstack/vtun"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/fwmark"
	"github.com/asciimoth/p-mark/multirule"
	linux "github.com/asciimoth/sysnet-linux"
	"github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/routing"
	"golang.org/x/sys/unix"
)

const (
	physLinkName = "snrt-phys0"
	peerLinkName = "snrt-peer0"
	safeLinkName = "snrt-safe0"

	dnsIP         = "10.66.0.1"
	vtunServiceIP = "10.66.0.2"
	vtunHTTPPort  = 18080

	userMark = 0x4d000001

	socketProbeMode = "socket-probe"
	socketProbeComm = "system-e2e"
	curlComm        = "^curl$"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == socketProbeMode {
		if err := runSocketProbe(); err != nil {
			log.Fatalf("socket probe failed: %v", err)
		}
		return
	}
	var err error
	if len(os.Args) > 1 && os.Args[1] == "systemd-resolved" {
		err = runResolved()
	} else {
		err = run()
	}
	if err != nil {
		log.Fatalf("system e2e failed: %v", err)
	}
	log.Print("system e2e passed")
}

func run() error {
	if err := checkDegradedSystem(); err != nil {
		return err
	}
	if err := checkMatcherOnlySystem(); err != nil {
		return err
	}
	if err := setupLinksAndMainRoutes(); err != nil {
		return err
	}
	defer cleanupLinks()

	if err := checkAutoNewDirectSystem(); err != nil {
		return err
	}

	pmarkCtl := &recordingPmark{}
	system, err := newSystem(pmarkCtl)
	if err != nil {
		return err
	}
	defer func() {
		if err := system.Close(); err != nil {
			log.Printf("system cleanup failed: %v", err)
		}
	}()

	if err := checkFeaturesAndRules(system); err != nil {
		return err
	}
	if err := checkInvalidRules(system); err != nil {
		return err
	}
	if err := checkValidRuleBoundaries(system); err != nil {
		return err
	}
	if err := checkRegularTun(system); err != nil {
		return err
	}
	if err := checkDefaultTunFallbackDNS(system); err != nil {
		return err
	}
	if err := checkDefaultTunLifecycle(system, pmarkCtl); err != nil {
		return err
	}
	if err := checkDefaultTunRebuildDNSMutation(system); err != nil {
		return err
	}
	if err := checkDefaultTunUnderlyingLinkRecreate(system); err != nil {
		return err
	}
	if err := checkDefaultTunRuleContexts(system, pmarkCtl); err != nil {
		return err
	}
	if err := checkMatchers(system, pmarkCtl); err != nil {
		return err
	}
	if err := checkFullPmarkEBPFSetup(); err != nil {
		return err
	}
	if err := checkAutoNewPmarkCurrentProcessSetup(); err != nil {
		return err
	}

	return nil
}

func newSystem(pmarkCtl linux.PmarkController) (*linux.System, error) {
	plainNet := gonnect.NativeConfig{}.Build()
	dnsProvider, err := dns.NewDirect(
		dns.Env{Logf: log.Printf},
		plainNet,
		plainNet,
		netip.MustParseAddrPort("1.1.1.1:53"),
	)
	if err != nil {
		return nil, fmt.Errorf("create direct DNS provider: %w", err)
	}

	routingManager, err := routing.NewManager()
	if err != nil {
		_ = dnsProvider.Close()
		return nil, fmt.Errorf("create routing manager: %w", err)
	}

	system, err := linux.NewSystem(linux.Config{
		Features: linux.FeatureConfig{
			Tun:           true,
			DefaultTun:    true,
			DynTun:        true,
			DynDefaultTun: true,
			StrictMode:    true,
			TunRules:      true,
			MatcherRules:  true,
			DNSControl:    true,
			Routing:       true,
			Pmark:         true,
		},
		DNSProvider:    dnsProvider,
		RoutingManager: routingManager,
		Pmark:          pmarkCtl,
		RuleTracker:    multirule.New(),
		OwnerLookup:    sockowner.GetSockOwner,
		UserMark:       userMark,
	})
	if err != nil {
		_ = routingManager.Close()
		_ = dnsProvider.Close()
		return nil, fmt.Errorf("create System: %w", err)
	}
	return system, nil
}

func runResolved() error {
	stopResolved, err := startSystemdResolved()
	if err != nil {
		return err
	}
	defer stopResolved()

	if err := setupLinksAndMainRoutes(); err != nil {
		return err
	}
	defer cleanupLinks()

	if err := checkAutoNewResolvedSystem(); err != nil {
		return err
	}

	pmarkCtl := &recordingPmark{}
	system, err := newResolvedSystem(pmarkCtl)
	if err != nil {
		return err
	}
	defer func() {
		if err := system.Close(); err != nil {
			log.Printf("resolved system cleanup failed: %v", err)
		}
	}()

	if err := checkFeaturesAndRules(system); err != nil {
		return err
	}
	if err := checkRegularTun(system); err != nil {
		return err
	}
	if err := checkResolvedDefaultTunLifecycle(system, pmarkCtl); err != nil {
		return err
	}
	if err := checkResolvedDefaultTunRebuildDNSMutation(system); err != nil {
		return err
	}
	if err := checkResolvedDefaultTunUnderlyingLinkRecreate(
		system,
	); err != nil {
		return err
	}
	if err := checkDefaultTunRuleContexts(system, pmarkCtl); err != nil {
		return err
	}
	return nil
}

func newResolvedSystem(pmarkCtl linux.PmarkController) (*linux.System, error) {
	plainNet := gonnect.NativeConfig{}.Build()
	dnsProvider, err := dns.NewResolved(
		dns.Env{Logf: log.Printf},
		plainNet,
		plainNet,
		0,
		netip.MustParseAddrPort("1.1.1.1:53"),
	)
	if err != nil {
		return nil, fmt.Errorf("create resolved DNS provider: %w", err)
	}

	routingManager, err := routing.NewManager()
	if err != nil {
		_ = dnsProvider.Close()
		return nil, fmt.Errorf("create routing manager: %w", err)
	}

	system, err := linux.NewSystem(linux.Config{
		Features: linux.FeatureConfig{
			Tun:           true,
			DefaultTun:    true,
			DynTun:        true,
			DynDefaultTun: true,
			StrictMode:    true,
			TunRules:      true,
			MatcherRules:  true,
			DNSControl:    true,
			Routing:       true,
			Pmark:         true,
		},
		DNSProvider:    dnsProvider,
		RoutingManager: routingManager,
		Pmark:          pmarkCtl,
		RuleTracker:    multirule.New(),
		OwnerLookup:    sockowner.GetSockOwner,
		UserMark:       userMark,
	})
	if err != nil {
		_ = routingManager.Close()
		_ = dnsProvider.Close()
		return nil, fmt.Errorf("create resolved System: %w", err)
	}
	return system, nil
}

func checkAutoNewDirectSystem() error {
	system, err := linux.New(linux.SystemConfig{
		DNS: linux.DNSConfig{
			Mode: linux.DNSModeDirect,
			FallbackServers: []netip.AddrPort{
				netip.MustParseAddrPort("1.1.1.1:53"),
			},
		},
		UserMark: userMark,
		Logf:     log.Printf,
	})
	if err != nil {
		return fmt.Errorf("auto New direct System: %w", err)
	}
	defer func() { _ = system.Close() }()

	if err := checkAutoNewNoPmarkFeatures(system, "direct"); err != nil {
		return err
	}
	if err := checkDefaultTunFallbackDNS(system); err != nil {
		return fmt.Errorf("auto New direct fallback DNS: %w", err)
	}
	if err := checkAutoNewDefaultTunWithoutRules(system, "direct"); err != nil {
		return err
	}
	return nil
}

func checkAutoNewResolvedSystem() error {
	system, err := linux.New(linux.SystemConfig{
		DNS: linux.DNSConfig{
			Mode: linux.DNSModeAuto,
			FallbackServers: []netip.AddrPort{
				netip.MustParseAddrPort("1.1.1.1:53"),
			},
		},
		UserMark: userMark,
		Logf:     log.Printf,
	})
	if err != nil {
		return fmt.Errorf("auto New resolved System: %w", err)
	}
	defer func() { _ = system.Close() }()

	if err := checkAutoNewNoPmarkFeatures(system, "resolved"); err != nil {
		return err
	}
	if err := checkResolvedDefaultTunFallbackDNS(
		system,
		"auto New resolved",
	); err != nil {
		return err
	}
	if err := checkAutoNewResolvedDefaultTunWithoutRules(system); err != nil {
		return err
	}
	return nil
}

func checkAutoNewNoPmarkFeatures(system *linux.System, label string) error {
	features := system.Features()
	if !features.Tun || !features.DefaultTun || !features.DynTun ||
		!features.DynDefaultTun || !features.StrictMode {
		return fmt.Errorf(
			"auto New %s features = %+v, want native TUN/DefaultTun support",
			label,
			features,
		)
	}
	rules := system.ListRules()
	if len(rules.TunRules) != 0 {
		return fmt.Errorf(
			"auto New %s TunRules len = %d, want 0 without p-mark",
			label,
			len(rules.TunRules),
		)
	}
	if len(rules.MatcherRules) != 8 {
		return fmt.Errorf(
			"auto New %s MatcherRules len = %d, want 8",
			label,
			len(rules.MatcherRules),
		)
	}
	if err := system.VerifyDefaultTunOpts(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		Exclude:  []sysnet.Rule{{Type: "pid", Rule: strconv.Itoa(os.Getpid())}},
	}); !errors.Is(err, sysnet.ErrNotSupported) {
		return fmt.Errorf(
			"auto New %s VerifyDefaultTunOpts with rules = %v, want ErrNotSupported",
			label,
			err,
		)
	}
	return nil
}

func checkAutoNewDefaultTunWithoutRules(
	system *linux.System,
	label string,
) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf(
			"auto New %s build DefaultTun without rules: %w",
			label,
			err,
		)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("auto New %s DefaultTun name: %w", label, err)
	}
	if err := waitForResolvconf(dnsIP); err != nil {
		return fmt.Errorf("auto New %s resolv.conf DNS: %w", label, err)
	}
	if err := expectRoute(
		"auto New "+label+" unmarked public route",
		"9.9.9.9",
		0,
		"dev "+tunName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"auto New "+label+" app-bypass public route",
		"9.9.9.9",
		routing.DefaultAppBypassMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	dt.SetDns(newStaticDNS(netip.MustParseAddr("203.0.113.111")))
	if err := expectDNSA(
		"auto New "+label+" attached DNS",
		netip.MustParseAddr("203.0.113.111"),
	); err != nil {
		return err
	}
	if err := dt.Close(); err != nil {
		return fmt.Errorf("auto New %s close DefaultTun: %w", label, err)
	}
	if err := waitForResolvconfNot(dnsIP); err != nil {
		return fmt.Errorf("auto New %s resolv.conf rollback: %w", label, err)
	}
	return nil
}

func checkAutoNewResolvedDefaultTunWithoutRules(system *linux.System) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf(
			"auto New resolved build DefaultTun without rules: %w",
			err,
		)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("auto New resolved DefaultTun name: %w", err)
	}
	if err := waitForResolvedLinkDNS(tunName, dnsIP); err != nil {
		return fmt.Errorf("auto New resolved link DNS: %w", err)
	}
	if err := expectRoute(
		"auto New resolved unmarked public route",
		"9.9.9.9",
		0,
		"dev "+tunName,
	); err != nil {
		return err
	}
	dt.SetDns(newStaticDNS(netip.MustParseAddr("203.0.113.122")))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSAAt(
		"auto New resolved attached DNS",
		"127.0.0.53",
		netip.MustParseAddr("203.0.113.122"),
	); err != nil {
		return err
	}
	if err := dt.Close(); err != nil {
		return fmt.Errorf("auto New resolved close DefaultTun: %w", err)
	}
	if err := waitForResolvedLinkDNSNot(tunName, dnsIP); err != nil {
		return fmt.Errorf("auto New resolved link DNS rollback: %w", err)
	}
	return nil
}

func checkDegradedSystem() error {
	system, err := linux.NewSystem(linux.Config{
		Features: linux.FeatureConfig{
			Tun:          true,
			DefaultTun:   true,
			StrictMode:   true,
			MatcherRules: false,
			DNSControl:   true,
			Routing:      true,
		},
		UserMark: userMark,
	})
	if err != nil {
		return fmt.Errorf("create degraded System: %w", err)
	}
	defer func() { _ = system.Close() }()

	features := system.Features()
	if !features.Tun {
		return fmt.Errorf("degraded features = %+v, want Tun support", features)
	}
	if features.DefaultTun || features.StrictMode {
		return fmt.Errorf(
			"degraded features = %+v, want no DefaultTun or StrictMode",
			features,
		)
	}
	rules := system.ListRules()
	if len(rules.TunRules) != 0 || len(rules.MatcherRules) != 0 {
		return fmt.Errorf("degraded rules = %+v, want no rules", rules)
	}
	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{}); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		return fmt.Errorf(
			"degraded BuildDefaultTun error = %v, want ErrNotSupported",
			err,
		)
	}
	if _, err := system.BuildMatcher(sysnet.Rule{
		Type: "pid",
		Rule: strconv.Itoa(os.Getpid()),
	}); !errors.Is(err, sysnet.ErrNotSupported) {
		return fmt.Errorf(
			"degraded BuildMatcher error = %v, want ErrNotSupported",
			err,
		)
	}
	return nil
}

func checkMatcherOnlySystem() error {
	system, err := linux.NewSystem(linux.Config{
		Features: linux.FeatureConfig{
			MatcherRules: true,
			TunRules:     true,
		},
		UserMark: userMark,
	})
	if err != nil {
		return fmt.Errorf("create matcher-only System: %w", err)
	}
	defer func() { _ = system.Close() }()

	features := system.Features()
	if features.Tun || features.DefaultTun || features.StrictMode {
		return fmt.Errorf(
			"matcher-only features = %+v, want no TUN/DefaultTun/StrictMode",
			features,
		)
	}
	rules := system.ListRules()
	if len(rules.MatcherRules) != 8 {
		return fmt.Errorf(
			"matcher-only MatcherRules len = %d, want 8",
			len(rules.MatcherRules),
		)
	}
	if len(rules.TunRules) != 0 {
		return fmt.Errorf(
			"matcher-only TunRules len = %d, want 0 without pmark",
			len(rules.TunRules),
		)
	}
	matcher, err := system.BuildMatcher(sysnet.Rule{
		Type: "pid",
		Rule: strconv.Itoa(os.Getpid()),
	})
	if err != nil {
		return fmt.Errorf("matcher-only BuildMatcher: %w", err)
	}
	if err := matcher.Close(); err != nil {
		return fmt.Errorf("matcher-only matcher close: %w", err)
	}
	return nil
}

func checkFeaturesAndRules(system *linux.System) error {
	features := system.Features()
	if !features.Tun || !features.DefaultTun || !features.StrictMode {
		return fmt.Errorf(
			"features = %+v, want TUN, DefaultTun, StrictMode",
			features,
		)
	}
	rules := system.ListRules()
	if len(rules.TunRules) != 8 {
		return fmt.Errorf("TunRules len = %d, want 8", len(rules.TunRules))
	}
	if len(rules.MatcherRules) != 8 {
		return fmt.Errorf(
			"MatcherRules len = %d, want 8",
			len(rules.MatcherRules),
		)
	}
	if !system.RuleVerify(
		sysnet.Rule{Type: "pid", Rule: strconv.Itoa(os.Getpid())},
	) {
		return fmt.Errorf("pid rule did not verify")
	}
	return nil
}

func checkInvalidRules(system *linux.System) error {
	cases := []ruleCase{
		{
			name: "unknown type",
			rule: sysnet.Rule{Type: "unknown", Rule: "1"},
		},
		{
			name: "bad regexp",
			rule: sysnet.Rule{Type: "comm", Rule: "["},
		},
		{
			name: "relative exec path",
			rule: sysnet.Rule{Type: "exec", Rule: "./curl"},
		},
		{
			name: "negative pid",
			rule: sysnet.Rule{Type: "pid", Rule: "-1"},
		},
		{
			name: "mixed uid list",
			rule: sysnet.Rule{Type: "uid", Rule: "0 nope"},
		},
		{
			name: "missing user",
			rule: sysnet.Rule{Type: "user", Rule: "sysnet-e2e-missing-user"},
		},
		{
			name: "missing group",
			rule: sysnet.Rule{Type: "group", Rule: "sysnet-e2e-missing-group"},
		},
	}
	for _, tc := range cases {
		if system.RuleVerify(tc.rule) {
			return fmt.Errorf(
				"%s RuleVerify(%+v) = true, want false",
				tc.name,
				tc.rule,
			)
		}
		if err := system.VerifyDefaultTunOpts(sysnet.DefaultTunOpts{
			TunAddrs: []string{dnsIP + "/32"},
			DnsIP:    dnsIP,
			Exclude:  []sysnet.Rule{tc.rule},
		}); err == nil {
			return fmt.Errorf(
				"%s VerifyDefaultTunOpts succeeded, want error",
				tc.name,
			)
		}
		if _, err := system.BuildMatcher(tc.rule); err == nil {
			return fmt.Errorf("%s BuildMatcher succeeded, want error", tc.name)
		}
	}
	if err := system.VerifyDefaultTunOpts(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		Exclude:  []sysnet.Rule{{Type: "pid", Rule: strconv.Itoa(os.Getpid())}},
		Include:  []sysnet.Rule{{Type: "uid", Rule: strconv.Itoa(os.Getuid())}},
	}); err == nil {
		return fmt.Errorf(
			"VerifyDefaultTunOpts with exclude and include succeeded, want error",
		)
	}
	return nil
}

func checkValidRuleBoundaries(system *linux.System) error {
	info, _, err := currentProcessRuleCases()
	if err != nil {
		return err
	}
	cases := []ruleCase{
		{
			name: "exec absolute wildcard",
			rule: sysnet.Rule{
				Type: "exec",
				Rule: filepath.Dir(info.Exe) + "/*",
			},
		},
		{
			name: "exec absolute exact path",
			rule: sysnet.Rule{Type: "exec", Rule: info.Exe},
		},
		{
			name: "pid list",
			rule: sysnet.Rule{
				Type: "pid",
				Rule: "1 " + strconv.Itoa(os.Getpid()),
			},
		},
		{
			name: "uid list",
			rule: sysnet.Rule{
				Type: "uid",
				Rule: "0 " + strconv.Itoa(os.Getuid()),
			},
		},
		{
			name: "gid list",
			rule: sysnet.Rule{
				Type: "gid",
				Rule: "0 " + strconv.Itoa(os.Getgid()),
			},
		},
	}
	for _, tc := range cases {
		if !system.RuleVerify(tc.rule) {
			return fmt.Errorf(
				"%s RuleVerify(%+v) = false, want true",
				tc.name,
				tc.rule,
			)
		}
		if err := system.VerifyDefaultTunOpts(sysnet.DefaultTunOpts{
			TunAddrs: []string{dnsIP + "/32"},
			DnsIP:    dnsIP,
			Exclude:  []sysnet.Rule{tc.rule},
		}); err != nil {
			return fmt.Errorf("%s VerifyDefaultTunOpts: %w", tc.name, err)
		}
		matcher, err := system.BuildMatcher(tc.rule)
		if err != nil {
			return fmt.Errorf("%s BuildMatcher: %w", tc.name, err)
		}
		if err := matcher.Close(); err != nil {
			return fmt.Errorf("%s matcher close: %w", tc.name, err)
		}
	}
	return nil
}

func checkRegularTun(system *linux.System) error {
	t, err := system.BuildTun(sysnet.TunOpts{
		TunAddrs: []string{"127.0.0.1/8", "10.67.0.1/32"},
		MTU:      1300,
	})
	if err != nil {
		return fmt.Errorf("build regular TUN: %w", err)
	}
	defer func() { _ = t.Close() }()

	addrs, err := system.GetTunAddrs(t)
	if err != nil {
		return fmt.Errorf("get regular TUN addrs: %w", err)
	}
	if !contains(addrs, "10.67.0.1/32") || contains(addrs, "127.0.0.1/8") {
		return fmt.Errorf(
			"regular TUN addrs = %v, want normalized 10.67.0.1/32",
			addrs,
		)
	}
	if err := system.SetTunMTU(
		nil,
		1400,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf("SetTunMTU(nil) = %v, want ErrUnknownTun", err)
	}
	if err := system.AddTunAddr(nil, "10.67.0.2/32"); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf("AddTunAddr(nil) = %v, want ErrUnknownTun", err)
	}
	if _, err := system.GetTunAddrs(nil); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf("GetTunAddrs(nil) = %v, want ErrUnknownTun", err)
	}
	if err := system.SetTunRoutes(nil, []string{"10.68.0.0/24"}); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf("SetTunRoutes(nil) = %v, want ErrUnknownTun", err)
	}
	if err := system.AddTunRoute(nil, "10.68.1.0/24"); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf("AddTunRoute(nil) = %v, want ErrUnknownTun", err)
	}
	if _, err := system.GetTunRotue(nil); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf("GetTunRotue(nil) = %v, want ErrUnknownTun", err)
	}
	if _, err := system.SetTunName(nil); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf("SetTunName(nil) = %v, want ErrUnknownTun", err)
	}
	return nil
}

func checkDefaultTunFallbackDNS(system *linux.System) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"127.0.0.1/8"},
		DnsIP:    "127.0.0.1",
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf("build fallback DNS DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("fallback DNS DefaultTun name: %w", err)
	}
	addrs, err := linkAddrPrefixes(tunName)
	if err != nil {
		return fmt.Errorf("get fallback DNS DefaultTun link addrs: %w", err)
	}
	if contains(addrs, "127.0.0.1/8") {
		return fmt.Errorf(
			"fallback DNS DefaultTun addrs = %v, want no loopback",
			addrs,
		)
	}
	server, err := waitForResolvconfAny()
	if err != nil {
		return err
	}
	if server == "127.0.0.1" || server == dnsIP {
		return fmt.Errorf(
			"fallback DNS server = %s, want allocator-selected non-loopback IP",
			server,
		)
	}
	if !tunAddrsContainIP(addrs, server) {
		return fmt.Errorf(
			"fallback DNS server = %s, DefaultTun addrs = %v, want DNS server on TUN",
			server,
			addrs,
		)
	}
	if err := expectDNSRCodeAt(
		"fallback detached DefaultTun DNS",
		server,
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answer := netip.MustParseAddr("203.0.113.99")
	dt.SetDns(newStaticDNS(answer))
	if err := expectDNSAAt(
		"fallback attached DefaultTun DNS",
		server,
		answer,
	); err != nil {
		return err
	}
	if err := dt.Close(); err != nil {
		return fmt.Errorf("close fallback DNS DefaultTun: %w", err)
	}
	if err := waitForResolvconfNot(server); err != nil {
		return err
	}
	return nil
}

func checkDefaultTunLifecycle(
	system *linux.System,
	pmarkCtl *recordingPmark,
) error {
	pid := strconv.Itoa(os.Getpid())
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Exclude:  []sysnet.Rule{{Type: "pid", Rule: pid}},
	})
	if err != nil {
		return fmt.Errorf("build exclude DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("default TUN name: %w", err)
	}
	if err := waitForResolvconf(dnsIP); err != nil {
		return err
	}
	if err := expectDNSRCode(
		"detached DefaultTun DNS",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answerA := netip.MustParseAddr("203.0.113.77")
	answerB := netip.MustParseAddr("203.0.113.88")
	dt.SetDns(newStaticDNS(answerA))
	if err := expectDNSA("attached DefaultTun DNS", answerA); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude unmarked public route",
		"9.9.9.9",
		0,
		"dev "+tunName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude user-mark public route",
		"9.9.9.9",
		userMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude app-bypass public route",
		"9.9.9.9",
		routing.DefaultAppBypassMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectPmark(pmarkCtl, true); err != nil {
		return err
	}

	rebuilt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Include:  []sysnet.Rule{{Type: "pid", Rule: pid}},
	})
	if err != nil {
		return fmt.Errorf("rebuild include DefaultTun: %w", err)
	}
	defer func() { _ = rebuilt.Close() }()
	rebuiltName, err := rebuilt.Name()
	if err != nil {
		return fmt.Errorf("rebuilt default TUN name: %w", err)
	}
	if rebuiltName != tunName {
		return fmt.Errorf(
			"rebuild created %s, want existing TUN %s",
			rebuiltName,
			tunName,
		)
	}
	if err := dt.Close(); err != nil {
		return fmt.Errorf("close stale DefaultTun wrapper: %w", err)
	}
	if err := expectRoute(
		"stale close leaves include route active",
		"9.9.9.9",
		userMark,
		"dev "+tunName,
	); err != nil {
		return err
	}
	if _, err := system.SetTunName(rebuilt); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf(
			"SetTunName(DefaultTun) = %v, want ErrUnknownTun",
			err,
		)
	}

	dt.SetDns(newStaticDNS(answerB))
	if err := expectDNSRCode(
		"old DefaultTun wrapper after rebuild",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	rebuilt.SetDns(newStaticDNS(answerB))
	if err := expectDNSA("rebuilt DefaultTun DNS", answerB); err != nil {
		return err
	}
	if err := expectRoute(
		"include unmarked public route",
		"9.9.9.9",
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include user-mark public route",
		"9.9.9.9",
		userMark,
		"dev "+tunName,
	); err != nil {
		return err
	}
	if err := rebuilt.Close(); err != nil {
		return fmt.Errorf("close rebuilt DefaultTun: %w", err)
	}
	if err := waitForResolvconfNot(dnsIP); err != nil {
		return err
	}
	if err := expectRoute(
		"closed DefaultTun public route",
		"9.9.9.9",
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	return nil
}

func checkDefaultTunRebuildDNSMutation(system *linux.System) error {
	const rebuiltDNSIP = "10.66.0.9"

	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf("build DNS mutation DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("DNS mutation DefaultTun name: %w", err)
	}
	if err := waitForResolvconf(dnsIP); err != nil {
		return err
	}
	answerA := netip.MustParseAddr("203.0.113.101")
	dt.SetDns(newStaticDNS(answerA))
	if err := expectDNSA(
		"DNS mutation initial attached DNS",
		answerA,
	); err != nil {
		return err
	}

	rebuilt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{rebuiltDNSIP + "/32"},
		DnsIP:    rebuiltDNSIP,
		MTU:      1350,
		Strict:   true,
	})
	if err != nil {
		return fmt.Errorf("rebuild DNS mutation DefaultTun: %w", err)
	}
	defer func() { _ = rebuilt.Close() }()
	rebuiltName, err := rebuilt.Name()
	if err != nil {
		return fmt.Errorf("DNS mutation rebuilt DefaultTun name: %w", err)
	}
	if rebuiltName != tunName {
		return fmt.Errorf(
			"DNS mutation rebuild created %s, want existing TUN %s",
			rebuiltName,
			tunName,
		)
	}
	if err := waitForResolvconf(rebuiltDNSIP); err != nil {
		return err
	}
	if err := waitForResolvconfNot(dnsIP); err != nil {
		return err
	}
	addrs, err := linkAddrPrefixes(rebuiltName)
	if err != nil {
		return fmt.Errorf("DNS mutation rebuilt link addrs: %w", err)
	}
	if !tunAddrsContainIP(addrs, rebuiltDNSIP) ||
		tunAddrsContainIP(addrs, dnsIP) {
		return fmt.Errorf(
			"DNS mutation rebuilt addrs = %v, want %s and not %s",
			addrs,
			rebuiltDNSIP,
			dnsIP,
		)
	}
	if err := dt.Close(); err != nil {
		return fmt.Errorf(
			"close stale DNS mutation DefaultTun wrapper: %w",
			err,
		)
	}
	if err := expectDNSRCodeAt(
		"DNS mutation rebuilt starts detached",
		rebuiltDNSIP,
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	dt.SetDns(newStaticDNS(netip.MustParseAddr("203.0.113.102")))
	if err := expectDNSRCodeAt(
		"DNS mutation old wrapper after rebuild",
		rebuiltDNSIP,
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answerB := netip.MustParseAddr("203.0.113.103")
	rebuilt.SetDns(newStaticDNS(answerB))
	if err := expectDNSAAt(
		"DNS mutation rebuilt attached DNS",
		rebuiltDNSIP,
		answerB,
	); err != nil {
		return err
	}
	rebuilt.SetDns(nil)
	if err := expectDNSRCodeAt(
		"DNS mutation rebuilt detached with nil DNS",
		rebuiltDNSIP,
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	if err := rebuilt.Close(); err != nil {
		return fmt.Errorf("close DNS mutation rebuilt DefaultTun: %w", err)
	}
	if err := waitForResolvconfNot(rebuiltDNSIP); err != nil {
		return err
	}
	return nil
}

func checkDefaultTunUnderlyingLinkRecreate(system *linux.System) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf("build link recreate DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	oldName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("link recreate DefaultTun name: %w", err)
	}
	oldIndex, err := linkIndex(oldName)
	if err != nil {
		return fmt.Errorf("link recreate DefaultTun ifindex: %w", err)
	}
	if err := waitForResolvconf(dnsIP); err != nil {
		return err
	}
	answerA := netip.MustParseAddr("203.0.113.131")
	dt.SetDns(newStaticDNS(answerA))
	if err := expectDNSA(
		"link recreate initial attached DNS",
		answerA,
	); err != nil {
		return err
	}

	if err := ip("link", "del", oldName); err != nil {
		return fmt.Errorf("delete DefaultTun link %s: %w", oldName, err)
	}
	if err := waitForLinkGone(oldName); err != nil {
		return err
	}
	if err := expectDNSQueryFailureAt(
		"link recreate deleted link DNS",
		dnsIP,
	); err != nil {
		return err
	}

	rebuilt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1350,
		Strict:   true,
	})
	if err != nil {
		return fmt.Errorf("rebuild deleted-link DefaultTun: %w", err)
	}
	defer func() { _ = rebuilt.Close() }()
	newName, err := rebuilt.Name()
	if err != nil {
		return fmt.Errorf("deleted-link rebuilt DefaultTun name: %w", err)
	}
	newIndex, err := linkIndex(newName)
	if err != nil {
		return fmt.Errorf("deleted-link rebuilt DefaultTun ifindex: %w", err)
	}
	if newIndex == oldIndex {
		return fmt.Errorf(
			"deleted-link rebuilt ifindex = %d, want different from old %d",
			newIndex,
			oldIndex,
		)
	}
	if err := waitForResolvconf(dnsIP); err != nil {
		return err
	}
	addrs, err := linkAddrPrefixes(newName)
	if err != nil {
		return fmt.Errorf("deleted-link rebuilt link addrs: %w", err)
	}
	if !tunAddrsContainIP(addrs, dnsIP) {
		return fmt.Errorf(
			"deleted-link rebuilt addrs = %v, want %s",
			addrs,
			dnsIP,
		)
	}
	if err := expectRoute(
		"deleted-link rebuilt unmarked public route",
		"9.9.9.9",
		0,
		"dev "+newName,
	); err != nil {
		return err
	}
	if err := expectDNSRCode(
		"deleted-link rebuilt starts detached",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	dt.SetDns(newStaticDNS(netip.MustParseAddr("203.0.113.132")))
	if err := expectDNSRCode(
		"deleted-link stale wrapper after rebuild",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answerB := netip.MustParseAddr("203.0.113.133")
	rebuilt.SetDns(newStaticDNS(answerB))
	if err := expectDNSA(
		"deleted-link rebuilt attached DNS",
		answerB,
	); err != nil {
		return err
	}
	if err := rebuilt.Close(); err != nil {
		return fmt.Errorf("close deleted-link rebuilt DefaultTun: %w", err)
	}
	if err := waitForResolvconfNot(dnsIP); err != nil {
		return err
	}
	return nil
}

func checkResolvedDefaultTunLifecycle(
	system *linux.System,
	pmarkCtl *recordingPmark,
) error {
	pid := strconv.Itoa(os.Getpid())
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Exclude:  []sysnet.Rule{{Type: "pid", Rule: pid}},
	})
	if err != nil {
		return fmt.Errorf("build resolved exclude DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("resolved default TUN name: %w", err)
	}
	if err := waitForResolvedLinkDNS(tunName, dnsIP); err != nil {
		return err
	}
	if err := expectDNSRCodeAt(
		"resolved detached DefaultTun DNS",
		"127.0.0.53",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answerA := netip.MustParseAddr("203.0.113.177")
	answerB := netip.MustParseAddr("203.0.113.188")
	dt.SetDns(newStaticDNS(answerA))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSAAt(
		"resolved attached DefaultTun DNS",
		"127.0.0.53",
		answerA,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"resolved exclude unmarked public route",
		"9.9.9.9",
		0,
		"dev "+tunName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"resolved exclude user-mark public route",
		"9.9.9.9",
		userMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectPmark(pmarkCtl, true); err != nil {
		return err
	}

	rebuilt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Include:  []sysnet.Rule{{Type: "pid", Rule: pid}},
	})
	if err != nil {
		return fmt.Errorf("rebuild resolved include DefaultTun: %w", err)
	}
	defer func() { _ = rebuilt.Close() }()
	rebuiltName, err := rebuilt.Name()
	if err != nil {
		return fmt.Errorf("resolved rebuilt default TUN name: %w", err)
	}
	if rebuiltName != tunName {
		return fmt.Errorf(
			"resolved rebuild created %s, want existing TUN %s",
			rebuiltName,
			tunName,
		)
	}
	if err := waitForResolvedLinkDNS(rebuiltName, dnsIP); err != nil {
		return err
	}
	dt.SetDns(newStaticDNS(answerB))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSRCodeAt(
		"resolved old DefaultTun wrapper after rebuild",
		"127.0.0.53",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	rebuilt.SetDns(newStaticDNS(answerB))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSAAt(
		"resolved rebuilt DefaultTun DNS",
		"127.0.0.53",
		answerB,
	); err != nil {
		return err
	}
	if err := rebuilt.Close(); err != nil {
		return fmt.Errorf("close resolved rebuilt DefaultTun: %w", err)
	}
	if err := waitForResolvedLinkDNSNot(rebuiltName, dnsIP); err != nil {
		return err
	}
	return nil
}

func checkResolvedDefaultTunRebuildDNSMutation(system *linux.System) error {
	const rebuiltDNSIP = "10.66.0.9"

	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf("build resolved DNS mutation DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("resolved DNS mutation DefaultTun name: %w", err)
	}
	if err := waitForResolvedLinkDNS(tunName, dnsIP); err != nil {
		return err
	}
	answerA := netip.MustParseAddr("203.0.113.201")
	dt.SetDns(newStaticDNS(answerA))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSAAt(
		"resolved DNS mutation initial attached DNS",
		"127.0.0.53",
		answerA,
	); err != nil {
		return err
	}

	rebuilt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{rebuiltDNSIP + "/32"},
		DnsIP:    rebuiltDNSIP,
		MTU:      1350,
		Strict:   true,
	})
	if err != nil {
		return fmt.Errorf("rebuild resolved DNS mutation DefaultTun: %w", err)
	}
	defer func() { _ = rebuilt.Close() }()
	rebuiltName, err := rebuilt.Name()
	if err != nil {
		return fmt.Errorf(
			"resolved DNS mutation rebuilt DefaultTun name: %w",
			err,
		)
	}
	if rebuiltName != tunName {
		return fmt.Errorf(
			"resolved DNS mutation rebuild created %s, want existing TUN %s",
			rebuiltName,
			tunName,
		)
	}
	if err := waitForResolvedLinkDNS(rebuiltName, rebuiltDNSIP); err != nil {
		return err
	}
	if err := waitForResolvedLinkDNSNot(rebuiltName, dnsIP); err != nil {
		return err
	}
	addrs, err := linkAddrPrefixes(rebuiltName)
	if err != nil {
		return fmt.Errorf("resolved DNS mutation rebuilt link addrs: %w", err)
	}
	if !tunAddrsContainIP(addrs, rebuiltDNSIP) ||
		tunAddrsContainIP(addrs, dnsIP) {
		return fmt.Errorf(
			"resolved DNS mutation rebuilt addrs = %v, want %s and not %s",
			addrs,
			rebuiltDNSIP,
			dnsIP,
		)
	}
	if err := dt.Close(); err != nil {
		return fmt.Errorf(
			"close stale resolved DNS mutation DefaultTun wrapper: %w",
			err,
		)
	}
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSRCodeAt(
		"resolved DNS mutation rebuilt starts detached",
		"127.0.0.53",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	dt.SetDns(newStaticDNS(netip.MustParseAddr("203.0.113.202")))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSRCodeAt(
		"resolved DNS mutation old wrapper after rebuild",
		"127.0.0.53",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answerB := netip.MustParseAddr("203.0.113.203")
	rebuilt.SetDns(newStaticDNS(answerB))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSAAt(
		"resolved DNS mutation rebuilt attached DNS",
		"127.0.0.53",
		answerB,
	); err != nil {
		return err
	}
	rebuilt.SetDns(nil)
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSRCodeAt(
		"resolved DNS mutation rebuilt detached with nil DNS",
		"127.0.0.53",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	if err := rebuilt.Close(); err != nil {
		return fmt.Errorf(
			"close resolved DNS mutation rebuilt DefaultTun: %w",
			err,
		)
	}
	if err := waitForResolvedLinkDNSNot(rebuiltName, rebuiltDNSIP); err != nil {
		return err
	}
	return nil
}

func checkResolvedDefaultTunUnderlyingLinkRecreate(system *linux.System) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf("build resolved link recreate DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	oldName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("resolved link recreate DefaultTun name: %w", err)
	}
	oldIndex, err := linkIndex(oldName)
	if err != nil {
		return fmt.Errorf("resolved link recreate DefaultTun ifindex: %w", err)
	}
	if err := waitForResolvedLinkDNS(oldName, dnsIP); err != nil {
		return err
	}
	answerA := netip.MustParseAddr("203.0.113.231")
	dt.SetDns(newStaticDNS(answerA))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSAAt(
		"resolved link recreate initial attached DNS",
		"127.0.0.53",
		answerA,
	); err != nil {
		return err
	}

	if err := ip("link", "del", oldName); err != nil {
		return fmt.Errorf(
			"delete resolved DefaultTun link %s: %w",
			oldName,
			err,
		)
	}
	if err := waitForLinkGone(oldName); err != nil {
		return err
	}
	if err := waitForResolvedLinkDNSNot(oldName, dnsIP); err != nil {
		return err
	}
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSNonSuccessAt(
		"resolved link recreate deleted link DNS",
		"127.0.0.53",
	); err != nil {
		return err
	}

	rebuilt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1350,
		Strict:   true,
	})
	if err != nil {
		return fmt.Errorf("rebuild resolved deleted-link DefaultTun: %w", err)
	}
	defer func() { _ = rebuilt.Close() }()
	newName, err := rebuilt.Name()
	if err != nil {
		return fmt.Errorf(
			"resolved deleted-link rebuilt DefaultTun name: %w",
			err,
		)
	}
	newIndex, err := linkIndex(newName)
	if err != nil {
		return fmt.Errorf(
			"resolved deleted-link rebuilt DefaultTun ifindex: %w",
			err,
		)
	}
	if newIndex == oldIndex {
		return fmt.Errorf(
			"resolved deleted-link rebuilt ifindex = %d, want different from old %d",
			newIndex,
			oldIndex,
		)
	}
	if err := waitForResolvedLinkDNS(newName, dnsIP); err != nil {
		return err
	}
	addrs, err := linkAddrPrefixes(newName)
	if err != nil {
		return fmt.Errorf("resolved deleted-link rebuilt link addrs: %w", err)
	}
	if !tunAddrsContainIP(addrs, dnsIP) {
		return fmt.Errorf(
			"resolved deleted-link rebuilt addrs = %v, want %s",
			addrs,
			dnsIP,
		)
	}
	if err := expectRoute(
		"resolved deleted-link rebuilt unmarked public route",
		"9.9.9.9",
		0,
		"dev "+newName,
	); err != nil {
		return err
	}
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSRCodeAt(
		"resolved deleted-link rebuilt starts detached",
		"127.0.0.53",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	dt.SetDns(newStaticDNS(netip.MustParseAddr("203.0.113.232")))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSRCodeAt(
		"resolved deleted-link stale wrapper after rebuild",
		"127.0.0.53",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answerB := netip.MustParseAddr("203.0.113.233")
	rebuilt.SetDns(newStaticDNS(answerB))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSAAt(
		"resolved deleted-link rebuilt attached DNS",
		"127.0.0.53",
		answerB,
	); err != nil {
		return err
	}
	if err := rebuilt.Close(); err != nil {
		return fmt.Errorf(
			"close resolved deleted-link rebuilt DefaultTun: %w",
			err,
		)
	}
	if err := waitForResolvedLinkDNSNot(newName, dnsIP); err != nil {
		return err
	}
	return nil
}

func checkResolvedDefaultTunFallbackDNS(
	system *linux.System,
	label string,
) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"127.0.0.1/8"},
		DnsIP:    "127.0.0.1",
		MTU:      1400,
	})
	if err != nil {
		return fmt.Errorf("%s build fallback DNS DefaultTun: %w", label, err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("%s fallback DNS DefaultTun name: %w", label, err)
	}
	addrs, err := linkAddrPrefixes(tunName)
	if err != nil {
		return fmt.Errorf(
			"%s get fallback DNS DefaultTun link addrs: %w",
			label,
			err,
		)
	}
	if contains(addrs, "127.0.0.1/8") {
		return fmt.Errorf(
			"%s fallback DNS DefaultTun addrs = %v, want no loopback",
			label,
			addrs,
		)
	}
	server, err := waitForResolvedLinkDNSAny(tunName)
	if err != nil {
		return fmt.Errorf("%s fallback resolved link DNS: %w", label, err)
	}
	if server == "127.0.0.1" || server == dnsIP {
		return fmt.Errorf(
			"%s fallback DNS server = %s, want allocator-selected non-loopback IP",
			label,
			server,
		)
	}
	if !tunAddrsContainIP(addrs, server) {
		return fmt.Errorf(
			"%s fallback DNS server = %s, DefaultTun addrs = %v, want DNS server on TUN",
			label,
			server,
			addrs,
		)
	}
	if err := expectDNSRCodeAt(
		label+" fallback detached DefaultTun DNS",
		"127.0.0.53",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answer := netip.MustParseAddr("203.0.113.199")
	dt.SetDns(newStaticDNS(answer))
	if err := flushResolvedCaches(); err != nil {
		return err
	}
	if err := expectDNSAAt(
		label+" fallback attached DefaultTun DNS",
		"127.0.0.53",
		answer,
	); err != nil {
		return err
	}
	if err := dt.Close(); err != nil {
		return fmt.Errorf("%s close fallback DNS DefaultTun: %w", label, err)
	}
	if err := waitForResolvedLinkDNSNot(tunName, server); err != nil {
		return fmt.Errorf(
			"%s fallback resolved link DNS rollback: %w",
			label,
			err,
		)
	}
	return nil
}

type ruleCase struct {
	name string
	rule sysnet.Rule
}

func checkDefaultTunRuleContexts(
	system *linux.System,
	pmarkCtl *recordingPmark,
) error {
	info, cases, err := currentProcessRuleCases()
	if err != nil {
		return err
	}
	for _, contextName := range []string{"exclude", "include"} {
		for _, tc := range cases {
			opts := sysnet.DefaultTunOpts{
				TunAddrs: []string{dnsIP + "/32"},
				DnsIP:    dnsIP,
				MTU:      1400,
			}
			switch contextName {
			case "exclude":
				opts.Exclude = []sysnet.Rule{tc.rule}
			case "include":
				opts.Include = []sysnet.Rule{tc.rule}
			}
			dt, err := system.BuildDefaultTun(opts)
			if err != nil {
				return fmt.Errorf(
					"build %s DefaultTun for %s rule: %w",
					contextName,
					tc.name,
					err,
				)
			}
			if err := expectPmarkInfo(
				pmarkCtl,
				info,
				true,
				fmt.Sprintf("%s DefaultTun %s rule", contextName, tc.name),
			); err != nil {
				_ = dt.Close()
				return err
			}
			if err := dt.Close(); err != nil {
				return fmt.Errorf(
					"close %s DefaultTun for %s rule: %w",
					contextName,
					tc.name,
					err,
				)
			}
		}
	}
	return nil
}

func checkMatchers(system *linux.System, pmarkCtl *recordingPmark) error {
	info, cases, err := currentProcessRuleCases()
	if err != nil {
		return err
	}
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Exclude:  []sysnet.Rule{{Type: "pid", Rule: strconv.Itoa(os.Getpid())}},
	})
	if err != nil {
		return fmt.Errorf("build matcher DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()
	if err := expectPmarkInfo(
		pmarkCtl,
		info,
		true,
		"matcher seed pid rule",
	); err != nil {
		return err
	}

	flow, closeFlow, err := outgoingTunFlow(dt, "9.9.9.9:53")
	if err != nil {
		return err
	}
	defer closeFlow()
	if err := expectAllMatchers(
		system,
		cases,
		flow,
		"outgoing TUN packet",
	); err != nil {
		return err
	}
	if err := expectClosedMatcher(system, cases[3].rule, flow); err != nil {
		return err
	}

	localNetSystem, err := newLocalNetOnlySystem()
	if err != nil {
		return err
	}
	defer func() { _ = localNetSystem.Close() }()
	localFlow, closeLocalFlow, err := acceptedLocalNetFlow(localNetSystem)
	if err != nil {
		return err
	}
	defer closeLocalFlow()
	if err := expectAllMatchers(
		system,
		cases,
		localFlow,
		"LocalNet accepted connection",
	); err != nil {
		return err
	}
	return nil
}

func newLocalNetOnlySystem() (*linux.System, error) {
	system, err := linux.NewSystem(linux.Config{
		Features: linux.FeatureConfig{
			MatcherRules: true,
		},
		RuleTracker: multirule.New(),
		OwnerLookup: sockowner.GetSockOwner,
		UserMark:    userMark,
	})
	if err != nil {
		return nil, fmt.Errorf("create LocalNet-only System: %w", err)
	}
	return system, nil
}

func checkFullPmarkEBPFSetup() error {
	harness, err := newPmarkEBPFHarness()
	if err != nil {
		return err
	}
	defer harness.Close()

	if err := checkPmarkEBPFSocketProbe(harness.system); err != nil {
		return err
	}
	if err := checkPmarkEBPFVTunCurl(harness.system); err != nil {
		return err
	}
	return nil
}

func checkAutoNewPmarkCurrentProcessSetup() error {
	cleanupBPFFS, err := prepareBPFFS()
	if err != nil {
		return err
	}
	defer cleanupBPFFS()

	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "sysnet-e2e-auto-pmark-")
	if err != nil {
		return fmt.Errorf("create auto New pmark pin path: %w", err)
	}
	defer func() { _ = os.RemoveAll(pinPath) }()

	system, err := linux.New(linux.SystemConfig{
		DNS: linux.DNSConfig{
			Mode: linux.DNSModeDirect,
			FallbackServers: []netip.AddrPort{
				netip.MustParseAddrPort("1.1.1.1:53"),
			},
		},
		Pmark:    linux.PmarkConfig{PinPath: pinPath},
		UserMark: userMark,
		Logf:     log.Printf,
	})
	if err != nil {
		return fmt.Errorf("auto New pmark System: %w", err)
	}
	defer func() { _ = system.Close() }()

	features := system.Features()
	rules := system.ListRules()
	if len(rules.TunRules) != 8 {
		return fmt.Errorf(
			"auto New pmark TunRules len = %d with features %+v, want 8",
			len(rules.TunRules),
			features,
		)
	}

	probeConn, err := net.Dial("udp4", "9.9.9.9:53")
	if err != nil {
		return fmt.Errorf("auto New pmark open probe socket: %w", err)
	}
	defer func() { _ = probeConn.Close() }()

	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Include: []sysnet.Rule{{
			Type: "pid",
			Rule: strconv.Itoa(os.Getpid()),
		}},
	})
	if err != nil {
		return fmt.Errorf("auto New pmark build DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("auto New pmark DefaultTun name: %w", err)
	}
	if err := expectRoute(
		"auto New pmark unmarked public route",
		"9.9.9.9",
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"auto New pmark user-mark public route",
		"9.9.9.9",
		userMark,
		"dev "+tunName,
	); err != nil {
		return err
	}
	if err := waitForTimeout(5*time.Second, func() error {
		mark, err := socketMark(probeConn)
		if err != nil {
			return err
		}
		if mark != userMark {
			return fmt.Errorf("SO_MARK = %#x, want %#x", mark, userMark)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("auto New pmark current process socket: %w", err)
	}
	return nil
}

type pmarkEBPFHarness struct {
	system  *linux.System
	cleanup func()
}

func (h *pmarkEBPFHarness) Close() {
	if h.cleanup != nil {
		h.cleanup()
	}
}

func newPmarkEBPFHarness() (*pmarkEBPFHarness, error) {
	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	cleanupBPFFS, err := prepareBPFFS()
	if err != nil {
		return nil, err
	}
	cleanups = append(cleanups, cleanupBPFFS)

	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "sysnet-e2e-pmark-")
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create pmark pin path: %w", err)
	}
	cleanups = append(cleanups, func() { _ = os.RemoveAll(pinPath) })

	daemon, err := pmark.NewDaemon(
		pinPath,
		pmark.Callbacks{Logf: log.Printf},
		0,
		0,
	)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create pmark daemon: %w", err)
	}
	cleanups = append(cleanups, func() { _ = daemon.Close() })

	fwmarks, err := fwmark.NewManager(pinPath, log.Printf)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create fwmark eBPF manager: %w", err)
	}
	cleanups = append(cleanups, func() { _ = fwmarks.Close() })

	fwmarkUpdate := fwmarks.ProcessUpdateCallback()
	daemon.UpdateHooks(pmark.Callbacks{
		ProcessUpdate: fwmarkUpdate,
		Logf:          log.Printf,
	})
	if err := daemon.Run(); err != nil {
		cleanup()
		return nil, fmt.Errorf("run pmark daemon: %w", err)
	}

	system, err := newSystem(daemon)
	if err != nil {
		cleanup()
		return nil, err
	}
	cleanups = append(cleanups, func() { _ = system.Close() })

	return &pmarkEBPFHarness{system: system, cleanup: cleanup}, nil
}

func checkPmarkEBPFSocketProbe(system *linux.System) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Include: []sysnet.Rule{{
			Type: "comm",
			Rule: socketProbeComm,
		}},
	})
	if err != nil {
		return fmt.Errorf("build pmark eBPF DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("pmark eBPF default TUN name: %w", err)
	}
	if err := expectRoute(
		"pmark eBPF unmarked public route",
		"9.9.9.9",
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"pmark eBPF user-mark public route",
		"9.9.9.9",
		userMark,
		"dev "+tunName,
	); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	output, err := commandOutputContext(
		ctx,
		os.Args[0],
		socketProbeMode,
		"9.9.9.9:53",
		dnsIP,
		fmt.Sprintf("%#x", userMark),
	)
	if err != nil {
		return fmt.Errorf(
			"run pmark eBPF socket probe with output %q: %w",
			output,
			err,
		)
	}
	return nil
}

func checkPmarkEBPFVTunCurl(system *linux.System) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Include: []sysnet.Rule{{
			Type: "comm",
			Rule: curlComm,
		}},
	})
	if err != nil {
		return fmt.Errorf("build curl pmark eBPF DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("curl pmark eBPF default TUN name: %w", err)
	}
	if err := expectRoute(
		"curl eBPF unmarked service route",
		vtunServiceIP,
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"curl eBPF marked service route",
		vtunServiceIP,
		userMark,
		"dev "+tunName,
	); err != nil {
		return err
	}

	serviceURL, stopService, err := startVTunHTTPService(dt)
	if err != nil {
		return err
	}
	defer stopService()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := commandOutputContext(
		ctx,
		"curl",
		"--fail",
		"--silent",
		"--show-error",
		"--max-time",
		"5",
		serviceURL,
	)
	if err != nil {
		return fmt.Errorf(
			"curl vtun service %s output %q: %w",
			serviceURL,
			output,
			err,
		)
	}
	if strings.TrimSpace(output) != "sysnet vtun ok" {
		return fmt.Errorf(
			"curl vtun service response = %q, want %q",
			output,
			"sysnet vtun ok",
		)
	}
	return nil
}

func startVTunHTTPService(dt sysnet.DefaultTun) (string, func(), error) {
	serviceAddr := netip.MustParseAddr(vtunServiceIP)
	serverTun, err := (&vtun.Opts{
		LocalAddrs: []netip.Addr{serviceAddr},
		Name:       "sysnet-e2e-vtun",
	}).Build()
	if err != nil {
		return "", func() {}, fmt.Errorf("build vtun service stack: %w", err)
	}
	bridgeTuns(dt, serverTun)

	listenAddr := netip.AddrPortFrom(serviceAddr, vtunHTTPPort)
	listener, err := serverTun.ListenTCPAddrPort(listenAddr)
	if err != nil {
		_ = serverTun.Close()
		return "", func() {}, fmt.Errorf("listen vtun HTTP service: %w", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "sysnet vtun ok")
		}),
	}
	serveDone := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveDone <- err
			return
		}
		serveDone <- nil
	}()

	stop := func() {
		_ = server.Close()
		_ = listener.Close()
		_ = serverTun.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				log.Printf("vtun HTTP service stopped with error: %v", err)
			}
		case <-time.After(time.Second):
			log.Printf("vtun HTTP service did not stop within timeout")
		}
	}
	return "http://" + listenAddr.String() + "/", stop, nil
}

func bridgeTuns(a, b gtun.Tun) {
	done := make(chan struct{})
	go forwardTunPackets(a, b, done)
	go forwardTunPackets(b, a, done)
	go func() {
		for range b.Events() {
		}
		close(done)
	}()
}

func forwardTunPackets(src, dst gtun.Tun, done <-chan struct{}) {
	readBatch := src.BatchSize()
	if readBatch < 1 {
		readBatch = 1
	}
	mtu, err := src.MTU()
	if err != nil {
		mtu = 1500
	}
	if dstMTU, err := dst.MTU(); err == nil && dstMTU > mtu {
		mtu = dstMTU
	}
	offset := max(src.MRO(), dst.MWO())
	bufs := make([][]byte, readBatch)
	sizes := make([]int, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, mtu+offset)
	}

	for {
		select {
		case <-done:
			return
		default:
		}

		n, err := src.Read(bufs, sizes, offset)
		if err != nil {
			if gtun.IsTunTermError(err) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}
		writeBufs := make([][]byte, n)
		for i := range n {
			writeBufs[i] = bufs[i][:offset+sizes[i]]
		}
		if _, err := dst.Write(
			writeBufs,
			offset,
		); err != nil &&
			gtun.IsTunTermError(err) {
			return
		}
	}
}

func prepareBPFFS() (func(), error) {
	const root = "/sys/fs/bpf"
	if err := os.MkdirAll(root, 0o755); err != nil {
		return func() {}, fmt.Errorf("create bpffs mountpoint: %w", err)
	}
	mounted, err := isBPFFS(root)
	if err != nil {
		return func() {}, err
	}
	if mounted {
		return func() {}, nil
	}
	if err := unix.Mount(
		"bpffs",
		root,
		"bpf",
		0,
		"",
	); err != nil &&
		!errors.Is(err, unix.EBUSY) {
		return func() {}, fmt.Errorf("mount bpffs at %s: %w", root, err)
	}
	mounted, err = isBPFFS(root)
	if err != nil {
		return func() {}, err
	}
	if !mounted {
		return func() {}, fmt.Errorf("%s is not bpffs after mount", root)
	}
	return func() { _ = unix.Unmount(root, 0) }, nil
}

func isBPFFS(path string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false, fmt.Errorf("statfs %s: %w", path, err)
	}
	return stat.Type == unix.BPF_FS_MAGIC, nil
}

func runSocketProbe() error {
	if len(os.Args) != 5 {
		return fmt.Errorf(
			"usage: %s %s <dst> <want-local-ip> <want-mark>",
			os.Args[0],
			socketProbeMode,
		)
	}
	dst := os.Args[2]
	wantLocal, err := netip.ParseAddr(os.Args[3])
	if err != nil {
		return fmt.Errorf("parse wanted local IP: %w", err)
	}
	rawMark, err := strconv.ParseUint(os.Args[4], 0, 32)
	if err != nil {
		return fmt.Errorf("parse wanted mark: %w", err)
	}
	wantMark := uint32(rawMark)

	var gotMark uint32
	var gotLocal netip.Addr
	if err := waitForTimeout(5*time.Second, func() error {
		mark, local, err := udpSocketMarkAndLocal(dst)
		if err != nil {
			return err
		}
		gotMark = mark
		gotLocal = local
		if mark != wantMark {
			return fmt.Errorf("SO_MARK = %#x, want %#x", mark, wantMark)
		}
		if local != wantLocal {
			return fmt.Errorf("local IP = %s, want %s", local, wantLocal)
		}
		return nil
	}); err != nil {
		return err
	}

	fmt.Printf("socket probe mark=%#x local=%s\n", gotMark, gotLocal)
	return nil
}

func udpSocketMarkAndLocal(dst string) (uint32, netip.Addr, error) {
	conn, err := net.Dial("udp4", dst)
	if err != nil {
		return 0, netip.Addr{}, fmt.Errorf("dial UDP probe socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return 0, netip.Addr{}, fmt.Errorf(
			"probe connection is %T, want *net.UDPConn",
			conn,
		)
	}
	localUDP, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, netip.Addr{}, fmt.Errorf(
			"probe local addr is %T, want *net.UDPAddr",
			udpConn.LocalAddr(),
		)
	}
	local, ok := netip.AddrFromSlice(localUDP.IP)
	if !ok {
		return 0, netip.Addr{}, fmt.Errorf(
			"parse probe local IP %v",
			localUDP.IP,
		)
	}

	mark, err := socketMark(conn)
	if err != nil {
		return 0, netip.Addr{}, err
	}
	return mark, local.Unmap(), nil
}

func socketMark(conn net.Conn) (uint32, error) {
	syscallConn, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return 0, fmt.Errorf("connection is %T, want syscall connection", conn)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("probe syscall conn: %w", err)
	}
	var mark int
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		mark, sockErr = unix.GetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_MARK,
		)
	}); err != nil {
		return 0, fmt.Errorf("probe control socket: %w", err)
	}
	if sockErr != nil {
		return 0, fmt.Errorf("get probe SO_MARK: %w", sockErr)
	}
	return uint32(mark), nil
}

func setupLinksAndMainRoutes() error {
	cleanupLinks()
	for ip("route", "del", "default") == nil {
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
	for _, name := range []string{physLinkName, peerLinkName, safeLinkName} {
		if err := ip("link", "set", name, "up"); err != nil {
			return err
		}
	}
	commands := [][]string{
		{"addr", "add", "198.51.100.2/24", "dev", physLinkName},
		{"addr", "add", "198.51.100.1/24", "dev", peerLinkName},
		{"addr", "add", "172.28.0.1/16", "dev", safeLinkName},
		{"route", "add", "default", "via", "198.51.100.1", "dev", physLinkName},
		{
			"route",
			"add",
			"172.29.0.0/16",
			"via",
			"172.28.0.254",
			"dev",
			safeLinkName,
		},
	}
	for _, args := range commands {
		if err := ip(args...); err != nil {
			return err
		}
	}
	return nil
}

func cleanupLinks() {
	_ = ip("link", "del", physLinkName)
	_ = ip("link", "del", safeLinkName)
}

func startSystemdResolved() (func(), error) {
	if err := os.MkdirAll("/run/dbus", 0o755); err != nil {
		return func() {}, fmt.Errorf("create /run/dbus: %w", err)
	}
	if err := os.MkdirAll("/etc/systemd", 0o755); err != nil {
		return func() {}, fmt.Errorf("create /etc/systemd: %w", err)
	}
	if err := os.WriteFile(
		"/etc/systemd/resolved.conf",
		[]byte("[Resolve]\nDNSStubListener=yes\nFallbackDNS=\n"),
		0o644,
	); err != nil {
		return func() {}, fmt.Errorf("write resolved.conf: %w", err)
	}
	if _, err := commandOutput(
		"dbus-daemon",
		"--system",
		"--fork",
	); err != nil {
		return func() {}, fmt.Errorf("start dbus-daemon: %w", err)
	}
	cmd := exec.Command("/lib/systemd/systemd-resolved")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return func() {}, fmt.Errorf("start systemd-resolved: %w", err)
	}
	stop := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
	if err := waitFor(func() error {
		_, err := commandOutput(
			"busctl",
			"--system",
			"call",
			"org.freedesktop.resolve1",
			"/org/freedesktop/resolve1",
			"org.freedesktop.DBus.Peer",
			"Ping",
		)
		return err
	}); err != nil {
		stop()
		return func() {}, fmt.Errorf("wait for systemd-resolved: %w", err)
	}
	if err := os.WriteFile(
		"/etc/resolv.conf",
		[]byte(
			"# sysnet system e2e systemd-resolved stub\nnameserver 127.0.0.53\n",
		),
		0o644,
	); err != nil {
		stop()
		return func() {}, fmt.Errorf("write resolved resolv.conf: %w", err)
	}
	return stop, nil
}

func expectDNSRCode(name string, code uint8) error {
	return expectDNSRCodeAt(name, dnsIP, code)
}

func expectDNSRCodeAt(name, server string, code uint8) error {
	resp, err := queryDefaultTunDNSAt(server)
	if err != nil {
		return fmt.Errorf("%s: query failed: %w", name, err)
	}
	if resp.RCode != code {
		return fmt.Errorf("%s: RCode = %d, want %d", name, resp.RCode, code)
	}
	return nil
}

func expectDNSNonSuccessAt(name, server string) error {
	resp, err := queryDefaultTunDNSAt(server)
	if err != nil {
		return fmt.Errorf("%s: query failed: %w", name, err)
	}
	if resp.RCode == gdns.RCodeSuccess {
		return fmt.Errorf("%s: RCode = success, want failure", name)
	}
	return nil
}

func expectDNSA(name string, want netip.Addr) error {
	return expectDNSAAt(name, dnsIP, want)
}

func expectDNSAAt(name, server string, want netip.Addr) error {
	resp, err := queryDefaultTunDNSAt(server)
	if err != nil {
		return fmt.Errorf("%s: query failed: %w", name, err)
	}
	if resp.RCode != gdns.RCodeSuccess {
		return fmt.Errorf("%s: RCode = %d, want success", name, resp.RCode)
	}
	for _, rr := range resp.Answers {
		if rr.Type != gdns.TypeA || len(rr.Data) != net.IPv4len {
			continue
		}
		got := netip.AddrFrom4([4]byte(rr.Data))
		if got == want {
			return nil
		}
	}
	return fmt.Errorf("%s: answers = %+v, want A %s", name, resp.Answers, want)
}

func expectDNSQueryFailureAt(name, server string) error {
	resp, err := queryDefaultTunDNSAt(server)
	if err != nil {
		return nil
	}
	return fmt.Errorf("%s: query succeeded unexpectedly: %+v", name, resp)
}

func queryDefaultTunDNS() (*gdns.Message, error) {
	return queryDefaultTunDNSAt(dnsIP)
}

func queryDefaultTunDNSAt(server string) (*gdns.Message, error) {
	client := gdns.NewClient(nil, "udp://"+net.JoinHostPort(server, "53"))
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return gdns.Query(ctx, client, &gdns.Message{
		ID:               gdns.NextID(),
		Opcode:           gdns.OpcodeQuery,
		RecursionDesired: true,
		Questions: []gdns.Question{{
			Name:  "sysnet-e2e.test.",
			Type:  gdns.TypeA,
			Class: gdns.ClassIN,
		}},
	})
}

func expectRoute(name, dst string, mark uint32, contains string) error {
	output, err := routeGet("-4", dst, mark)
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

func routeGet(family, dst string, mark uint32) (string, error) {
	args := []string{family, "route", "get", dst}
	if mark != 0 {
		args = append(args, "mark", fmt.Sprintf("%#x", mark))
	}
	return commandOutput("ip", args...)
}

func linkAddrPrefixes(name string) ([]string, error) {
	output, err := commandOutput("ip", "-o", "addr", "show", "dev", name)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i, field := range fields {
			if (field == "inet" || field == "inet6") && i+1 < len(fields) {
				addrs = append(addrs, fields[i+1])
			}
		}
	}
	return addrs, nil
}

func linkIndex(name string) (int, error) {
	output, err := commandOutput("ip", "-o", "link", "show", "dev", name)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return 0, fmt.Errorf("ip link output is empty for %s", name)
	}
	raw := strings.TrimSuffix(fields[0], ":")
	index, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse ifindex from %q: %w", output, err)
	}
	return index, nil
}

func waitForLinkGone(name string) error {
	return waitFor(func() error {
		if _, err := commandOutput(
			"ip",
			"link",
			"show",
			"dev",
			name,
		); err != nil {
			return nil
		}
		return fmt.Errorf("link %s still exists", name)
	})
}

func waitForResolvconf(server string) error {
	return waitFor(func() error {
		bs, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		if !strings.Contains(string(bs), "nameserver "+server) {
			return fmt.Errorf(
				"/etc/resolv.conf = %q",
				strings.TrimSpace(string(bs)),
			)
		}
		return nil
	})
}

func waitForResolvconfNot(server string) error {
	return waitFor(func() error {
		bs, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		if strings.Contains(string(bs), "nameserver "+server) {
			return fmt.Errorf("/etc/resolv.conf still contains %s", server)
		}
		return nil
	})
}

func waitForResolvconfAny() (string, error) {
	var server string
	err := waitFor(func() error {
		bs, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(bs), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "nameserver" {
				server = fields[1]
				return nil
			}
		}
		return fmt.Errorf(
			"/etc/resolv.conf has no nameserver: %q",
			strings.TrimSpace(string(bs)),
		)
	})
	return server, err
}

func waitForResolvedLinkDNS(ifname, server string) error {
	return waitFor(func() error {
		output, err := commandOutput("resolvectl", "dns", ifname)
		if err != nil {
			return err
		}
		if !strings.Contains(output, server) {
			return fmt.Errorf(
				"resolvectl dns %s = %q, want %s",
				ifname,
				output,
				server,
			)
		}
		return nil
	})
}

func waitForResolvedLinkDNSAny(ifname string) (string, error) {
	var server string
	err := waitFor(func() error {
		output, err := commandOutput("resolvectl", "dns", ifname)
		if err != nil {
			return err
		}
		server = firstIPInText(output)
		if server == "" {
			return fmt.Errorf(
				"resolvectl dns %s = %q, want an IP server",
				ifname,
				output,
			)
		}
		return nil
	})
	return server, err
}

func waitForResolvedLinkDNSNot(ifname, server string) error {
	return waitFor(func() error {
		output, err := commandOutput("resolvectl", "dns", ifname)
		if err != nil {
			return nil
		}
		if strings.Contains(output, server) {
			return fmt.Errorf(
				"resolvectl dns %s still contains %s: %q",
				ifname,
				server,
				output,
			)
		}
		return nil
	})
}

func flushResolvedCaches() error {
	if _, err := commandOutput("resolvectl", "flush-caches"); err != nil {
		return fmt.Errorf("flush resolved caches: %w", err)
	}
	return nil
}

func waitFor(check func() error) error {
	return waitForTimeout(3*time.Second, check)
}

func waitForTimeout(timeout time.Duration, check func() error) error {
	var last error
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := check(); err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return nil
	}
	return last
}

func expectPmark(pmarkCtl *recordingPmark, wantOK bool) error {
	info := pmark.ProcessInfo{Key: pmark.ProcessKey{Tgid: uint32(os.Getpid())}}
	return expectPmarkInfo(pmarkCtl, info, wantOK, "pmark")
}

func expectPmarkInfo(
	pmarkCtl *recordingPmark,
	info pmark.ProcessInfo,
	wantOK bool,
	name string,
) error {
	pmarkCtl.mu.Lock()
	check := pmarkCtl.check
	setCheckerCalls := pmarkCtl.setCheckerCalls
	forceCalls := pmarkCtl.forceCalls
	pmarkCtl.mu.Unlock()
	if setCheckerCalls == 0 || forceCalls == 0 || check == nil {
		return fmt.Errorf(
			"%s: pmark calls set=%d force=%d check nil=%v",
			name,
			setCheckerCalls,
			forceCalls,
			check == nil,
		)
	}
	priority, mark, ok := check(info)
	if ok != wantOK {
		return fmt.Errorf("%s: pmark check ok = %v, want %v", name, ok, wantOK)
	}
	if ok && (priority != 0 || mark != fwmark.ToMark(userMark)) {
		return fmt.Errorf(
			"%s: pmark check = (%d, %#x, true), want (0, %#x, true)",
			name,
			priority,
			mark,
			fwmark.ToMark(userMark),
		)
	}
	return nil
}

func currentProcessRuleCases() (pmark.ProcessInfo, []ruleCase, error) {
	info, err := currentProcessInfo()
	if err != nil {
		return pmark.ProcessInfo{}, nil, err
	}
	currentUser, err := osuser.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return pmark.ProcessInfo{}, nil, fmt.Errorf(
			"lookup current user: %w",
			err,
		)
	}
	currentGroup, err := osuser.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		return pmark.ProcessInfo{}, nil, fmt.Errorf(
			"lookup current group: %w",
			err,
		)
	}
	if info.Comm == "" || info.Cmdline == "" || info.Exe == "" {
		return pmark.ProcessInfo{}, nil, fmt.Errorf(
			"current process info is incomplete: %+v",
			info,
		)
	}
	cases := []ruleCase{
		{
			name: "comm",
			rule: sysnet.Rule{
				Type: "comm",
				Rule: "^" + regexp.QuoteMeta(info.Comm) + "$",
			},
		},
		{
			name: "exec",
			rule: sysnet.Rule{Type: "exec", Rule: filepath.Base(info.Exe)},
		},
		{
			name: "cmd",
			rule: sysnet.Rule{
				Type: "cmd",
				Rule: regexp.QuoteMeta(info.Cmdline),
			},
		},
		{
			name: "pid",
			rule: sysnet.Rule{Type: "pid", Rule: strconv.Itoa(os.Getpid())},
		},
		{
			name: "user",
			rule: sysnet.Rule{Type: "user", Rule: currentUser.Username},
		},
		{
			name: "uid",
			rule: sysnet.Rule{Type: "uid", Rule: strconv.Itoa(os.Getuid())},
		},
		{
			name: "group",
			rule: sysnet.Rule{Type: "group", Rule: currentGroup.Name},
		},
		{
			name: "gid",
			rule: sysnet.Rule{Type: "gid", Rule: strconv.Itoa(os.Getgid())},
		},
	}
	return info, cases, nil
}

func currentProcessInfo() (pmark.ProcessInfo, error) {
	pid := os.Getpid()
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return pmark.ProcessInfo{}, fmt.Errorf("read /proc/self/exe: %w", err)
	}
	cmdline, err := readProcCmdline(pid)
	if err != nil {
		return pmark.ProcessInfo{}, err
	}
	return pmark.ProcessInfo{
		Key:     pmark.ProcessKey{Tgid: uint32(pid)},
		PPID:    uint32(os.Getppid()),
		Comm:    readProcText(pid, "comm"),
		Cmdline: cmdline,
		Exe:     exe,
	}, nil
}

func readProcText(pid int, name string) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcCmdline(pid int) (string, error) {
	data, err := os.ReadFile(
		filepath.Join("/proc", strconv.Itoa(pid), "cmdline"),
	)
	if err != nil {
		return "", fmt.Errorf("read proc cmdline: %w", err)
	}
	parts := bytes.Split(bytes.Trim(data, "\x00"), []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) != 0 {
			out = append(out, string(part))
		}
	}
	return strings.Join(out, " "), nil
}

func outgoingTunFlow(
	dt sysnet.DefaultTun,
	dst string,
) (sockowner.FlowTuple, func(), error) {
	dstAddr, err := net.ResolveUDPAddr("udp4", dst)
	if err != nil {
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"resolve UDP flow destination: %w",
			err,
		)
	}
	conn, err := net.Dial("udp4", dst)
	if err != nil {
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"dial UDP flow for TUN matcher: %w",
			err,
		)
	}
	flowCh := make(chan sockowner.FlowTuple, 1)
	errCh := make(chan error, 1)
	go func() {
		for {
			packet, err := readOutgoingIPPacket(dt)
			if err != nil {
				errCh <- err
				return
			}
			flow, err := sockowner.FlowTupleFromOutgoingIPPacket(packet)
			if err != nil {
				continue
			}
			if flow.Proto != "udp" || flow.RemotePort != uint16(dstAddr.Port) ||
				!flow.RemoteIP.Equal(dstAddr.IP) {
				continue
			}
			flowCh <- flow
			return
		}
	}()
	send := func() error {
		_, err := conn.Write([]byte("sysnet matcher e2e"))
		return err
	}
	if err := send(); err != nil {
		_ = conn.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"write UDP flow for TUN matcher: %w",
			err,
		)
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case flow := <-flowCh:
			return flow, func() { _ = conn.Close() }, nil
		case err := <-errCh:
			_ = conn.Close()
			return sockowner.FlowTuple{}, func() {}, err
		case <-ticker.C:
			if err := send(); err != nil {
				_ = conn.Close()
				return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
					"write UDP flow for TUN matcher: %w",
					err,
				)
			}
		case <-timeout:
			_ = conn.Close()
			return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
				"timed out reading UDP packet from DefaultTun",
			)
		}
	}
}

func readOutgoingIPPacket(dt sysnet.DefaultTun) ([]byte, error) {
	batchSize := dt.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	offset := dt.MRO()
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, offset+2048)
	}
	n, err := dt.Read(bufs, sizes, offset)
	if err != nil {
		return nil, fmt.Errorf("read DefaultTun packet: %w", err)
	}
	if n < 1 || sizes[0] <= 0 {
		return nil, fmt.Errorf(
			"read DefaultTun packet count=%d size=%d",
			n,
			sizes[0],
		)
	}
	packet := append([]byte(nil), bufs[0][offset:offset+sizes[0]]...)
	return packet, nil
}

func acceptedLocalNetFlow(
	system *linux.System,
) (sockowner.FlowTuple, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	listener, err := system.LocalNet().Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"listen with LocalNet: %w",
			err,
		)
	}
	acceptCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conn
	}()
	client, err := system.LocalNet().Dial(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"dial LocalNet listener: %w",
			err,
		)
	}
	var accepted net.Conn
	select {
	case accepted = <-acceptCh:
	case err := <-errCh:
		_ = client.Close()
		_ = listener.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"accept LocalNet connection: %w",
			err,
		)
	case <-ctx.Done():
		_ = client.Close()
		_ = listener.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"accept LocalNet connection: %w",
			ctx.Err(),
		)
	}
	flow, err := sockowner.IncomingConnPeerFlow(accepted)
	if err != nil {
		_ = accepted.Close()
		_ = client.Close()
		_ = listener.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"extract LocalNet accepted flow tuple: %w",
			err,
		)
	}
	cleanup := func() {
		_ = accepted.Close()
		_ = client.Close()
		_ = listener.Close()
	}
	return *flow, cleanup, nil
}

func expectAllMatchers(
	system *linux.System,
	cases []ruleCase,
	flow sockowner.FlowTuple,
	label string,
) error {
	for _, tc := range cases {
		matcher, err := system.BuildMatcher(tc.rule)
		if err != nil {
			return fmt.Errorf("%s %s matcher build: %w", label, tc.name, err)
		}
		matched, matchErr := matcher.Match(flow)
		closeErr := matcher.Close()
		if matchErr != nil {
			return fmt.Errorf("%s %s matcher: %w", label, tc.name, matchErr)
		}
		if closeErr != nil {
			return fmt.Errorf(
				"%s %s matcher close: %w",
				label,
				tc.name,
				closeErr,
			)
		}
		if !matched {
			return fmt.Errorf(
				"%s %s matcher did not match flow %+v",
				label,
				tc.name,
				flow,
			)
		}
	}
	return nil
}

func expectClosedMatcher(
	system *linux.System,
	rule sysnet.Rule,
	flow sockowner.FlowTuple,
) error {
	matcher, err := system.BuildMatcher(rule)
	if err != nil {
		return fmt.Errorf("closed matcher build: %w", err)
	}
	if err := matcher.Close(); err != nil {
		return fmt.Errorf("closed matcher close: %w", err)
	}
	if err := matcher.Close(); err != nil {
		return fmt.Errorf("closed matcher second close: %w", err)
	}
	matched, err := matcher.Match(flow)
	if !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf(
			"closed matcher Match = (%v, %v), want net.ErrClosed",
			matched,
			err,
		)
	}
	if matched {
		return fmt.Errorf("closed matcher Match matched, want false")
	}
	return nil
}

func ip(args ...string) error {
	_, err := commandOutput("ip", args...)
	return err
}

func commandOutput(name string, args ...string) (string, error) {
	return commandOutputContext(context.Background(), name, args...)
}

func commandOutputContext(
	ctx context.Context,
	name string,
	args ...string,
) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	output := strings.TrimSpace(stdout.String() + stderr.String())
	if err != nil {
		if output == "" {
			return output, fmt.Errorf(
				"%s %s: %w",
				name,
				strings.Join(args, " "),
				err,
			)
		}
		return output, fmt.Errorf(
			"%s %s: %w",
			name,
			strings.Join(args, " "),
			errors.Join(err, errors.New(output)),
		)
	}
	return output, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func tunAddrsContainIP(addrs []string, ip string) bool {
	want, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, value := range addrs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		if prefix.Addr() == want {
			return true
		}
	}
	return false
}

func firstIPInText(text string) string {
	for _, field := range strings.Fields(text) {
		value := strings.Trim(field, "[],:;")
		if addr, err := netip.ParseAddr(value); err == nil {
			return addr.String()
		}
	}
	return ""
}

type recordingPmark struct {
	mu              sync.Mutex
	check           pmark.CheckFunc
	setCheckerCalls int
	forceCalls      int
}

func (r *recordingPmark) SetChecker(check pmark.CheckFunc) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setCheckerCalls++
	r.check = check
	return uint64(r.setCheckerCalls), nil
}

func (r *recordingPmark) ForceProcessTraversal() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forceCalls++
	return nil
}

type staticDNS struct {
	ch     chan gdns.Request
	closed chan struct{}
	answer netip.Addr
}

func newStaticDNS(answer netip.Addr) *staticDNS {
	s := &staticDNS{
		ch:     make(chan gdns.Request),
		closed: make(chan struct{}),
		answer: answer,
	}
	go s.run()
	return s
}

func (s *staticDNS) Requests() chan<- gdns.Request { return s.ch }

func (s *staticDNS) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

func (s *staticDNS) run() {
	for {
		select {
		case req := <-s.ch:
			resp := &gdns.Message{
				ID:                 req.Message.ID,
				Response:           true,
				Opcode:             req.Message.Opcode,
				RCode:              gdns.RCodeSuccess,
				RecursionDesired:   req.Message.RecursionDesired,
				RecursionAvailable: true,
				Questions: append(
					[]gdns.Question(nil),
					req.Message.Questions...),
			}
			for _, q := range req.Message.Questions {
				if q.Type == gdns.TypeA && q.Class == gdns.ClassIN {
					a4 := s.answer.As4()
					resp.Answers = append(resp.Answers, gdns.Resource{
						Name:  q.Name,
						Type:  gdns.TypeA,
						Class: gdns.ClassIN,
						TTL:   60,
						Data:  a4[:],
					})
				}
			}
			req.Reply <- gdns.Response{Message: resp}
		case <-s.closed:
			return
		}
	}
}
