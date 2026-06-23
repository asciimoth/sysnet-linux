//go:build linux

// nolint
package linux

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/multirule"
	linuxdns "github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/killswitch"
	"github.com/asciimoth/sysnet-linux/routing"
)

func TestNewAutoBuildsAvailableComponents(t *testing.T) {
	oldEnv := autoSystemEnv
	defer func() { autoSystemEnv = oldEnv }()

	closer := &fakeCloser{}
	autoSystemEnv = systemAutoEnvironment{
		hasCapability: func(int) bool { return true },
		probeTUN: func(TUNFactory) error {
			return nil
		},
		newRoutingManager: func() (RoutingManager, error) {
			return &fakeRouting{}, nil
		},
		newDNSProvider: func(
			SystemConfig,
			gonnect.Network,
			gonnect.Network,
		) (linuxdns.DNSProvider, error) {
			return newFakeDNSProvider(), nil
		},
		newPmark: func(
			SystemConfig,
			func(format string, args ...any),
		) (PmarkController, []io.Closer, error) {
			return &fakePmark{}, []io.Closer{closer}, nil
		},
		newKillswitch: func(string, killswitch.Logf) KillswitchClient {
			return &fakeKillswitch{}
		},
	}

	s, err := New(SystemConfig{
		Pmark: PmarkConfig{PinPath: filepath.Join(t.TempDir(), "pmark")},
	})
	if err != nil {
		t.Fatal(err)
	}
	features := s.Features()
	if !features.Tun || !features.DefaultTun || !features.DynTun ||
		!features.DynDefaultTun || !features.TunNames || !features.StrictMode {
		t.Fatalf("Features() = %+v, want native feature set", features)
	}
	rules := s.ListRules()
	if len(rules.TunRules) != len(supportedRules) ||
		len(rules.MatcherRules) != len(supportedRules) {
		t.Fatalf("ListRules() = %+v, want all rule contexts", rules)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !closer.closed {
		t.Fatal("auto-owned closer was not closed by System.Close")
	}
}

func TestNewAutoDegradesUnavailableComponents(t *testing.T) {
	oldEnv := autoSystemEnv
	defer func() { autoSystemEnv = oldEnv }()

	autoSystemEnv = systemAutoEnvironment{
		hasCapability: func(int) bool { return false },
		probeTUN: func(TUNFactory) error {
			t.Fatal("probeTUN should not run without CAP_NET_ADMIN")
			return nil
		},
		newRoutingManager: func() (RoutingManager, error) {
			t.Fatal(
				"routing manager should not be created without CAP_NET_ADMIN",
			)
			return nil, nil
		},
		newDNSProvider: func(
			SystemConfig,
			gonnect.Network,
			gonnect.Network,
		) (linuxdns.DNSProvider, error) {
			return nil, errors.New("no DNS backend")
		},
		newPmark: func(
			SystemConfig,
			func(format string, args ...any),
		) (PmarkController, []io.Closer, error) {
			return nil, nil, nil
		},
		newKillswitch: func(string, killswitch.Logf) KillswitchClient {
			return &fakeKillswitch{}
		},
	}

	s, err := New(SystemConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	features := s.Features()
	if features.Tun || features.DefaultTun || features.DynTun ||
		features.DynDefaultTun || features.TunNames || features.StrictMode {
		t.Fatalf(
			"Features() = %+v, want TUN/routing features disabled",
			features,
		)
	}
	if err := s.VerifyTunOpts(
		sysnet.TunOpts{},
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("VerifyTunOpts error = %v, want ErrNotSupported", err)
	}
	rules := s.ListRules()
	if len(rules.TunRules) != 0 {
		t.Fatalf("TunRules len = %d, want 0", len(rules.TunRules))
	}
	if len(rules.MatcherRules) != len(supportedRules) {
		t.Fatalf(
			"MatcherRules len = %d, want %d",
			len(rules.MatcherRules),
			len(supportedRules),
		)
	}
	if s.dnsProvider != nil || s.routingManager != nil || s.killswitch == nil ||
		s.pmark != nil {
		t.Fatalf(
			"components = dns:%v routing:%v killswitch:%v pmark:%v, want only killswitch built",
			s.dnsProvider != nil,
			s.routingManager != nil,
			s.killswitch != nil,
			s.pmark != nil,
		)
	}
}

func TestFeaturesAndRulesDegradeWithDependencies(t *testing.T) {
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:          true,
			DefaultTun:   true,
			DynTun:       true,
			StrictMode:   true,
			TunRules:     true,
			MatcherRules: true,
			DNSControl:   true,
			Routing:      true,
			Pmark:        true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: &fakeRouting{},
		Pmark:          &fakePmark{},
		TUNFactory:     &fakeTUNFactory{},
		TunConfig:      &fakeTunConfig{},
		RuleTracker:    multirule.New(),
		OwnerLookup: func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
			return &sockowner.SocketOwner{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	features := s.Features()
	if !features.Tun || !features.DefaultTun || !features.DynTun ||
		!features.StrictMode {
		t.Fatalf(
			"Features() = %+v, want tun/default/dyn/strict support",
			features,
		)
	}
	rules := s.ListRules()
	if len(rules.TunRules) != len(supportedRules) {
		t.Fatalf(
			"TunRules len = %d, want %d",
			len(rules.TunRules),
			len(supportedRules),
		)
	}
	if len(rules.MatcherRules) != len(supportedRules) {
		t.Fatalf(
			"MatcherRules len = %d, want %d",
			len(rules.MatcherRules),
			len(supportedRules),
		)
	}
}

func TestTunRulesRequirePmarkFeatureEnabled(t *testing.T) {
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:          true,
			DefaultTun:   true,
			TunRules:     true,
			MatcherRules: true,
			DNSControl:   true,
			Routing:      true,
			Pmark:        false,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: &fakeRouting{},
		Pmark:          &fakePmark{},
		TUNFactory:     &fakeTUNFactory{},
		TunConfig:      &fakeTunConfig{},
		RuleTracker:    multirule.New(),
		OwnerLookup: func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
			return &sockowner.SocketOwner{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rules := s.ListRules()
	if len(rules.TunRules) != 0 {
		t.Fatalf("TunRules len = %d, want 0", len(rules.TunRules))
	}
	if len(rules.MatcherRules) != len(supportedRules) {
		t.Fatalf(
			"MatcherRules len = %d, want %d",
			len(rules.MatcherRules),
			len(supportedRules),
		)
	}
	err = s.VerifyDefaultTunOpts(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
		Exclude:   []sysnet.Rule{{Type: "pid", Rule: "7"}},
	})
	if !errors.Is(err, sysnet.ErrNotSupported) {
		t.Fatalf("VerifyDefaultTunOpts error = %v, want ErrNotSupported", err)
	}
}

func TestRuleVerifyCoversSharedContract(t *testing.T) {
	s, err := NewSystem(Config{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		rule sysnet.Rule
		want bool
	}{
		{"comm regexp", sysnet.Rule{Type: "comm", Rule: "bash|zsh"}, true},
		{"bad regexp", sysnet.Rule{Type: "comm", Rule: "["}, false},
		{"exec basename", sysnet.Rule{Type: "exec", Rule: "bash"}, true},
		{
			"exec absolute glob",
			sysnet.Rule{Type: "exec", Rule: "/usr/bin/*"},
			true,
		},
		{"exec relative", sysnet.Rule{Type: "exec", Rule: "./bash"}, false},
		{"pid list", sysnet.Rule{Type: "pid", Rule: "1 22"}, true},
		{"bad pid", sysnet.Rule{Type: "pid", Rule: "abc"}, false},
		{"unknown", sysnet.Rule{Type: "app", Rule: "x"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.RuleVerify(tc.rule); got != tc.want {
				t.Fatalf("RuleVerify(%+v) = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

func TestRuleComplAccounts(t *testing.T) {
	passwd := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(
		passwd,
		[]byte(`root:x:0:0:root:/root:/bin/sh
alice:x:1000:1000:Alice:/home/alice:/bin/sh
alex:x:1001:1001:Alex:/home/alex:/bin/sh
duplicate:x:1000:1000:Duplicate:/home/duplicate:/bin/sh
malformed
`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	users, err := completePasswdRule("al", false, passwd)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"alex", "alice"}; !slices.Equal(users, want) {
		t.Fatalf("user completions = %#v, want %#v", users, want)
	}
	uids, err := completePasswdRule("10", true, passwd)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1000", "1001"}; !slices.Equal(uids, want) {
		t.Fatalf("uid completions = %#v, want %#v", uids, want)
	}

	group := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(
		group,
		[]byte(`root:x:0:
audio:x:29:alice
adm:x:4:alice
apps:x:1000:alex
`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	groups, err := completeGroupRule("a", false, group)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"adm", "apps", "audio"}; !slices.Equal(groups, want) {
		t.Fatalf("group completions = %#v, want %#v", groups, want)
	}
	gids, err := completeGroupRule("2", true, group)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"29"}; !slices.Equal(gids, want) {
		t.Fatalf("gid completions = %#v, want %#v", gids, want)
	}
}

func TestRuleComplExecPath(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"bash", "batch", "cat"} {
		if err := os.WriteFile(
			filepath.Join(dir, name),
			[]byte{},
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	got, err := completeExecRule(filepath.Join(dir, "ba"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "bash"), filepath.Join(dir, "batch")}
	if !slices.Equal(got, want) {
		t.Fatalf("exec completions = %#v, want %#v", got, want)
	}
	got, err = completeExecRule("ba")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("relative exec completions = %#v, want nil", got)
	}
}

func TestRuleComplExecPathIsCapped(t *testing.T) {
	dir := t.TempDir()
	for i := range 12 {
		name := "tool" + strconv.Itoa(i)
		if err := os.WriteFile(
			filepath.Join(dir, name),
			[]byte{},
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	got, err := completeExecRule(filepath.Join(dir, "tool"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxExecCompletions {
		t.Fatalf(
			"exec completions len = %d, want %d",
			len(got),
			maxExecCompletions,
		)
	}
	for _, value := range got {
		if !filepath.IsAbs(value) {
			t.Fatalf("exec completion %q is not absolute", value)
		}
	}
}

func TestRuleComplErrorsReturnNil(t *testing.T) {
	s, err := NewSystem(Config{})
	if err != nil {
		t.Fatal(err)
	}
	got := s.RuleCompl(sysnet.Rule{
		Type: "exec",
		Rule: filepath.Join(t.TempDir(), "missing", "ba"),
	})
	if got != nil {
		t.Fatalf("RuleCompl missing dir = %#v, want nil", got)
	}
}

func TestBuildMatcherMatchesOwnerAndUnregisters(t *testing.T) {
	tracker := multirule.New()
	owner := &sockowner.SocketOwner{PIDs: []int{42}, Comm: "bash"}
	s, err := NewSystem(Config{
		Features:    FeatureConfig{MatcherRules: true},
		RuleTracker: tracker,
		OwnerLookup: func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
			return owner, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.BuildMatcher(sysnet.Rule{Type: "comm", Rule: "^ba"})
	if err != nil {
		t.Fatal(err)
	}
	matched, err := m.Match(sockowner.FlowTuple{})
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("Match() = false, want true")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Match(
		sockowner.FlowTuple{},
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf("Match() after Close error = %v, want net.ErrClosed", err)
	}
}

func TestBuildTunConfiguresAndChecksOwnership(t *testing.T) {
	cfg := &fakeTunConfig{}
	factory := &fakeTUNFactory{}
	s, err := NewSystem(Config{
		Features:   FeatureConfig{Tun: true},
		TUNFactory: factory,
		TunConfig:  cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := s.BuildTun(sysnet.TunOpts{
		TunAddrs:  []string{"127.0.0.1/8", "10.0.0.2/32"},
		TunRoutes: []string{"127.0.0.0/8", "0.0.0.0/0"},
		MTU:       1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(factory.created) != 1 {
		t.Fatalf("created TUNs = %d, want 1", len(factory.created))
	}
	if got := cfg.addrs[tun][0]; got != "10.0.0.2/32" {
		t.Fatalf("configured addr = %q, want 10.0.0.2/32", got)
	}
	if got := cfg.routes[tun][0]; got != "0.0.0.0/0" {
		t.Fatalf("configured route = %q, want 0.0.0.0/0", got)
	}
	names, err := s.SetTunName(tun, "renamed0")
	if err != nil {
		t.Fatalf("SetTunName error = %v", err)
	}
	if got := cfg.names[tun]; got != "renamed0" {
		t.Fatalf("configured name = %q, want renamed0", got)
	}
	if len(names) != 1 || names[0] != "renamed0" {
		t.Fatalf("SetTunName = %v, want [renamed0]", names)
	}
	if err := s.SetTunMTU(
		&fakeTun{},
		1500,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunMTU(unknown) = %v, want ErrUnknownTun", err)
	}
	if _, err := s.SetTunName(
		&fakeTun{},
		"unknown0",
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunName(unknown) = %v, want ErrUnknownTun", err)
	}
}

func TestBuildTunNormalizesFactoryMTU(t *testing.T) {
	factory := &fakeTUNFactory{}
	s, err := NewSystem(Config{
		Features:   FeatureConfig{Tun: true},
		TUNFactory: factory,
		TunConfig:  &fakeTunConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := s.BuildTun(sysnet.TunOpts{MTU: 0})
	if err != nil {
		t.Fatal(err)
	}
	if got := factory.mtus; len(got) != 1 || got[0] != 1420 {
		t.Fatalf("factory MTUs = %v, want [1420]", got)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDefaultTunAppliesSideEffectsAndCloseRollsBack(t *testing.T) {
	dnsProvider := newFakeDNSProvider()
	routingManager := &fakeRouting{}
	pmarkCtl := &fakePmark{}
	ks := &fakeKillswitch{}
	packetListen := &fakePacketListen{}
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
			Pmark:      true,
			TunRules:   true,
			Killswitch: true,
		},
		DNSProvider:    dnsProvider,
		RoutingManager: routingManager,
		Pmark:          pmarkCtl,
		Killswitch:     ks,
		TUNFactory:     &fakeTUNFactory{},
		TunConfig:      &fakeTunConfig{},
		RuleTracker:    multirule.New(),
		PacketListen:   packetListen.listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
		Exclude:   []sysnet.Rule{{Type: "pid", Rule: "7"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dnsProvider.setDNS != netip.MustParseAddr("10.55.0.1") {
		t.Fatalf("SetDNS = %v, want 10.55.0.1", dnsProvider.setDNS)
	}
	if routingManager.applied == nil || routingManager.applied.TUNIndex != 99 {
		t.Fatalf(
			"routing applied = %+v, want TUNIndex 99",
			routingManager.applied,
		)
	}
	if pmarkCtl.setChecker == 0 || pmarkCtl.force == 0 {
		t.Fatalf(
			"pmark calls set=%d force=%d, want both",
			pmarkCtl.setChecker,
			pmarkCtl.force,
		)
	}
	if ks.created == 0 {
		t.Fatal("killswitch ruleset was not created")
	}
	if packetListen.addr != "10.55.0.1:53" {
		t.Fatalf(
			"packet listen addr = %q, want 10.55.0.1:53",
			packetListen.addr,
		)
	}
	dt.SetDns(dnsProvider)
	if err := dt.Close(); err != nil {
		t.Fatal(err)
	}
	if !dnsProvider.unset {
		t.Fatal("DefaultTun.Close did not unset DNS")
	}
	if routingManager.rollback == nil {
		t.Fatal("DefaultTun.Close did not rollback routing")
	}
	if ks.deleted == 0 {
		t.Fatal("DefaultTun.Close did not delete killswitch ruleset")
	}
}

func TestBuildDefaultTunSetsDNSProviderInterfaceIndex(t *testing.T) {
	dnsProvider := newFakeInterfaceDNSProvider()
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    dnsProvider,
		RoutingManager: &fakeRouting{},
		TUNFactory:     &fakeTUNFactory{},
		TunConfig:      &fakeTunConfig{},
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := dnsProvider.interfaceIndices; len(got) != 1 || got[0] != 99 {
		t.Fatalf("SetInterfaceIndex calls = %v, want [99]", got)
	}
	if dnsProvider.setDNS != netip.MustParseAddr("10.55.0.1") {
		t.Fatalf("SetDNS = %v, want 10.55.0.1", dnsProvider.setDNS)
	}
	if err := dt.Close(); err != nil {
		t.Fatal(err)
	}
	if got := dnsProvider.interfaceIndices; len(got) != 2 || got[1] != 0 {
		t.Fatalf("SetInterfaceIndex calls = %v, want clear to 0 on close", got)
	}
}

func TestBuildDefaultTunNormalizesFactoryMTU(t *testing.T) {
	factory := &fakeTUNFactory{}
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: &fakeRouting{},
		TUNFactory:     factory,
		TunConfig:      &fakeTunConfig{},
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
		MTU:      0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := factory.mtus; len(got) != 1 || got[0] != 1420 {
		t.Fatalf("factory MTUs = %v, want [1420]", got)
	}
	if err := dt.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDefaultTunRecreatesMissingLinkAndUpdatesInterfaceIndex(
	t *testing.T,
) {
	dnsProvider := newFakeInterfaceDNSProvider()
	routingManager := &fakeRouting{}
	factory := &fakeTUNFactory{}
	packetListen := &fakePacketListen{}
	linkDeleted := false
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    dnsProvider,
		RoutingManager: routingManager,
		TUNFactory:     factory,
		TunConfig:      &fakeTunConfig{},
		PacketListen:   packetListen.listen,
		TUNIndex: func(t gtun.Tun) (int, error) {
			if len(factory.created) > 0 && t == factory.created[0] {
				if linkDeleted {
					return 0, errors.New("link deleted")
				}
				return 99, nil
			}
			if len(factory.created) > 1 && t == factory.created[1] {
				return 123, nil
			}
			return 0, errors.New("unknown tun")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	linkDeleted = true
	second, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
		MTU:      0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(factory.created) != 2 {
		t.Fatalf("created TUNs = %d, want 2", len(factory.created))
	}
	if got := factory.mtus; len(got) != 2 || got[1] != 1420 {
		t.Fatalf("factory MTUs = %v, want recreated MTU 1420", got)
	}
	if !factory.created[0].closed {
		t.Fatal("old deleted-link TUN was not closed")
	}
	if len(packetListen.addrs) != 2 {
		t.Fatalf("packet listen calls = %d, want 2", len(packetListen.addrs))
	}
	if !packetListen.conns[0].isClosed() {
		t.Fatal("old DNS listener was not closed after link recreation")
	}
	if packetListen.conns[1].isClosed() {
		t.Fatal("new DNS listener was closed after link recreation")
	}
	if got := dnsProvider.interfaceIndices; len(got) != 2 ||
		got[0] != 99 || got[1] != 123 {
		t.Fatalf("SetInterfaceIndex calls = %v, want [99 123]", got)
	}
	if routingManager.applied == nil || routingManager.applied.TUNIndex != 123 {
		t.Fatalf(
			"routing applied = %+v, want TUNIndex 123",
			routingManager.applied,
		)
	}
	first.SetDns(dnsProvider)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDefaultTunWithoutTunRulesSkipsPmarkChecker(t *testing.T) {
	pmarkCtl := &fakePmark{}
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
			Pmark:      true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: &fakeRouting{},
		Pmark:          pmarkCtl,
		TUNFactory:     &fakeTUNFactory{},
		TunConfig:      &fakeTunConfig{},
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pmarkCtl.setChecker != 0 || pmarkCtl.force != 0 {
		t.Fatalf(
			"pmark calls set=%d force=%d, want none",
			pmarkCtl.setChecker,
			pmarkCtl.force,
		)
	}
	if err := dt.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDefaultTunRebindsDNSListenerOnDNSIPChange(t *testing.T) {
	dnsProvider := newFakeDNSProvider()
	packetListen := &fakePacketListen{}
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    dnsProvider,
		RoutingManager: &fakeRouting{},
		TUNFactory:     &fakeTUNFactory{},
		TunConfig:      &fakeTunConfig{},
		PacketListen:   packetListen.listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.2/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(packetListen.addrs) != 2 {
		t.Fatalf("packet listen calls = %d, want 2", len(packetListen.addrs))
	}
	if packetListen.addrs[0] != "10.55.0.1:53" ||
		packetListen.addrs[1] != "10.55.0.2:53" {
		t.Fatalf(
			"packet listen addrs = %#v, want both DNS binds",
			packetListen.addrs,
		)
	}
	if !packetListen.conns[0].isClosed() {
		t.Fatal("old DNS listener was not closed after DNS IP rebuild")
	}
	if packetListen.conns[1].isClosed() {
		t.Fatal("new DNS listener was closed after successful rebuild")
	}
	if dnsProvider.setDNS != netip.MustParseAddr("10.55.0.2") {
		t.Fatalf("SetDNS = %v, want 10.55.0.2", dnsProvider.setDNS)
	}
	first.SetDns(dnsProvider)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDefaultTunFailedRebuildClosesActiveDefaultTun(t *testing.T) {
	dnsProvider := newFakeDNSProvider()
	routingManager := &fakeRouting{}
	factory := &fakeTUNFactory{}
	packetListen := &fakePacketListen{}
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:        true,
			DefaultTun: true,
			DNSControl: true,
			Routing:    true,
		},
		DNSProvider:    dnsProvider,
		RoutingManager: routingManager,
		TUNFactory:     factory,
		TunConfig:      &fakeTunConfig{},
		PacketListen:   packetListen.listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 99, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	dnsProvider.setErr = errors.New("set dns failed")
	_, err = s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.2/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.2",
	})
	if !errors.Is(err, dnsProvider.setErr) {
		t.Fatalf("BuildDefaultTun error = %v, want %v", err, dnsProvider.setErr)
	}
	if s.defaultTun != nil {
		t.Fatal("failed rebuild left an active default tun")
	}
	if len(factory.created) != 1 || !factory.created[0].closed {
		t.Fatalf(
			"default tun closed = %v, want true",
			len(factory.created) == 1 && factory.created[0].closed,
		)
	}
	if len(packetListen.conns) != 2 {
		t.Fatalf("packet listeners = %d, want 2", len(packetListen.conns))
	}
	if !packetListen.conns[0].isClosed() || !packetListen.conns[1].isClosed() {
		t.Fatal(
			"failed rebuild did not close old and replacement DNS listeners",
		)
	}
	if !dnsProvider.unset {
		t.Fatal("failed rebuild did not unset DNS")
	}
	if routingManager.rollback == nil {
		t.Fatal("failed rebuild did not rollback routing")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
}

type fakeTUNFactory struct {
	created []*fakeTun
	mtus    []int
}

func (f *fakeTUNFactory) CreateTUN(_ string, mtu int) (gtun.Tun, error) {
	t := &fakeTun{events: make(chan gtun.Event)}
	f.created = append(f.created, t)
	f.mtus = append(f.mtus, mtu)
	return t, nil
}

type fakeTun struct {
	closed bool
	events chan gtun.Event
}

func (f *fakeTun) File() *os.File { return nil }
func (f *fakeTun) IsNative() bool { return true }
func (f *fakeTun) Read([][]byte, []int, int) (int, error) {
	return 0, net.ErrClosed
}
func (f *fakeTun) Write([][]byte, int) (int, error) { return 0, net.ErrClosed }
func (f *fakeTun) MWO() int                         { return 0 }
func (f *fakeTun) MRO() int                         { return 0 }
func (f *fakeTun) MTU() (int, error)                { return 1500, nil }
func (f *fakeTun) Name() (string, error)            { return "fake0", nil }
func (f *fakeTun) Events() <-chan gtun.Event        { return f.events }
func (f *fakeTun) Close() error {
	if !f.closed {
		f.closed = true
		close(f.events)
	}
	return nil
}
func (f *fakeTun) BatchSize() int { return 1 }

type fakeTunConfig struct {
	mtu    map[gtun.Tun]int
	addrs  map[gtun.Tun][]string
	routes map[gtun.Tun][]string
	names  map[gtun.Tun]string
}

func (f *fakeTunConfig) init() {
	if f.mtu == nil {
		f.mtu = map[gtun.Tun]int{}
		f.addrs = map[gtun.Tun][]string{}
		f.routes = map[gtun.Tun][]string{}
		f.names = map[gtun.Tun]string{}
	}
}
func (f *fakeTunConfig) SetTunMTU(t gtun.Tun, mtu int) error {
	f.init()
	f.mtu[t] = mtu
	return nil
}
func (f *fakeTunConfig) SetTunAddrs(t gtun.Tun, addrs []string) error {
	f.init()
	f.addrs[t] = append([]string(nil), addrs...)
	return nil
}
func (f *fakeTunConfig) AddTunAddr(t gtun.Tun, addr string) error {
	f.init()
	f.addrs[t] = append(f.addrs[t], addr)
	return nil
}
func (f *fakeTunConfig) GetTunAddrs(t gtun.Tun) ([]string, error) {
	f.init()
	return append([]string(nil), f.addrs[t]...), nil
}
func (f *fakeTunConfig) SetTunRoutes(t gtun.Tun, routes []string) error {
	f.init()
	f.routes[t] = append([]string(nil), routes...)
	return nil
}
func (f *fakeTunConfig) AddTunRoute(t gtun.Tun, route string) error {
	f.init()
	f.routes[t] = append(f.routes[t], route)
	return nil
}
func (f *fakeTunConfig) GetTunRotue(t gtun.Tun) ([]string, error) {
	f.init()
	return append([]string(nil), f.routes[t]...), nil
}
func (f *fakeTunConfig) SetTunName(t gtun.Tun, name string) ([]string, error) {
	f.init()
	f.names[t] = name
	return []string{name}, nil
}

type fakeDNSProvider struct {
	ch     chan gdns.Request
	setDNS netip.Addr
	setErr error
	unset  bool
}

func newFakeDNSProvider() *fakeDNSProvider {
	return &fakeDNSProvider{ch: make(chan gdns.Request)}
}
func (f *fakeDNSProvider) Requests() chan<- gdns.Request { return f.ch }
func (f *fakeDNSProvider) Close() error                  { return nil }
func (f *fakeDNSProvider) SetDNS(addr netip.Addr) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.setDNS = addr
	return nil
}
func (f *fakeDNSProvider) UnsetDNS() error {
	f.unset = true
	return nil
}

type fakeInterfaceDNSProvider struct {
	*fakeDNSProvider
	interfaceIndices []int
}

func newFakeInterfaceDNSProvider() *fakeInterfaceDNSProvider {
	return &fakeInterfaceDNSProvider{fakeDNSProvider: newFakeDNSProvider()}
}

func (f *fakeInterfaceDNSProvider) SetInterfaceIndex(ifidx int) error {
	f.interfaceIndices = append(f.interfaceIndices, ifidx)
	return nil
}

type fakeRouting struct {
	applied  *routing.Config
	rollback *routing.Config
}

func (f *fakeRouting) Apply(config routing.Config) error {
	c := config
	f.applied = &c
	return nil
}
func (f *fakeRouting) Refresh() error { return nil }
func (f *fakeRouting) Rollback(config routing.Config) error {
	c := config
	f.rollback = &c
	return nil
}

func (f *fakeRouting) Status() (routing.DesiredState, bool) { return routing.DesiredState{}, false }
func (f *fakeRouting) Close() error                         { return nil }

type fakePmark struct {
	setChecker int
	force      int
	check      pmark.CheckFunc
}

func (f *fakePmark) SetChecker(check pmark.CheckFunc) (uint64, error) {
	f.setChecker++
	f.check = check
	return uint64(f.setChecker), nil
}
func (f *fakePmark) ForceProcessTraversal() error {
	f.force++
	return nil
}

type fakeKillswitch struct {
	created uint64
	updated uint64
	deleted uint64
}

func (f *fakeKillswitch) CreateTMPRuleset(
	killswitch.AllowRules,
) (uint64, error) {
	f.created = 1
	return 1, nil
}

func (f *fakeKillswitch) UpdateTMPRuleset(
	id uint64,
	_ killswitch.AllowRules,
) error {
	f.updated = id
	return nil
}
func (f *fakeKillswitch) DeleteTMPRuleset(id uint64) error {
	f.deleted = id
	return nil
}
func (f *fakeKillswitch) Close() error { return nil }

type fakeCloser struct {
	closed bool
}

func (f *fakeCloser) Close() error {
	f.closed = true
	return nil
}

type fakePacketListen struct {
	addr  string
	addrs []string
	conn  *fakePacketConn
	conns []*fakePacketConn
}

func (f *fakePacketListen) listen(
	_ context.Context,
	_, addr string,
) (net.PacketConn, error) {
	f.addr = addr
	f.conn = newFakePacketConn()
	f.addrs = append(f.addrs, addr)
	f.conns = append(f.conns, f.conn)
	return f.conn, nil
}

type fakePacketConn struct {
	closed chan struct{}
	once   sync.Once
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{closed: make(chan struct{})}
}
func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-f.closed
	return 0, nil, net.ErrClosed
}

func (f *fakePacketConn) WriteTo(
	[]byte,
	net.Addr,
) (int, error) {
	return 0, nil
}
func (f *fakePacketConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakePacketConn) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

func (f *fakePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }
