//go:build linux

// nolint
package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/multirule"
	"github.com/asciimoth/sysnet-linux/killswitch"
	"github.com/asciimoth/sysnet-linux/routing"
)

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
	if err := s.SetTunMTU(
		&fakeTun{},
		1500,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunMTU(unknown) = %v, want ErrUnknownTun", err)
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

type fakeTUNFactory struct {
	created []*fakeTun
}

func (f *fakeTUNFactory) CreateTUN(string, int) (gtun.Tun, error) {
	t := &fakeTun{events: make(chan gtun.Event)}
	f.created = append(f.created, t)
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
}

func (f *fakeTunConfig) init() {
	if f.mtu == nil {
		f.mtu = map[gtun.Tun]int{}
		f.addrs = map[gtun.Tun][]string{}
		f.routes = map[gtun.Tun][]string{}
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
func (f *fakeTunConfig) SetTunName(gtun.Tun) ([]string, error) {
	return []string{"fake0"}, nil
}

type fakeDNSProvider struct {
	ch     chan gdns.Request
	setDNS netip.Addr
	unset  bool
}

func newFakeDNSProvider() *fakeDNSProvider {
	return &fakeDNSProvider{ch: make(chan gdns.Request)}
}
func (f *fakeDNSProvider) Requests() chan<- gdns.Request { return f.ch }
func (f *fakeDNSProvider) Close() error                  { return nil }
func (f *fakeDNSProvider) SetDNS(addr netip.Addr) error {
	f.setDNS = addr
	return nil
}
func (f *fakeDNSProvider) UnsetDNS() error {
	f.unset = true
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

type fakePacketListen struct {
	addr string
	conn *fakePacketConn
}

func (f *fakePacketListen) listen(
	_ context.Context,
	_, addr string,
) (net.PacketConn, error) {
	f.addr = addr
	f.conn = newFakePacketConn()
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

func (f *fakePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }
