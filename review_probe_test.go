//go:build linux

//nolint:testpackage // Tests exercise injected package-private dependencies.
package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/sysnet-linux/routing"
	"golang.org/x/sys/unix"
)

func reviewSystem(
	t *testing.T,
	listen PacketListenFunc,
) (*System, *fakeRouting) {
	t.Helper()
	rm := &fakeRouting{}
	if listen == nil {
		listen = (&fakePacketListen{}).listen
	}
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:           true,
			DefaultTun:    true,
			DynDefaultTun: true,
			Routing:       true,
			DNSControl:    true,
			StrictMode:    true,
			TunRules:      true,
			Pmark:         true,
		},
		DNSProvider: newFakeDNSProvider(), RoutingManager: rm,
		Connmark: &fakeConnmark{}, Pmark: &fakePmark{},
		TUNFactory: &fakeTUNFactory{}, TunConfig: &fakeTunConfig{},
		PacketListen: listen, TUNIndex: func(gtun.Tun) (int, error) { return 77, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, rm
}

func TestReviewStrictExcludedTrafficMustDrop(t *testing.T) {
	s, rm := reviewSystem(t, nil)
	_, err := s.BuildDefaultTun(
		sysnet.DefaultTunOpts{
			Strict:  true,
			Exclude: []sysnet.Rule{{Type: "pid", Rule: "123"}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := routing.CompileDesiredState(*rm.applied, routing.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range desired.Rules {
		if rule.Family == unix.AF_INET && rule.Mark == rm.applied.UserMark {
			if rule.Action != routing.RuleUnreachable {
				t.Fatalf(
					"first excluded-traffic rule is action=%v table=%d; want unreachable",
					rule.Action,
					rule.Table,
				)
			}
			return
		}
	}
	t.Fatal("no user rule")
}

func TestReviewStrictDefaultProtectsIPv6(t *testing.T) {
	s, rm := reviewSystem(t, nil)
	if _, err := s.BuildDefaultTun(
		sysnet.DefaultTunOpts{Strict: true},
	); err != nil {
		t.Fatal(err)
	}
	desired, err := routing.CompileDesiredState(*rm.applied, routing.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range desired.Rules {
		if rule.Family == unix.AF_INET6 {
			return
		}
	}
	t.Fatalf(
		"Strict:true produced no IPv6 routing or blocking rules; families=%+v",
		rm.applied.Families,
	)
}

func TestReviewIgnoreUnassignedDNSIP(t *testing.T) {
	_, got, err := normalizeTunAddrs(
		[]string{"10.42.0.1/24"},
		"100.64.0.1/32",
		"10.42.0.99",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got == netip.MustParseAddr("10.42.0.99") {
		t.Fatalf(
			"accepted unassigned DNS IP %s solely because it is inside a configured subnet",
			got,
		)
	}
}

func TestReviewSystemCloseDisablesNetworks(t *testing.T) {
	for _, test := range []struct {
		name string
		get  func(*System) gonnect.Network
	}{
		{"OutNet", (*System).OutNet},
		{"LocalNet", (*System).LocalNet},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, err := NewSystem(Config{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			n := test.get(s)
			listener, err := n.Listen(
				context.Background(), "tcp", "127.0.0.1:0",
			)
			if err != nil {
				t.Skipf("listener unavailable: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(
				context.Background(), time.Second,
			)
			defer cancel()
			c, err := n.Dial(ctx, "tcp", listener.Addr().String())
			if err == nil {
				_ = c.Close()
				t.Fatal("saved network remains active after System.Close")
			}
		})
	}
}

func TestSocketMarkFailureIsAllowedWithoutDefaultTunCapability(t *testing.T) {
	var logs []string
	s, err := NewSystem(
		Config{
			Logf: func(f string, args ...any) { logs = append(logs, fmt.Sprintf(f, args...)) },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	l, err := s.OutNet().Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen without default-TUN capability: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if len(logs) == 0 {
		t.Skip("environment did not trigger a marking error")
	}
}

func TestMarkedPolicyNetworkReturnsInjectedMarkFailure(t *testing.T) {
	want := errors.New("mark denied")
	n := buildMarkedPolicyNetwork(
		1,
		true,
		func(string, ...any) {},
		func(any, uint32) error {
			return want
		},
	)
	closer, ok := n.(io.Closer)
	if !ok {
		t.Fatal("marked policy network does not implement io.Closer")
	}
	t.Cleanup(func() { _ = closer.Close() })
	if _, err := n.Listen(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	); !errors.Is(
		err,
		want,
	) {
		t.Fatalf("Listen error = %v, want %v", err, want)
	}
	if _, err := n.ListenPacket(
		context.Background(),
		"udp",
		"127.0.0.1:0",
	); !errors.Is(
		err,
		want,
	) {
		t.Fatalf("ListenPacket error = %v, want %v", err, want)
	}
	listener, err := (&net.ListenConfig{}).Listen(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if _, err := n.Dial(
		context.Background(),
		"tcp",
		listener.Addr().String(),
	); !errors.Is(
		err,
		want,
	) {
		t.Fatalf("Dial error = %v, want %v", err, want)
	}
}

func TestPolicyNetworkCloseRejectsNewOperationsAndClosesListener(t *testing.T) {
	n := buildMarkedPolicyNetwork(
		1,
		true,
		func(string, ...any) {},
		func(any, uint32) error {
			return nil
		},
	)
	listener, err := n.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closer, ok := n.(io.Closer)
	if !ok {
		t.Fatal("marked policy network does not implement io.Closer")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); err == nil {
		t.Fatal("listener remains active after policy network close")
	}
	if _, err := n.Listen(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf("Listen after Close error = %v, want net.ErrClosed", err)
	}
}

type reviewPacketConn struct {
	*fakePacketConn
	in  chan []byte
	out chan []byte
}

func (c *reviewPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case p := <-c.in:
		return copy(
				buf,
				p,
			), &net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 12345,
			}, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}
func (c *reviewPacketConn) WriteTo(buf []byte, _ net.Addr) (int, error) {
	c.out <- append([]byte(nil), buf...)
	return len(buf), nil
}
func (c *reviewPacketConn) query() (*gdns.Message, error) {
	p, err := gdns.Pack(
		&gdns.Message{
			ID: 1,
			Questions: []gdns.Question{
				{Name: "probe.example.", Type: gdns.TypeA, Class: 1},
			},
		},
	)
	if err != nil {
		return nil, err
	}
	c.in <- p
	select {
	case p = <-c.out:
		return gdns.Unpack(p)
	case <-time.After(time.Second):
		return nil, errors.New("DNS response timeout")
	}
}
func TestReviewRebuildPreservesDNSResolver(t *testing.T) {
	pc := &reviewPacketConn{
		fakePacketConn: newFakePacketConn(),
		in:             make(chan []byte, 1),
		out:            make(chan []byte, 1),
	}
	s, _ := reviewSystem(
		t,
		func(context.Context, string, string) (net.PacketConn, error) { return pc, nil },
	)
	d, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{})
	if err != nil {
		t.Fatal(err)
	}
	up := newFakeDNSProvider()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case req := <-up.ch:
				resp := req.Message.Copy()
				resp.Response = true
				resp.RCode = gdns.RCodeSuccess
				req.Reply <- gdns.Response{Message: resp}
			}
		}
	}()
	if err := d.SetDNS(up); err != nil {
		t.Fatal(err)
	}
	before, err := pc.query()
	if err != nil || before.RCode != gdns.RCodeSuccess {
		t.Fatalf("before rebuild: %v %v", before, err)
	}
	if _, err := s.BuildDefaultTun(
		sysnet.DefaultTunOpts{MTU: 1400},
	); err != nil {
		t.Fatal(err)
	}
	after, err := pc.query()
	if err != nil {
		t.Fatal(err)
	}
	if after.RCode != gdns.RCodeSuccess {
		t.Fatalf(
			"MTU-only rebuild changed DNS from success to RCode %d",
			after.RCode,
		)
	}
}

func TestRebuildReattachesResolverWhenDNSListenerChanges(t *testing.T) {
	first := &reviewPacketConn{
		fakePacketConn: newFakePacketConn(),
		in:             make(chan []byte, 1),
		out:            make(chan []byte, 1),
	}
	second := &reviewPacketConn{
		fakePacketConn: newFakePacketConn(),
		in:             make(chan []byte, 1),
		out:            make(chan []byte, 1),
	}
	listenCount := 0
	s, _ := reviewSystem(
		t,
		func(context.Context, string, string) (net.PacketConn, error) {
			listenCount++
			if listenCount == 1 {
				return first, nil
			}
			return second, nil
		},
	)
	d, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{})
	if err != nil {
		t.Fatal(err)
	}
	up := newFakeDNSProvider()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case req := <-up.ch:
				resp := req.Message.Copy()
				resp.Response = true
				resp.RCode = gdns.RCodeSuccess
				req.Reply <- gdns.Response{Message: resp}
			}
		}
	}()
	if err := d.SetDNS(up); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.42.0.1/24"},
		DnsIP:    "10.42.0.1",
	}); err != nil {
		t.Fatal(err)
	}
	response, err := second.query()
	if err != nil {
		t.Fatal(err)
	}
	if response.RCode != gdns.RCodeSuccess {
		t.Fatalf("replacement listener returned RCode %d", response.RCode)
	}
}
