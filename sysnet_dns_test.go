//go:build linux

package linux_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	linux "github.com/asciimoth/sysnet-linux"
	linuxdns "github.com/asciimoth/sysnet-linux/dns"
)

func TestSystemOutNetDialUsesDNSProviderAfterDNSChange(t *testing.T) {
	listener := listenResolverTestTCP(t, "0.0.0.0:0")
	provider := newResolverTestDNSProvider()
	provider.setHost("outnet-dial.test", netip.MustParseAddr("127.0.0.1"))
	system := newResolverTestSystem(t, provider)

	assertResolverNetwork(t, system.OutNet())
	if system.OutDNS() != provider {
		t.Fatal("OutDNS does not return the configured DNS provider")
	}

	before := dialResolverTestTCP(
		t,
		system.OutNet(),
		"outnet-dial.test",
		listener,
	)
	if before != "127.0.0.1" {
		t.Fatalf("first remote address = %s, want 127.0.0.1", before)
	}
	assertResolverTestQuestions(
		t,
		provider.takeQuestions(),
		"outnet-dial.test",
		gdns.TypeA,
		gdns.TypeAAAA,
	)

	managed := netip.MustParseAddr("100.64.0.53")
	if err := provider.SetDNS(managed); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	provider.setHost("outnet-dial.test", netip.MustParseAddr("127.0.0.2"))

	after := dialResolverTestTCP(
		t,
		system.OutNet(),
		"outnet-dial.test",
		listener,
	)
	if after != "127.0.0.2" {
		t.Fatalf("second remote address = %s, want 127.0.0.2", after)
	}
	assertResolverTestQuestions(
		t,
		provider.takeQuestions(),
		"outnet-dial.test",
		gdns.TypeA,
		gdns.TypeAAAA,
	)
	if got := provider.setDNSAddresses(); !slices.Equal(
		got,
		[]netip.Addr{managed},
	) {
		t.Fatalf("SetDNS addresses = %v, want [%s]", got, managed)
	}
}

func TestSystemOutNetDialUsesDirectProviderOriginalUpstreamAfterSetDNS(
	t *testing.T,
) {
	const host = "direct-outnet.test"
	upstreamProvider := newResolverTestDNSProvider()
	upstreamProvider.setHost(host, netip.MustParseAddr("127.0.0.1"))
	var listenConfig net.ListenConfig
	upstreamConn, err := listenConfig.ListenPacket(
		context.Background(),
		"udp4",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("listen upstream DNS: %v", err)
	}
	upstreamServer := gdns.NewServer(upstreamConn, upstreamProvider, nil)
	t.Cleanup(func() {
		_ = upstreamServer.Close()
		_ = upstreamProvider.Close()
	})

	original := netip.MustParseAddr("192.0.2.53")
	managed := netip.MustParseAddr("100.64.0.53")
	env := newResolverTestDirectEnv("nameserver " + original.String() + "\n")
	dialNetwork := &resolverTestRedirectNetwork{
		Network: gonnect.NativeConfig{}.Build(),
		target:  upstreamConn.LocalAddr().String(),
	}
	provider, err := linuxdns.NewDirect(
		env.env(),
		gonnect.NativeConfig{}.Build(),
		dialNetwork,
	)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	system := newResolverTestSystem(t, provider)
	if err := provider.SetDNS(managed); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}

	listener := listenResolverTestTCP(t, "127.0.0.1:0")
	remote := dialResolverTestTCP(t, system.OutNet(), host, listener)
	if remote != "127.0.0.1" {
		t.Fatalf("remote address = %s, want 127.0.0.1", remote)
	}
	assertResolverTestQuestions(
		t,
		upstreamProvider.takeQuestions(),
		host,
		gdns.TypeA,
		gdns.TypeAAAA,
	)
	wantUpstream := net.JoinHostPort(original.String(), "53")
	dials := dialNetwork.dialAddresses()
	if len(dials) == 0 {
		t.Fatal("the direct provider did not dial its original upstream")
	}
	for _, address := range dials {
		if address != wantUpstream {
			t.Fatalf(
				"upstream dial address = %s, want %s",
				address,
				wantUpstream,
			)
		}
	}
	if got := env.contents(); !strings.Contains(got, managed.String()) {
		t.Fatalf("managed resolv.conf = %q, want server %s", got, managed)
	}
}

func TestSystemLocalNetDialUsesDNSProvider(t *testing.T) {
	listener := listenResolverTestTCP(t, "127.0.0.1:0")
	provider := newResolverTestDNSProvider()
	provider.setHost("localnet-dial.test", netip.MustParseAddr("127.0.0.1"))
	system := newResolverTestSystem(t, provider)

	assertResolverNetwork(t, system.LocalNet())
	remote := dialResolverTestTCP(
		t,
		system.LocalNet(),
		"localnet-dial.test",
		listener,
	)
	if remote != "127.0.0.1" {
		t.Fatalf("remote address = %s, want 127.0.0.1", remote)
	}
	assertResolverTestQuestions(
		t,
		provider.takeQuestions(),
		"localnet-dial.test",
		gdns.TypeA,
		gdns.TypeAAAA,
	)
}

func TestSystemOutNetLookupsUseDNSProvider(t *testing.T) {
	const host = "outnet-lookup.test"
	want := netip.MustParseAddr("192.0.2.25")
	provider := newResolverTestDNSProvider()
	provider.setHost(host, want)
	system := newResolverTestSystem(t, provider)
	ctx := resolverTestContext(t)

	t.Run("LookupHost", func(t *testing.T) {
		got, err := system.OutNet().LookupHost(ctx, host)
		if err != nil {
			t.Fatalf("LookupHost: %v", err)
		}
		if !slices.Equal(got, []string{want.String()}) {
			t.Fatalf("LookupHost = %v, want [%s]", got, want)
		}
		assertResolverTestQuestions(
			t,
			provider.takeQuestions(),
			host,
			gdns.TypeA,
			gdns.TypeAAAA,
		)
	})

	t.Run("LookupIP", func(t *testing.T) {
		got, err := system.OutNet().LookupIP(ctx, "ip4", host)
		if err != nil {
			t.Fatalf("LookupIP: %v", err)
		}
		if len(got) != 1 || got[0].String() != want.String() {
			t.Fatalf("LookupIP = %v, want [%s]", got, want)
		}
		assertResolverTestQuestions(
			t,
			provider.takeQuestions(),
			host,
			gdns.TypeA,
		)
	})

	t.Run("LookupIPAddr", func(t *testing.T) {
		got, err := system.OutNet().LookupIPAddr(ctx, host)
		if err != nil {
			t.Fatalf("LookupIPAddr: %v", err)
		}
		if len(got) != 1 || got[0].IP.String() != want.String() {
			t.Fatalf("LookupIPAddr = %v, want [%s]", got, want)
		}
		assertResolverTestQuestions(
			t,
			provider.takeQuestions(),
			host,
			gdns.TypeA,
			gdns.TypeAAAA,
		)
	})

	t.Run("LookupNetIP", func(t *testing.T) {
		got, err := system.OutNet().LookupNetIP(ctx, "ip4", host)
		if err != nil {
			t.Fatalf("LookupNetIP: %v", err)
		}
		if len(got) != 1 || got[0].Unmap() != want {
			t.Fatalf("LookupNetIP = %v, want [%s]", got, want)
		}
		assertResolverTestQuestions(
			t,
			provider.takeQuestions(),
			host,
			gdns.TypeA,
		)
	})
}

func TestSystemOutNetHostnameOperationMatrix(t *testing.T) {
	tcpListener := listenResolverTestTCP(t, "127.0.0.1:0")
	udpListener := listenResolverTestUDP(t, "127.0.0.1:0")
	provider := newResolverTestDNSProvider()
	system := newResolverTestSystem(t, provider)
	ctx := resolverTestContext(t)

	tcpPort := resolverTestTCPPort(t, tcpListener)
	udpPort := resolverTestUDPPort(t, udpListener)
	tests := []struct {
		name    string
		host    string
		call    func(string) (net.Conn, error)
		accept  bool
		wantNet string
	}{
		{
			name: "DialTCPNetwork",
			host: "dial-tcp.test",
			call: func(address string) (net.Conn, error) {
				return system.OutNet().Dial(ctx, "tcp4", address)
			},
			accept:  true,
			wantNet: "tcp",
		},
		{
			name: "DialTCP",
			host: "dial-typed-tcp.test",
			call: func(address string) (net.Conn, error) {
				return system.OutNet().DialTCP(ctx, "tcp4", "", address)
			},
			accept:  true,
			wantNet: "tcp",
		},
		{
			name: "DialUDPNetwork",
			host: "dial-udp.test",
			call: func(address string) (net.Conn, error) {
				return system.OutNet().Dial(ctx, "udp4", address)
			},
			wantNet: "udp",
		},
		{
			name: "PacketDial",
			host: "packet-dial.test",
			call: func(address string) (net.Conn, error) {
				return system.OutNet().PacketDial(ctx, "udp4", address)
			},
			wantNet: "udp",
		},
		{
			name: "DialUDP",
			host: "dial-typed-udp.test",
			call: func(address string) (net.Conn, error) {
				return system.OutNet().DialUDP(ctx, "udp4", "", address)
			},
			wantNet: "udp",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider.setHost(test.host, netip.MustParseAddr("127.0.0.1"))
			port := udpPort
			if test.wantNet == "tcp" {
				port = tcpPort
			}
			conn, err := test.call(
				net.JoinHostPort(test.host, netPortString(port)),
			)
			if err != nil {
				t.Fatalf("%s: %v", test.name, err)
			}
			defer func() { _ = conn.Close() }()
			remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil {
				t.Fatalf("split remote address: %v", err)
			}
			if remoteHost != "127.0.0.1" {
				t.Fatalf("remote host = %s, want 127.0.0.1", remoteHost)
			}
			if test.accept {
				acceptResolverTestTCP(t, tcpListener)
			}
			assertResolverTestQuestions(
				t,
				provider.takeQuestions(),
				test.host,
				gdns.TypeA,
				gdns.TypeAAAA,
			)
		})
	}
}

func TestSystemOutNetDialUsesAAAAProviderAnswer(t *testing.T) {
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(
		context.Background(),
		"tcp6",
		"[::1]:0",
	)
	if err != nil {
		t.Skipf("IPv6 loopback is not available: %v", err)
	}
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		t.Fatalf("IPv6 listener type = %T, want *net.TCPListener", listener)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })

	provider := newResolverTestDNSProvider()
	provider.setHost("outnet-ipv6.test", netip.IPv6Loopback())
	system := newResolverTestSystem(t, provider)
	port := resolverTestTCPPort(t, tcpListener)
	conn, err := system.OutNet().Dial(
		resolverTestContext(t),
		"tcp6",
		net.JoinHostPort("outnet-ipv6.test", netPortString(port)),
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()
	acceptResolverTestTCP(t, tcpListener)
	assertResolverTestQuestions(
		t,
		provider.takeQuestions(),
		"outnet-ipv6.test",
		gdns.TypeA,
		gdns.TypeAAAA,
	)
}

func TestSystemOutNetIPLiteralDoesNotUseDNSProvider(t *testing.T) {
	listener := listenResolverTestTCP(t, "127.0.0.1:0")
	provider := newResolverTestDNSProvider()
	system := newResolverTestSystem(t, provider)

	conn, err := system.OutNet().Dial(
		resolverTestContext(t),
		"tcp4",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()
	acceptResolverTestTCP(t, listener)
	if got := provider.takeQuestions(); len(got) != 0 {
		t.Fatalf("DNS questions for an IP literal = %v, want none", got)
	}
}

func TestSystemOutNetResolverErrorDoesNotUseNativeFallback(t *testing.T) {
	listener := listenResolverTestTCP(t, "127.0.0.1:0")
	provider := newResolverTestDNSProvider()
	system := newResolverTestSystem(t, provider)

	conn, err := system.OutNet().Dial(
		resolverTestContext(t),
		"tcp4",
		net.JoinHostPort(
			"localhost",
			netPortString(resolverTestTCPPort(t, listener)),
		),
	)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("Dial succeeded through the native localhost fallback")
	}
	var dnsErr *net.DNSError
	if !strings.Contains(err.Error(), "no such host") ||
		!errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("Dial error = %v, want a not-found DNS error", err)
	}
	assertResolverTestQuestions(
		t,
		provider.takeQuestions(),
		"localhost",
		gdns.TypeA,
		gdns.TypeAAAA,
	)
}

func TestSystemOutNetDNSCancellationStopsDial(t *testing.T) {
	const host = "outnet-cancel.test"
	provider := newResolverTestDNSProvider()
	provider.blockHost(host)
	system := newResolverTestSystem(t, provider)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		50*time.Millisecond,
	)
	defer cancel()

	started := time.Now()
	conn, err := system.OutNet().Dial(
		ctx,
		"tcp4",
		net.JoinHostPort(host, "443"),
	)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("Dial succeeded while provider resolution was blocked")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf(
			"canceled Dial returned after %v, want no more than 1s",
			elapsed,
		)
	}
	questions := provider.takeQuestions()
	if len(questions) == 0 {
		t.Fatal("provider received no DNS question before cancellation")
	}
	for _, question := range questions {
		if question.Name != resolverTestDNSName(host)+"." {
			t.Fatalf("DNS question name = %q, want %q", question.Name, host+".")
		}
	}
}

func newResolverTestSystem(
	t *testing.T,
	provider linuxdns.DNSProvider,
) *linux.System {
	t.Helper()
	system, err := linux.NewSystem(linux.Config{DNSProvider: provider})
	if err != nil {
		t.Fatalf("NewSystem: %v", err)
	}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("System.Close: %v", err)
		}
	})
	return system
}

func assertResolverNetwork(t *testing.T, network gonnect.Network) {
	t.Helper()
	wrapper, ok := network.(*gonnect.NetworkWithResolver)
	if !ok {
		t.Fatalf(
			"network type = %T, want *gonnect.NetworkWithResolver",
			network,
		)
	}
	if _, ok := wrapper.GetNetwork().(*gonnect.NativeNetwork); !ok {
		t.Fatalf(
			"wrapped network type = %T, want *gonnect.NativeNetwork",
			wrapper.GetNetwork(),
		)
	}
	if !wrapper.IsNative() {
		t.Fatal("resolver wrapper did not preserve native network status")
	}
}

func listenResolverTestTCP(t *testing.T, address string) *net.TCPListener {
	t.Helper()
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(
		context.Background(),
		"tcp4",
		address,
	)
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener type = %T, want *net.TCPListener", listener)
	}
	return tcpListener
}

func listenResolverTestUDP(t *testing.T, address string) *net.UDPConn {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatalf("resolve UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func dialResolverTestTCP(
	t *testing.T,
	network gonnect.Network,
	host string,
	listener *net.TCPListener,
) string {
	t.Helper()
	port := resolverTestTCPPort(t, listener)
	conn, err := network.Dial(
		resolverTestContext(t),
		"tcp4",
		net.JoinHostPort(host, netPortString(port)),
	)
	if err != nil {
		t.Fatalf("Dial %s: %v", host, err)
	}
	defer func() { _ = conn.Close() }()
	acceptResolverTestTCP(t, listener)
	remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		t.Fatalf("split remote address: %v", err)
	}
	return remoteHost
}

func acceptResolverTestTCP(t *testing.T, listener *net.TCPListener) {
	t.Helper()
	if err := listener.SetDeadline(
		time.Now().Add(2 * time.Second),
	); err != nil {
		t.Fatalf("set TCP listener deadline: %v", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept TCP connection: %v", err)
	}
	_ = conn.Close()
}

func resolverTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func netPortString(port int) string {
	return strconv.Itoa(port)
}

func resolverTestTCPPort(t *testing.T, listener *net.TCPListener) int {
	t.Helper()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf(
			"TCP listener address type = %T, want *net.TCPAddr",
			listener.Addr(),
		)
	}
	return address.Port
}

func resolverTestUDPPort(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	address, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"UDP listener address type = %T, want *net.UDPAddr",
			conn.LocalAddr(),
		)
	}
	return address.Port
}

type resolverTestDNSProvider struct {
	requests chan gdns.Request
	done     chan struct{}
	close    sync.Once

	mu        sync.Mutex
	hosts     map[string][]netip.Addr
	blocked   map[string]bool
	questions []gdns.Question
	setDNS    []netip.Addr
}

func newResolverTestDNSProvider() *resolverTestDNSProvider {
	provider := &resolverTestDNSProvider{
		requests: make(chan gdns.Request),
		done:     make(chan struct{}),
		hosts:    make(map[string][]netip.Addr),
		blocked:  make(map[string]bool),
	}
	go provider.run()
	return provider
}

func (p *resolverTestDNSProvider) Requests() chan<- gdns.Request {
	return p.requests
}

func (p *resolverTestDNSProvider) Close() error {
	p.close.Do(func() { close(p.done) })
	return nil
}

func (p *resolverTestDNSProvider) SetDNS(address netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setDNS = append(p.setDNS, address)
	return nil
}

func (p *resolverTestDNSProvider) UnsetDNS() error { return nil }

func (p *resolverTestDNSProvider) setHost(
	host string,
	addresses ...netip.Addr,
) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hosts[resolverTestDNSName(host)] = append([]netip.Addr(nil), addresses...)
}

func (p *resolverTestDNSProvider) blockHost(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blocked[resolverTestDNSName(host)] = true
}

func (p *resolverTestDNSProvider) takeQuestions() []gdns.Question {
	p.mu.Lock()
	defer p.mu.Unlock()
	questions := append([]gdns.Question(nil), p.questions...)
	p.questions = nil
	return questions
}

func (p *resolverTestDNSProvider) setDNSAddresses() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.Addr(nil), p.setDNS...)
}

func (p *resolverTestDNSProvider) run() {
	for {
		select {
		case <-p.done:
			return
		case request := <-p.requests:
			p.respond(request)
		}
	}
}

func (p *resolverTestDNSProvider) respond(request gdns.Request) {
	response := request.Message.Copy()
	if response == nil {
		request.Reply <- gdns.Response{}
		return
	}
	response.Response = true
	response.RCode = gdns.RCodeSuccess
	response.RecursionAvailable = true

	p.mu.Lock()
	blocked := false
	for _, question := range response.Questions {
		p.questions = append(p.questions, question)
		name := resolverTestDNSName(question.Name)
		if p.blocked[name] {
			blocked = true
			continue
		}
		addresses, found := p.hosts[name]
		if !found {
			response.RCode = gdns.RCodeNameError
			continue
		}
		for _, address := range addresses {
			address = address.Unmap()
			if question.Type == gdns.TypeA && !address.Is4() ||
				question.Type == gdns.TypeAAAA && !address.Is6() {
				continue
			}
			response.Answers = append(response.Answers, gdns.Resource{
				Name:  question.Name,
				Type:  question.Type,
				Class: gdns.ClassIN,
				TTL:   1,
				Data:  append([]byte(nil), address.AsSlice()...),
			})
		}
	}
	p.mu.Unlock()
	if blocked {
		select {
		case <-request.Context.Done():
		case <-p.done:
		}
		return
	}

	select {
	case request.Reply <- gdns.Response{Message: response}:
	case <-request.Context.Done():
	case <-p.done:
	}
}

func assertResolverTestQuestions(
	t *testing.T,
	questions []gdns.Question,
	host string,
	types ...uint16,
) {
	t.Helper()
	if len(questions) != len(types) {
		t.Fatalf("DNS questions = %v, want %d questions", questions, len(types))
	}
	wantName := resolverTestDNSName(host) + "."
	for i, question := range questions {
		if question.Name != wantName || question.Type != types[i] ||
			question.Class != gdns.ClassIN {
			t.Fatalf(
				"DNS question %d = %+v, want name %q, type %d, class IN",
				i,
				question,
				wantName,
				types[i],
			)
		}
	}
}

func resolverTestDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

type resolverTestDirectEnv struct {
	mu   sync.Mutex
	data []byte
}

func newResolverTestDirectEnv(contents string) *resolverTestDirectEnv {
	return &resolverTestDirectEnv{data: []byte(contents)}
}

func (e *resolverTestDirectEnv) env() linuxdns.Env {
	return linuxdns.Env{
		ReadFile:  e.readFile,
		WriteFile: e.writeFile,
		Remove:    e.remove,
	}
}

func (e *resolverTestDirectEnv) readFile(string) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.data == nil {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), e.data...), nil
}

func (e *resolverTestDirectEnv) writeFile(
	_ string,
	data []byte,
	_ os.FileMode,
) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data = append([]byte(nil), data...)
	return nil
}

func (e *resolverTestDirectEnv) remove(string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.data == nil {
		return os.ErrNotExist
	}
	e.data = nil
	return nil
}

func (e *resolverTestDirectEnv) contents() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return string(e.data)
}

type resolverTestRedirectNetwork struct {
	gonnect.Network
	target string

	mu    sync.Mutex
	dials []string
}

func (n *resolverTestRedirectNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	n.mu.Lock()
	n.dials = append(n.dials, address)
	n.mu.Unlock()
	_, port, err := net.SplitHostPort(address)
	if err == nil && port == "53" {
		address = n.target
	}
	return n.Network.Dial(ctx, network, address)
}

func (n *resolverTestRedirectNetwork) dialAddresses() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dials...)
}
