// nolint
package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func TestResolvedSetUnsetDNSOrderAndDynamicUpstreamChanges(t *testing.T) {
	upstreamA := startTestDNSUpstream(t, [4]byte{10, 0, 0, 1})
	upstreamB := startTestDNSUpstream(t, [4]byte{10, 0, 0, 2})
	managedA := netip.MustParseAddr("100.64.0.1")
	managedB := netip.MustParseAddr("100.64.0.2")
	managedC := netip.MustParseAddr("100.64.0.3")

	bus := newFakeResolvedBus(7)
	bus.setLinkDNS(upstreamA.addrPort)
	bus.revertDNS = []netip.AddrPort{upstreamA.addrPort}

	r := newTestResolved(t, bus)
	defer closeResolved(t, r)

	assertAResponse(t, r, "example.com.", [4]byte{10, 0, 0, 1})

	if err := r.SetDNS(managedA); err != nil {
		t.Fatalf("SetDNS(A): %v", err)
	}
	assertManagedDNS(t, bus, managedA)

	if err := r.SetDNS(managedB); err != nil {
		t.Fatalf("SetDNS(B): %v", err)
	}
	assertManagedDNS(t, bus, managedB)
	assertAResponse(t, r, "example.com.", [4]byte{10, 0, 0, 1})

	bus.setManagerDNS(7, upstreamB.addrPort)
	bus.setManagerDomains(
		7,
		resolvedGlobalDomain{IfIndex: 7, Domain: ".", RoutingOnly: false},
	)
	if err := r.syncResolvedState(); err != nil {
		t.Fatalf("sync dynamic upstream: %v", err)
	}
	assertManagedDNS(t, bus, managedB)
	assertAResponse(t, r, "example.com.", [4]byte{10, 0, 0, 2})

	bus.setLinkDNS(upstreamA.addrPort)
	bus.setLinkDomains(
		resolvedLinkDomain{Domain: "~dhcp.example", RoutingOnly: true},
	)
	bus.defaultRoute = false
	if err := r.syncResolvedState(); err != nil {
		t.Fatalf("sync managed DNS drift: %v", err)
	}
	assertManagedDNS(t, bus, managedB)
	assertAResponse(t, r, "dhcp.example.", [4]byte{10, 0, 0, 1})

	if err := r.UnsetDNS(); err != nil {
		t.Fatalf("UnsetDNS after SetDNS(B): %v", err)
	}
	if err := r.UnsetDNS(); err != nil {
		t.Fatalf("second UnsetDNS: %v", err)
	}
	if err := r.SetDNS(managedC); err != nil {
		t.Fatalf("SetDNS(C): %v", err)
	}
	assertManagedDNS(t, bus, managedC)
}

func TestResolvedRoutesSplitDNSUpstreams(t *testing.T) {
	defaultUpstream := startTestDNSUpstream(t, [4]byte{10, 0, 0, 10})
	corpUpstream := startTestDNSUpstream(t, [4]byte{10, 0, 0, 20})
	serviceUpstream := startTestDNSUpstream(t, [4]byte{10, 0, 0, 30})

	bus := newFakeResolvedBus(7)
	bus.setLinkDNS(defaultUpstream.addrPort)
	bus.setLinkDomains(resolvedLinkDomain{Domain: ".", RoutingOnly: false})
	bus.setManagerDNS(8, corpUpstream.addrPort)
	bus.setManagerDomains(
		8,
		resolvedGlobalDomain{
			IfIndex:     8,
			Domain:      "~corp.example",
			RoutingOnly: true,
		},
	)
	bus.setManagerDNS(9, serviceUpstream.addrPort)
	bus.setManagerDomains(
		9,
		resolvedGlobalDomain{
			IfIndex:     9,
			Domain:      "~svc.corp.example",
			RoutingOnly: true,
		},
	)

	r := newTestResolved(t, bus)
	defer closeResolved(t, r)

	assertAResponse(t, r, "www.example.com.", [4]byte{10, 0, 0, 10})
	assertAResponse(t, r, "db.corp.example.", [4]byte{10, 0, 0, 20})
	assertAResponse(t, r, "api.svc.corp.example.", [4]byte{10, 0, 0, 30})
}

func TestResolvedUsesFallbackWhenResolvedReportsNoUpstream(t *testing.T) {
	fallback := startTestDNSUpstream(t, [4]byte{10, 0, 0, 40})
	bus := newFakeResolvedBus(7)

	r := newTestResolved(t, bus, fallback.addrPort)
	defer closeResolved(t, r)

	assertAResponse(t, r, "fallback.example.", [4]byte{10, 0, 0, 40})
}

func newTestResolved(
	t *testing.T,
	bus *fakeResolvedBus,
	fallback ...netip.AddrPort,
) *Resolved {
	t.Helper()
	r, err := NewResolved(Env{
		ResolvedBus: func() (DBusConn, error) { return bus, nil },
	}, int(bus.ifidx), fallback...)
	if err != nil {
		t.Fatalf("NewResolved: %v", err)
	}
	return r
}

func closeResolved(t *testing.T, r *Resolved) {
	t.Helper()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func assertAResponse(t *testing.T, r *Resolved, name string, want [4]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	msg, err := gdns.Query(ctx, r, &gdns.Message{
		ID:               gdns.NextID(),
		RecursionDesired: true,
		Questions: []gdns.Question{{
			Name:  name,
			Type:  gdns.TypeA,
			Class: gdns.ClassIN,
		}},
	})
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("query %s got %d answers, want 1", name, len(msg.Answers))
	}
	if got := [4]byte(msg.Answers[0].Data); got != want {
		t.Fatalf("query %s got A %v, want %v", name, got, want)
	}
}

func assertManagedDNS(t *testing.T, bus *fakeResolvedBus, want netip.Addr) {
	t.Helper()
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.linkDNS) != 1 || bus.linkDNS[0].Addr() != want {
		t.Fatalf("link DNS = %v, want %s", bus.linkDNS, want)
	}
	if !reflect.DeepEqual(
		bus.linkDomains,
		[]resolvedLinkDomain{{Domain: ".", RoutingOnly: true}},
	) {
		t.Fatalf(
			"link domains = %#v, want root routing-only domain",
			bus.linkDomains,
		)
	}
	if !bus.defaultRoute {
		t.Fatal("link default route is false, want true")
	}
}

type testDNSUpstream struct {
	addrPort netip.AddrPort
	server   *gdns.Server
	provider *staticDNSProvider
}

func startTestDNSUpstream(t *testing.T, answer [4]byte) testDNSUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	provider := newStaticDNSProvider(answer)
	server := gdns.NewServer(pc, provider)
	t.Cleanup(func() {
		_ = server.Close()
		_ = provider.Close()
	})
	return testDNSUpstream{
		addrPort: netip.AddrPortFrom(
			netip.MustParseAddr("127.0.0.1"),
			uint16(addr.Port),
		),
		server:   server,
		provider: provider,
	}
}

type staticDNSProvider struct {
	answer [4]byte
	ch     chan gdns.Request
	done   chan struct{}
	once   sync.Once
}

func newStaticDNSProvider(answer [4]byte) *staticDNSProvider {
	p := &staticDNSProvider{
		answer: answer,
		ch:     make(chan gdns.Request),
		done:   make(chan struct{}),
	}
	go p.run()
	return p
}

func (p *staticDNSProvider) Requests() chan<- gdns.Request { return p.ch }

func (p *staticDNSProvider) Close() error {
	p.once.Do(func() { close(p.done) })
	return nil
}

func (p *staticDNSProvider) run() {
	for {
		select {
		case <-p.done:
			return
		case req := <-p.ch:
			resp := req.Message.Copy()
			resp.Response = true
			resp.RecursionAvailable = true
			if len(resp.Questions) > 0 {
				q := resp.Questions[0]
				resp.Answers = []gdns.Resource{{
					Name:  q.Name,
					Type:  gdns.TypeA,
					Class: gdns.ClassIN,
					TTL:   1,
					Data:  p.answer[:],
				}}
			}
			req.Reply <- gdns.Response{Message: resp}
		}
	}
}

type fakeResolvedBus struct {
	mu sync.Mutex

	ifidx int32

	linkDNS      []netip.AddrPort
	linkDomains  []resolvedLinkDomain
	defaultRoute bool
	revertDNS    []netip.AddrPort

	managerDNS     map[int32][]netip.AddrPort
	managerDomains map[int32][]resolvedGlobalDomain

	signals []chan<- *dbus.Signal
	closed  bool
}

func newFakeResolvedBus(ifidx int32) *fakeResolvedBus {
	return &fakeResolvedBus{
		ifidx:          ifidx,
		managerDNS:     make(map[int32][]netip.AddrPort),
		managerDomains: make(map[int32][]resolvedGlobalDomain),
	}
}

func (b *fakeResolvedBus) Object(
	_ string,
	path dbus.ObjectPath,
) dbus.BusObject {
	return fakeResolvedObject{bus: b, path: path}
}

func (b *fakeResolvedBus) AddMatchSignal(
	options ...dbus.MatchOption,
) error {
	return nil
}

func (b *fakeResolvedBus) Signal(ch chan<- *dbus.Signal) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.signals = append(b.signals, ch)
}

func (b *fakeResolvedBus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *fakeResolvedBus) setLinkDNS(servers ...netip.AddrPort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.linkDNS = append([]netip.AddrPort(nil), servers...)
}

func (b *fakeResolvedBus) setLinkDomains(domains ...resolvedLinkDomain) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.linkDomains = append([]resolvedLinkDomain(nil), domains...)
}

func (b *fakeResolvedBus) setManagerDNS(
	ifidx int32,
	servers ...netip.AddrPort,
) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.managerDNS[ifidx] = append([]netip.AddrPort(nil), servers...)
}

func (b *fakeResolvedBus) setManagerDomains(
	ifidx int32,
	domains ...resolvedGlobalDomain,
) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.managerDomains[ifidx] = append([]resolvedGlobalDomain(nil), domains...)
}

type fakeResolvedObject struct {
	bus  *fakeResolvedBus
	path dbus.ObjectPath
}

func (o fakeResolvedObject) Call(
	method string,
	flags dbus.Flags,
	args ...any,
) *dbus.Call {
	return o.CallWithContext(context.Background(), method, flags, args...)
}

func (o fakeResolvedObject) CallWithContext(
	_ context.Context,
	method string,
	_ dbus.Flags,
	args ...any,
) *dbus.Call {
	o.bus.mu.Lock()
	defer o.bus.mu.Unlock()

	call := &dbus.Call{Done: make(chan *dbus.Call, 1)}
	switch method {
	case dbusResolvedInterface + ".GetLink":
		call.Body = []any{dbus.ObjectPath(dbusResolvedPath + "/link/_7")}
	case dbusResolvedInterface + ".SetLinkDNS":
		o.bus.linkDNS = linkNameserversAsAddrPorts(
			args[1].([]resolvedLinkNameserver),
		)
	case dbusResolvedInterface + ".SetLinkDomains":
		o.bus.linkDomains = append(
			[]resolvedLinkDomain(nil),
			args[1].([]resolvedLinkDomain)...)
	case dbusResolvedInterface + ".SetLinkDefaultRoute":
		o.bus.defaultRoute = args[1].(bool)
	case dbusResolvedInterface + ".RevertLink":
		o.bus.linkDNS = append([]netip.AddrPort(nil), o.bus.revertDNS...)
		o.bus.linkDomains = nil
		o.bus.defaultRoute = false
	case dbusResolvedInterface + ".SetLinkLLMNR",
		dbusResolvedInterface + ".SetLinkMulticastDNS",
		dbusResolvedInterface + ".SetLinkDNSSEC",
		dbusResolvedInterface + ".SetLinkDNSOverTLS",
		dbusResolvedInterface + ".FlushCaches":
	case dbusPropertiesInterface + ".Get":
		value, err := o.property(args[0].(string), args[1].(string))
		if err != nil {
			call.Err = err
		} else {
			call.Body = []any{dbus.MakeVariant(value)}
		}
	default:
		call.Err = errors.New("unexpected D-Bus method: " + method)
	}
	call.Done <- call
	return call
}

func (o fakeResolvedObject) property(iface, member string) (any, error) {
	switch {
	case iface == dbusLinkInterface && member == "DNSEx":
		return linkAddrPortsAsDNSEx(o.bus.linkDNS), nil
	case iface == dbusLinkInterface && member == "DNS":
		return linkAddrPortsAsDNS(o.bus.linkDNS), nil
	case iface == dbusLinkInterface && member == "Domains":
		return append([]resolvedLinkDomain(nil), o.bus.linkDomains...), nil
	case iface == dbusLinkInterface && member == "DefaultRoute":
		return o.bus.defaultRoute, nil
	case iface == dbusResolvedInterface && member == "DNSEx":
		return managerAddrPortsAsDNSEx(o.bus.managerDNS), nil
	case iface == dbusResolvedInterface && member == "DNS":
		return managerAddrPortsAsDNS(o.bus.managerDNS), nil
	case iface == dbusResolvedInterface && member == "Domains":
		var out []resolvedGlobalDomain
		for _, domains := range o.bus.managerDomains {
			out = append(out, domains...)
		}
		return out, nil
	default:
		return nil, errors.New(
			"unexpected D-Bus property: " + iface + "." + member,
		)
	}
}

func (o fakeResolvedObject) Go(
	method string,
	flags dbus.Flags,
	ch chan *dbus.Call,
	args ...any,
) *dbus.Call {
	return o.GoWithContext(context.Background(), method, flags, ch, args...)
}

func (o fakeResolvedObject) GoWithContext(
	ctx context.Context,
	method string,
	flags dbus.Flags,
	ch chan *dbus.Call,
	args ...any,
) *dbus.Call {
	call := o.CallWithContext(ctx, method, flags, args...)
	if ch != nil {
		ch <- call
	}
	return call
}

func (o fakeResolvedObject) AddMatchSignal(
	iface, member string,
	options ...dbus.MatchOption,
) *dbus.Call {
	return &dbus.Call{Done: make(chan *dbus.Call, 1)}
}

func (o fakeResolvedObject) RemoveMatchSignal(
	iface, member string,
	options ...dbus.MatchOption,
) *dbus.Call {
	return &dbus.Call{Done: make(chan *dbus.Call, 1)}
}

func (o fakeResolvedObject) GetProperty(
	p string,
) (dbus.Variant, error) {
	return dbus.Variant{}, nil
}

func (o fakeResolvedObject) StoreProperty(
	p string,
	value any,
) error {
	return nil
}

func (o fakeResolvedObject) SetProperty(
	p string,
	v any,
) error {
	return nil
}

func (o fakeResolvedObject) Destination() string { return dbusResolvedObject }

func (o fakeResolvedObject) Path() dbus.ObjectPath { return o.path }

func linkNameserversAsAddrPorts(in []resolvedLinkNameserver) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(in))
	for _, server := range in {
		if addr, ok := addrFromResolved(server.Family, server.Address); ok {
			out = append(out, netip.AddrPortFrom(addr, 53))
		}
	}
	return out
}

func linkAddrPortsAsDNSEx(in []netip.AddrPort) []resolvedLinkNameserverEx {
	out := make([]resolvedLinkNameserverEx, 0, len(in))
	for _, server := range in {
		family, raw := addrFamilyBytes(server.Addr())
		out = append(out, resolvedLinkNameserverEx{
			Family:  family,
			Address: raw,
			Port:    server.Port(),
		})
	}
	return out
}

func linkAddrPortsAsDNS(in []netip.AddrPort) []resolvedLinkNameserver {
	out := make([]resolvedLinkNameserver, 0, len(in))
	for _, server := range in {
		family, raw := addrFamilyBytes(server.Addr())
		out = append(out, resolvedLinkNameserver{Family: family, Address: raw})
	}
	return out
}

func managerAddrPortsAsDNSEx(
	in map[int32][]netip.AddrPort,
) []resolvedGlobalNameserverEx {
	var out []resolvedGlobalNameserverEx
	for ifidx, servers := range in {
		for _, server := range servers {
			family, raw := addrFamilyBytes(server.Addr())
			out = append(out, resolvedGlobalNameserverEx{
				IfIndex: ifidx,
				Family:  family,
				Address: raw,
				Port:    server.Port(),
			})
		}
	}
	return out
}

func managerAddrPortsAsDNS(
	in map[int32][]netip.AddrPort,
) []resolvedGlobalNameserver {
	var out []resolvedGlobalNameserver
	for ifidx, servers := range in {
		for _, server := range servers {
			family, raw := addrFamilyBytes(server.Addr())
			out = append(out, resolvedGlobalNameserver{
				IfIndex: ifidx,
				Family:  family,
				Address: raw,
			})
		}
	}
	return out
}

func addrFamilyBytes(addr netip.Addr) (int32, []byte) {
	if addr.Is4() {
		raw := addr.As4()
		return unix.AF_INET, raw[:]
	}
	raw := addr.As16()
	return unix.AF_INET6, raw[:]
}
