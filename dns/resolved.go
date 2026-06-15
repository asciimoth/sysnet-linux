//go:build linux

package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	// Well-known D-Bus name, root object, and manager interface exported by
	// systemd-resolved.
	dbusResolvedObject    = "org.freedesktop.resolve1"
	dbusResolvedPath      = "/org/freedesktop/resolve1"
	dbusResolvedInterface = "org.freedesktop.resolve1.Manager"

	// Per-link D-Bus interface exposed by objects returned from Manager.GetLink.
	dbusLinkInterface = "org.freedesktop.resolve1.Link"

	dbusPropertiesInterface = "org.freedesktop.DBus.Properties"
	dbusPropertiesChanged   = dbusPropertiesInterface + ".PropertiesChanged"
	dbusBusPath             = "/org/freedesktop/DBus"
	dbusBusInterface        = "org.freedesktop.DBus"
	dbusNameOwnerChanged    = "NameOwnerChanged"

	// Upper bound for operations that reconfigure host DNS state. These calls
	// are synchronous D-Bus RPCs and should fail promptly if resolved is wedged
	// or unavailable.
	resolvedReconfigTimeout = 5 * time.Second
	resolvedSyncDelay       = 200 * time.Millisecond
	resolvedBackendName     = "default"
	maxResolvedIfIndex      = int64(1<<31 - 1)
)

var (
	_ DNSProvider = &Resolved{}
)

// resolvedLinkNameserver is the legacy per-link nameserver representation used
// by SetLinkDNS and by the Link.DNS property. It has no port field; resolved
// treats such servers as UDP/TCP port 53.
type resolvedLinkNameserver struct {
	Family  int32
	Address []byte
}

// resolvedGlobalNameserver is the legacy Manager.DNS entry format. IfIndex is
// the interface index that owns the server, or zero when resolved reports a
// global server not bound to a specific link.
type resolvedGlobalNameserver struct {
	IfIndex int32
	Family  int32
	Address []byte
}

// resolvedLinkNameserverEx is the modern per-link nameserver representation
// from Link.DNSEx. In addition to the address, resolved can report a custom
// port and an optional server name used for DNS-over-TLS.
type resolvedLinkNameserverEx struct {
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

// resolvedGlobalNameserverEx is the modern Manager.DNSEx entry format. The
// extra fields have the same meaning as resolvedLinkNameserverEx.
type resolvedGlobalNameserverEx struct {
	IfIndex int32
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

// resolvedGlobalDomain is the Manager.Domains entry format. IfIndex is the
// link that owns the domain, or zero for manager-wide domains.
type resolvedGlobalDomain struct {
	IfIndex     int32
	Domain      string
	RoutingOnly bool
}

// resolvedLinkDomain mirrors the tuple accepted by SetLinkDomains.
//
// RoutingOnly=true and Domain="." means "route all DNS names through this
// link", without adding "." as a search domain.
type resolvedLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

// Resolved is a DNSProvider backed by systemd-resolved.
//
// A Resolved instance owns one system bus connection and one resolved link. The
// link is identified by Linux interface index, because that is what resolved's
// Manager.SetLink* methods accept. Close reverts the link configuration and
// releases the internal forwarding client.
//
// Resolved deliberately does not use systemd-resolved itself as its request
// forwarder. It forwards through direct gonnect DNS clients backed by the
// upstream servers reported by resolved, and refreshes that client when
// resolved reports dynamic configuration changes. This avoids loops after
// SetDNS points the host at this provider while still following DHCP and other
// resolved upstream changes.
type Resolved struct {
	env   Env
	ifidx int32
	conn  DBusConn
	mgr   dbus.BusObject
	base  *gdns.Router

	mu           sync.Mutex
	dnsMu        sync.Mutex
	closed       bool
	clients      map[string]gdns.Interface
	fallback     []netip.AddrPort
	setDNS       netip.Addr
	setDNSActive bool
	upstreamSig  []string
	watchCancel  context.CancelFunc

	targetServers []netip.AddrPort
	targetDomains []resolvedLinkDomain
}

var _ DNSProvider = (*Resolved)(nil)

// NewResolved returns a DNSProvider backed by systemd-resolved.
//
// env provides access to the host environment. Any nil callbacks are replaced
// with production defaults.
//
// ifidx is the kernel network interface index to configure through resolved's
// per-link D-Bus API. Requests are forwarded directly to the DNS servers that
// resolved reports for that link, so SetDNS does not create a DNS loop through
// the newly installed server. fallback is used only if resolved does not report
// any usable link or global DNS servers.
func NewResolved(
	env Env,
	ifidx int,
	fallback ...netip.AddrPort,
) (*Resolved, error) {
	env = env.withDefaults()
	ifidx32, err := resolvedIfIndex(ifidx)
	if err != nil {
		return nil, err
	}

	env.Logf("resolved: connecting system bus")
	conn, err := env.ResolvedBus()
	if err != nil {
		return nil, fmt.Errorf("resolved: connect system bus: %w", err)
	}

	r := &Resolved{
		env:   env,
		ifidx: ifidx32,
		conn:  conn,
		mgr: conn.Object(
			dbusResolvedObject,
			dbus.ObjectPath(dbusResolvedPath),
		),
	}

	r.fallback = append([]netip.AddrPort(nil), fallback...)
	r.base = gdns.NewRouter()
	r.clients = make(map[string]gdns.Interface)
	env.Logf("resolved: initializing interface index %d", ifidx)
	if err := r.refreshUpstreams(netip.Addr{}); err != nil {
		_ = r.base.Close()
		_ = conn.Close()
		return nil, err
	}
	if err := r.startMonitor(); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

func resolvedIfIndex(ifidx int) (int32, error) {
	if ifidx <= 0 || int64(ifidx) > maxResolvedIfIndex {
		return 0, fmt.Errorf("resolved: invalid interface index %d", ifidx)
	}
	return int32(ifidx), nil //nolint:gosec // ifidx is bounds-checked above.
}

// Requests returns the queue consumed by the internal forwarding client.
//
// Requests sent to this channel are forwarded to the current resolved upstream
// servers, not to the server most recently installed with SetDNS.
func (r *Resolved) Requests() chan<- gdns.Request {
	return r.base.Requests()
}

// SetDNS installs server as the default DNS server for this resolved link.
//
// The method configures a per-link nameserver, adds a routing-only root domain
// so all names prefer the link, marks the link as a default route when the
// running resolved version supports it, and flushes resolved's caches. LLMNR,
// multicast DNS, DNSSEC, and DNS-over-TLS are disabled on a best-effort basis
// for this link because this provider expects plain DNS forwarding to the
// supplied server.
//
// The configuration lifetime is bounded by the Resolved object. UnsetDNS and
// Close call RevertLink to ask resolved to discard the per-link settings
// applied here.
//
// Resolved watches resolved configuration changes and rewrites this setup when
// it is changed externally. Calling UnsetDNS stops that active maintenance
// until SetDNS is called again.
func (r *Resolved) SetDNS(server netip.Addr) error {
	r.env.Logf("resolved: SetDNS(%s)", server)
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return gdns.ErrClosed
	}
	if !server.IsValid() {
		return errors.New("resolved: invalid DNS server")
	}

	r.mu.Lock()
	oldServer := r.setDNS
	oldServerActive := r.setDNSActive
	r.mu.Unlock()

	exclude := []netip.Addr{server}
	if oldServerActive {
		exclude = append(exclude, oldServer)
	}
	if err := r.refreshUpstreamsExcluding(exclude); err != nil {
		return err
	}
	if err := r.applyDNS(server); err != nil {
		return err
	}

	r.mu.Lock()
	r.setDNS = server
	r.setDNSActive = true
	r.mu.Unlock()
	r.env.Logf("resolved: SetDNS(%s) complete", server)
	return nil
}

// UnsetDNS rolls back resolved link configuration previously applied by
// SetDNS.
//
// After this method returns, Resolved no longer rewrites the SetDNS server in
// response to resolved configuration changes. Calling SetDNS later enables that
// maintenance again.
func (r *Resolved) UnsetDNS() error {
	r.env.Logf("resolved: UnsetDNS")
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return gdns.ErrClosed
	}
	active := r.setDNSActive
	server := r.setDNS
	r.setDNS = netip.Addr{}
	r.setDNSActive = false
	r.mu.Unlock()
	if !active {
		r.env.Logf("resolved: UnsetDNS skipped, no active managed DNS")
		return nil
	}

	err := r.revertDNS()
	if err == nil {
		r.env.Logf("resolved: reverted managed DNS")
		return r.refreshUpstreams(netip.Addr{})
	}
	if refreshErr := r.refreshUpstreams(server); refreshErr != nil {
		err = errors.Join(err, refreshErr)
	}
	return err
}

func (r *Resolved) applyDNS(server netip.Addr) error {
	r.env.Logf("resolved: applying managed DNS %s to ifidx %d", server, r.ifidx)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		resolvedReconfigTimeout,
	)
	defer cancel()

	err := r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".SetLinkDNS",
		0,
		r.ifidx,
		[]resolvedLinkNameserver{resolvedNameserver(server)},
	).Store()
	if err != nil {
		return fmt.Errorf("resolved: SetLinkDNS: %w", err)
	}
	r.env.Logf("resolved: SetLinkDNS applied")

	err = r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".SetLinkDomains",
		0,
		r.ifidx,
		[]resolvedLinkDomain{{Domain: ".", RoutingOnly: true}},
	).Store()
	if err != nil {
		return fmt.Errorf("resolved: SetLinkDomains: %w", err)
	}
	r.env.Logf("resolved: SetLinkDomains applied")

	defaultRouteSupported := true
	err = r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".SetLinkDefaultRoute",
		0,
		r.ifidx,
		true,
	).Store()
	if err != nil {
		if isDBusUnknownMethod(err) {
			r.env.Logf("resolved: SetLinkDefaultRoute unsupported")
			defaultRouteSupported = false
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("resolved: SetLinkDefaultRoute: %w", err)
	}
	if defaultRouteSupported {
		r.env.Logf("resolved: SetLinkDefaultRoute applied")
	}

	if err := r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".SetLinkLLMNR",
		0,
		r.ifidx,
		"no",
	).Err; err != nil {
		r.env.Logf("resolved: SetLinkLLMNR best-effort error: %v", err)
	}
	if err := r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".SetLinkMulticastDNS",
		0,
		r.ifidx,
		"no",
	).Err; err != nil {
		r.env.Logf("resolved: SetLinkMulticastDNS best-effort error: %v", err)
	}
	if err := r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".SetLinkDNSSEC",
		0,
		r.ifidx,
		"no",
	).Err; err != nil {
		r.env.Logf("resolved: SetLinkDNSSEC best-effort error: %v", err)
	}
	if err := r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".SetLinkDNSOverTLS",
		0,
		r.ifidx,
		"no",
	).Err; err != nil {
		r.env.Logf("resolved: SetLinkDNSOverTLS best-effort error: %v", err)
	}
	if err := r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".FlushCaches",
		0,
	).Err; err != nil {
		r.env.Logf("resolved: FlushCaches best-effort error: %v", err)
	}

	return nil
}

func (r *Resolved) startMonitor() error {
	r.env.Logf("resolved: starting monitor")
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan *dbus.Signal, 16)

	if err := r.conn.AddMatchSignal(
		dbus.WithMatchPathNamespace(dbus.ObjectPath(dbusResolvedPath)),
		dbus.WithMatchInterface(dbusPropertiesInterface),
		dbus.WithMatchMember("PropertiesChanged"),
	); err != nil {
		cancel()
		return fmt.Errorf("resolved: subscribe properties changes: %w", err)
	}
	if err := r.conn.AddMatchSignal(
		dbus.WithMatchObjectPath(dbus.ObjectPath(dbusBusPath)),
		dbus.WithMatchInterface(dbusBusInterface),
		dbus.WithMatchMember(dbusNameOwnerChanged),
		dbus.WithMatchArg(0, dbusResolvedObject),
	); err != nil {
		cancel()
		return fmt.Errorf("resolved: subscribe owner changes: %w", err)
	}

	r.conn.Signal(signals)
	r.mu.Lock()
	r.watchCancel = cancel
	r.mu.Unlock()

	go r.monitor(ctx, signals)
	r.env.Logf("resolved: monitor started")
	return nil
}

func (r *Resolved) monitor(ctx context.Context, signals <-chan *dbus.Signal) {
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	schedule := func() {
		if timer == nil {
			timer = time.NewTimer(resolvedSyncDelay)
			timerC = timer.C
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(resolvedSyncDelay)
		timerC = timer.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case signal, ok := <-signals:
			if !ok {
				return
			}
			if resolvedSignalNeedsSync(signal) {
				r.env.Logf(
					"resolved: scheduling sync after signal %s",
					signal.Name,
				)
				schedule()
			}
		case <-timerC:
			timerC = nil
			if err := r.syncResolvedState(); err != nil {
				r.env.Logf("resolved: sync error: %v", err)
			}
		}
	}
}

func resolvedSignalNeedsSync(signal *dbus.Signal) bool {
	if signal == nil {
		return false
	}
	if signal.Name == dbusBusInterface+"."+dbusNameOwnerChanged {
		if signal.Path != dbus.ObjectPath(dbusBusPath) ||
			len(signal.Body) != 3 {
			return false
		}
		name, _ := signal.Body[0].(string)
		newOwner, _ := signal.Body[2].(string)
		return name == dbusResolvedObject && newOwner != ""
	}
	if signal.Name != dbusPropertiesChanged {
		return false
	}
	path := string(signal.Path)
	return path == dbusResolvedPath ||
		strings.HasPrefix(path, dbusResolvedPath+"/link/")
}

func (r *Resolved) syncResolvedState() error {
	r.env.Logf("resolved: syncing state")
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return gdns.ErrClosed
	}
	managedDNS := r.setDNS
	managedDNSActive := r.setDNSActive
	fallback := append([]netip.AddrPort(nil), r.fallback...)
	r.mu.Unlock()

	linkServers, err := r.linkDNSServers()
	if err != nil {
		return err
	}
	linkDomains, err := r.linkDomains()
	if err != nil {
		linkDomains = nil
	}

	needsApply, err := r.reapplyDNSIfNeeded(
		managedDNSActive,
		managedDNS,
		linkServers,
	)
	if err != nil {
		return err
	}

	if needsApply {
		err = r.refreshUpstreamsFromLink(
			fallback,
			[]netip.Addr{managedDNS},
			linkServers,
			linkDomains,
		)
	} else {
		err = r.refreshUpstreamsWithFallback(
			fallback,
			[]netip.Addr{managedDNS},
		)
	}
	if err != nil {
		return err
	}
	r.env.Logf("resolved: sync complete")
	return nil
}

func (r *Resolved) reapplyDNSIfNeeded(
	managedDNSActive bool,
	managedDNS netip.Addr,
	linkServers []netip.AddrPort,
) (bool, error) {
	if !managedDNSActive {
		return false, nil
	}

	needsApply, err := r.linkConfigNeedsApply(managedDNS, linkServers)
	if err != nil {
		return false, err
	}
	if !needsApply {
		return false, nil
	}

	r.env.Logf("resolved: managed DNS drift detected")
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()

	r.mu.Lock()
	stillActive := r.setDNSActive && r.setDNS == managedDNS && !r.closed
	r.mu.Unlock()
	if !stillActive {
		r.env.Logf(
			"resolved: managed DNS no longer active, skipping reapply",
		)
		return false, nil
	}
	if err := r.applyDNS(managedDNS); err != nil {
		return false, err
	}
	return true, nil
}

func (r *Resolved) refreshUpstreams(exclude netip.Addr) error {
	return r.refreshUpstreamsExcluding([]netip.Addr{exclude})
}

func (r *Resolved) refreshUpstreamsExcluding(exclude []netip.Addr) error {
	r.mu.Lock()
	fallback := append([]netip.AddrPort(nil), r.fallback...)
	r.mu.Unlock()

	return r.refreshUpstreamsWithFallback(fallback, exclude)
}

func (r *Resolved) refreshUpstreamsWithFallback(
	fallback []netip.AddrPort,
	exclude []netip.Addr,
) error {
	cfg, err := r.upstreamConfig(fallback, exclude)
	if err != nil {
		return err
	}

	r.mu.Lock()
	if sameStrings(cfg.signature, r.upstreamSig) {
		r.mu.Unlock()
		r.env.Logf("resolved: upstream configuration unchanged")
		return nil
	}
	r.mu.Unlock()

	return r.setUpstreamConfig(cfg)
}

func (r *Resolved) refreshUpstreamsFromLink(
	fallback []netip.AddrPort,
	exclude []netip.Addr,
	linkServers []netip.AddrPort,
	linkDomains []resolvedLinkDomain,
) error {
	cfg, err := r.upstreamConfigFromLink(
		fallback,
		exclude,
		linkServers,
		linkDomains,
	)
	if err != nil {
		return err
	}

	r.mu.Lock()
	if sameStrings(cfg.signature, r.upstreamSig) {
		r.mu.Unlock()
		r.env.Logf("resolved: upstream configuration unchanged")
		return nil
	}
	r.mu.Unlock()

	return r.setUpstreamConfig(cfg)
}

func (r *Resolved) setUpstreamConfig(cfg resolvedUpstreamConfig) error {
	r.env.Logf(
		"resolved: updating upstream configuration with %d route(s)",
		len(cfg.routes),
	)
	clients := make(map[string]gdns.Interface, len(cfg.routes))
	for _, route := range cfg.routes {
		clients[route.name] = gdns.NewClient(nil, route.urls...)
	}
	routeFunc := resolvedRouteFunc(cfg.routes)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		closeDNSClients(clients)
		return gdns.ErrClosed
	}
	oldClients := r.clients
	for name, client := range clients {
		if err := r.base.Attach(name, client); err != nil {
			r.mu.Unlock()
			closeDNSClients(clients)
			return err
		}
	}
	if err := r.base.SetRouter(routeFunc); err != nil {
		r.mu.Unlock()
		closeDNSClients(clients)
		return err
	}
	for name := range oldClients {
		if _, ok := clients[name]; !ok {
			_ = r.base.Detach(name)
		}
	}
	r.clients = clients
	r.upstreamSig = append([]string(nil), cfg.signature...)
	r.targetServers = append([]netip.AddrPort(nil), cfg.targetServers...)
	r.targetDomains = append([]resolvedLinkDomain(nil), cfg.targetDomains...)
	r.mu.Unlock()

	closeDNSClients(oldClients)
	r.env.Logf("resolved: upstream configuration updated")
	return nil
}

// Close reverts the resolved link configuration and releases all resources.
//
// Close is idempotent. It attempts every cleanup step and returns the joined
// error, if any, so a failure to revert the link does not prevent the internal
// DNS client or D-Bus connection from being closed.
func (r *Resolved) Close() error {
	r.env.Logf("resolved: Close")
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		r.env.Logf("resolved: Close skipped, already closed")
		return nil
	}
	r.closed = true
	cancel := r.watchCancel
	clients := r.clients
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()

	err := r.revertDNS()
	if r.base != nil {
		err = errors.Join(err, r.base.Close())
	}
	for _, client := range clients {
		if client != nil {
			err = errors.Join(err, client.Close())
		}
	}
	if r.conn != nil {
		err = errors.Join(err, r.conn.Close())
	}

	if err != nil {
		r.env.Logf("resolved: Close finished with error: %v", err)
	} else {
		r.env.Logf("resolved: Close complete")
	}
	return err
}

func (r *Resolved) revertDNS() error {
	r.env.Logf("resolved: reverting link %d", r.ifidx)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		resolvedReconfigTimeout,
	)
	defer cancel()

	var err error
	if r.mgr != nil {
		err = errors.Join(
			err,
			r.mgr.CallWithContext(
				ctx,
				dbusResolvedInterface+".RevertLink",
				0,
				r.ifidx,
			).Err,
		)
	}
	return err
}

type resolvedUpstreamConfig struct {
	routes        []resolvedUpstreamRoute
	signature     []string
	targetServers []netip.AddrPort
	targetDomains []resolvedLinkDomain
}

type resolvedUpstreamRoute struct {
	name    string
	domains []string
	urls    []string
}

func (r *Resolved) upstreamConfig(
	fallback []netip.AddrPort,
	exclude []netip.Addr,
) (resolvedUpstreamConfig, error) {
	targetServers, err := r.linkDNSServers()
	if err != nil {
		return resolvedUpstreamConfig{}, err
	}

	targetDomains, err := r.linkDomains()
	if err != nil {
		targetDomains = nil
	}

	return r.upstreamConfigFromLink(
		fallback,
		exclude,
		targetServers,
		targetDomains,
	)
}

func (r *Resolved) upstreamConfigFromLink(
	fallback []netip.AddrPort,
	exclude []netip.Addr,
	targetServers []netip.AddrPort,
	targetDomains []resolvedLinkDomain,
) (resolvedUpstreamConfig, error) {
	r.mu.Lock()
	savedTargetServers := append([]netip.AddrPort(nil), r.targetServers...)
	savedTargetDomains := append([]resolvedLinkDomain(nil), r.targetDomains...)
	r.mu.Unlock()

	targetServers = filterAddr(
		append([]netip.AddrPort(nil), targetServers...),
		exclude,
	)

	managerServers, err := r.managerDNSServers()
	if err != nil {
		return resolvedUpstreamConfig{}, err
	}
	managerDomains, err := r.managerDomains()
	if err != nil {
		managerDomains = nil
	}

	if len(targetServers) == 0 {
		if servers := filterAddr(
			managerServers[r.ifidx],
			exclude,
		); len(
			servers,
		) > 0 {
			targetServers = servers
			targetDomains = globalDomainsAsLinkDomains(managerDomains[r.ifidx])
		} else {
			targetServers = filterAddr(savedTargetServers, exclude)
			targetDomains = savedTargetDomains
		}
	}

	cfg := resolvedUpstreamConfig{}
	cfg.targetServers = append([]netip.AddrPort(nil), targetServers...)
	cfg.targetDomains = append([]resolvedLinkDomain(nil), targetDomains...)

	builder := resolvedRouteBuilder{}
	builder.addLink(targetServers, targetDomains)

	ifindices := make([]int32, 0, len(managerServers))
	for ifidx := range managerServers {
		ifindices = append(ifindices, ifidx)
	}
	sort.Slice(ifindices, func(i, j int) bool {
		return ifindices[i] < ifindices[j]
	})
	for _, ifidx := range ifindices {
		if ifidx == r.ifidx {
			continue
		}
		servers := managerServers[ifidx]
		servers = filterAddr(servers, exclude)
		if len(servers) == 0 {
			continue
		}
		builder.addGlobal(servers, managerDomains[ifidx])
	}

	if builder.empty() {
		builder.addDefault(
			filterAddr(append([]netip.AddrPort(nil), fallback...), exclude),
		)
	}
	if builder.empty() {
		return resolvedUpstreamConfig{}, errors.New(
			"resolved: no upstream DNS servers",
		)
	}

	cfg.routes, cfg.signature = builder.config()
	if len(cfg.routes) == 0 {
		return resolvedUpstreamConfig{}, errors.New(
			"resolved: no usable upstream DNS servers",
		)
	}
	return cfg, nil
}

func globalDomainsAsLinkDomains(
	domains []resolvedGlobalDomain,
) []resolvedLinkDomain {
	out := make([]resolvedLinkDomain, 0, len(domains))
	for _, domain := range domains {
		out = append(out, resolvedLinkDomain{
			Domain:      domain.Domain,
			RoutingOnly: domain.RoutingOnly,
		})
	}
	return out
}

type resolvedRouteBuilder struct {
	routes []resolvedRouteInput
}

type resolvedRouteInput struct {
	domains []string
	servers []netip.AddrPort
}

func (b *resolvedRouteBuilder) addLink(
	servers []netip.AddrPort,
	domains []resolvedLinkDomain,
) {
	b.add(servers, linkDomainRoutes(domains))
}

func (b *resolvedRouteBuilder) addGlobal(
	servers []netip.AddrPort,
	domains []resolvedGlobalDomain,
) {
	b.add(servers, globalDomainRoutes(domains))
}

func (b *resolvedRouteBuilder) addDefault(servers []netip.AddrPort) {
	b.add(servers, []string{"."})
}

func (b *resolvedRouteBuilder) add(
	servers []netip.AddrPort,
	domains []string,
) {
	servers = dedupeServers(servers)
	if len(servers) == 0 {
		return
	}
	if len(domains) == 0 {
		domains = []string{"."}
	}
	b.routes = append(b.routes, resolvedRouteInput{
		domains: dedupeStrings(domains),
		servers: servers,
	})
}

func (b *resolvedRouteBuilder) empty() bool {
	return len(b.routes) == 0
}

func (b *resolvedRouteBuilder) config() ([]resolvedUpstreamRoute, []string) {
	routes := make([]resolvedUpstreamRoute, 0, len(b.routes))
	signature := make([]string, 0, len(b.routes))
	for i, input := range b.routes {
		urls := serverURLs(input.servers)
		if len(urls) == 0 {
			continue
		}
		route := resolvedUpstreamRoute{
			name:    fmt.Sprintf("%s-%d", resolvedBackendName, i),
			domains: input.domains,
			urls:    urls,
		}
		routes = append(routes, route)
		signature = append(
			signature,
			route.name+"|"+strings.Join(route.domains, ",")+"|"+
				strings.Join(route.urls, ","),
		)
	}
	return routes, signature
}

func resolvedRouteFunc(routes []resolvedUpstreamRoute) gdns.RouteFunc {
	routes = append([]resolvedUpstreamRoute(nil), routes...)
	sort.SliceStable(routes, func(i, j int) bool {
		return longestDomain(
			routes[i].domains,
		) > longestDomain(
			routes[j].domains,
		)
	})
	return func(msg *gdns.Message) string {
		name := resolvedQuestionName(msg)
		for _, route := range routes {
			for _, domain := range route.domains {
				if domain == "." || dnsNameMatchesDomain(name, domain) {
					return route.name
				}
			}
		}
		return ""
	}
}

func resolvedQuestionName(msg *gdns.Message) string {
	if msg == nil || len(msg.Questions) == 0 {
		return "."
	}
	return normalizeResolvedDomain(msg.Questions[0].Name)
}

func dnsNameMatchesDomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func longestDomain(domains []string) int {
	var maxLen int
	for _, domain := range domains {
		if domain == "." {
			continue
		}
		if len(domain) > maxLen {
			maxLen = len(domain)
		}
	}
	return maxLen
}

func linkDomainRoutes(domains []resolvedLinkDomain) []string {
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		out = append(out, normalizeResolvedDomain(domain.Domain))
	}
	return out
}

func globalDomainRoutes(domains []resolvedGlobalDomain) []string {
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		out = append(out, normalizeResolvedDomain(domain.Domain))
	}
	return out
}

func normalizeResolvedDomain(domain string) string {
	domain = strings.TrimSpace(strings.TrimPrefix(domain, "~"))
	if domain == "" || domain == "." {
		return "."
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	return domain + "."
}

func dedupeServers(servers []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(servers))
	seen := make(map[netip.AddrPort]bool, len(servers))
	for _, server := range servers {
		if !server.IsValid() || seen[server] {
			continue
		}
		seen[server] = true
		out = append(out, server)
	}
	return out
}

func serverURLs(servers []netip.AddrPort) []string {
	urls := make([]string, 0, len(servers))
	for _, server := range dedupeServers(servers) {
		urls = append(urls, "udp://"+server.String())
	}
	return urls
}

func dedupeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return longestDomain([]string{out[i]}) > longestDomain([]string{out[j]})
	})
	return out
}

func closeDNSClients(clients map[string]gdns.Interface) {
	for _, client := range clients {
		if client != nil {
			_ = client.Close()
		}
	}
}

// upstreamServers chooses the direct upstreams used by the internal DNS client.
//
// Preference order is:
//   - DNS servers already configured on the target resolved link;
//   - resolved's global DNS servers, excluding entries attached to the target
//     link; and
//   - caller-provided fallbacks.
//
// The result is deduplicated and converted into gonnect DNS client URLs. Invalid
// entries are ignored because resolved can expose partially configured or
// family-mismatched D-Bus entries while links are changing.
func (r *Resolved) upstreamServers(
	fallback []netip.AddrPort,
) ([]string, error) {
	return r.upstreamServersFiltered(fallback, netip.Addr{})
}

func (r *Resolved) upstreamServersFiltered(
	fallback []netip.AddrPort,
	exclude netip.Addr,
) ([]string, error) {
	servers, err := r.linkDNSServers()
	if err != nil {
		return nil, err
	}
	servers = filterAddr(servers, []netip.Addr{exclude})
	if len(servers) == 0 {
		servers, err = r.globalDNSServers()
		if err != nil {
			return nil, err
		}
		servers = filterAddr(servers, []netip.Addr{exclude})
	}
	if len(servers) == 0 {
		servers = append([]netip.AddrPort(nil), fallback...)
		servers = filterAddr(servers, []netip.Addr{exclude})
	}
	if len(servers) == 0 {
		return nil, errors.New("resolved: no upstream DNS servers")
	}

	urls := make([]string, 0, len(servers))
	seen := make(map[netip.AddrPort]bool, len(servers))
	for _, server := range servers {
		if !server.IsValid() || seen[server] {
			continue
		}
		seen[server] = true
		urls = append(urls, "udp://"+server.String())
	}
	if len(urls) == 0 {
		return nil, errors.New("resolved: no usable upstream DNS servers")
	}
	return urls, nil
}

// linkDNSServers returns DNS servers configured directly on r.ifidx.
//
// Modern resolved versions expose Link.DNSEx, which preserves custom ports.
// Older versions expose only Link.DNS, so this method falls back to the legacy
// property when DNSEx is missing or cannot be decoded.
func (r *Resolved) linkDNSServers() ([]netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DbusTimeout)
	defer cancel()

	link, err := r.linkObject(ctx)
	if err != nil {
		return nil, err
	}
	var v dbus.Variant
	if err := link.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusLinkInterface,
		"DNSEx",
	).Store(&v); err != nil {
		return r.linkDNSServersLegacy(ctx, link)
	}

	var raw []resolvedLinkNameserverEx
	if err := dbus.Store([]any{v.Value()}, &raw); err != nil {
		return r.linkDNSServersLegacy(ctx, link)
	}

	out := make([]netip.AddrPort, 0, len(raw))
	for _, server := range raw {
		if addr, ok := addrFromResolved(server.Family, server.Address); ok {
			out = append(out, addrPort(addr, server.Port))
		}
	}
	return out, nil
}

func (r *Resolved) linkObject(ctx context.Context) (dbus.BusObject, error) {
	var path dbus.ObjectPath
	if err := r.mgr.CallWithContext(
		ctx,
		dbusResolvedInterface+".GetLink",
		0,
		r.ifidx,
	).Store(&path); err != nil {
		return nil, fmt.Errorf("resolved: GetLink(%d): %w", r.ifidx, err)
	}

	return r.conn.Object(dbusResolvedObject, path), nil
}

func (r *Resolved) linkConfigNeedsApply(
	server netip.Addr,
	linkServers []netip.AddrPort,
) (bool, error) {
	if len(linkServers) != 1 || linkServers[0].Addr() != server {
		return true, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), DbusTimeout)
	defer cancel()

	link, err := r.linkObject(ctx)
	if err != nil {
		return false, err
	}

	var v dbus.Variant
	if err := link.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusLinkInterface,
		"Domains",
	).Store(&v); err != nil {
		return true, nil
	}
	var domains []resolvedLinkDomain
	if err := dbus.Store([]any{v.Value()}, &domains); err != nil {
		return true, nil
	}
	var hasRootRoute bool
	for _, domain := range domains {
		if domain.Domain == "." && domain.RoutingOnly {
			hasRootRoute = true
			break
		}
	}
	if !hasRootRoute {
		return true, nil
	}

	if err := link.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusLinkInterface,
		"DefaultRoute",
	).Store(&v); err != nil {
		return false, nil
	}
	defaultRoute, ok := v.Value().(bool)
	return !ok || !defaultRoute, nil
}

func (r *Resolved) linkDomains() ([]resolvedLinkDomain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DbusTimeout)
	defer cancel()

	link, err := r.linkObject(ctx)
	if err != nil {
		return nil, err
	}

	var v dbus.Variant
	if err := link.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusLinkInterface,
		"Domains",
	).Store(&v); err != nil {
		return nil, fmt.Errorf("resolved: read link domains: %w", err)
	}
	var domains []resolvedLinkDomain
	if err := dbus.Store([]any{v.Value()}, &domains); err != nil {
		return nil, fmt.Errorf("resolved: decode link domains: %w", err)
	}
	return domains, nil
}

// linkDNSServersLegacy reads Link.DNS and assumes the default DNS port.
func (r *Resolved) linkDNSServersLegacy(
	ctx context.Context,
	link dbus.BusObject,
) ([]netip.AddrPort, error) {
	var v dbus.Variant
	if err := link.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusLinkInterface,
		"DNS",
	).Store(&v); err != nil {
		return nil, fmt.Errorf("resolved: read link DNS: %w", err)
	}

	var raw []resolvedLinkNameserver
	if err := dbus.Store([]any{v.Value()}, &raw); err != nil {
		return nil, fmt.Errorf("resolved: decode link DNS: %w", err)
	}

	out := make([]netip.AddrPort, 0, len(raw))
	for _, server := range raw {
		if addr, ok := addrFromResolved(server.Family, server.Address); ok {
			out = append(out, netip.AddrPortFrom(addr, 53))
		}
	}
	return out, nil
}

func (r *Resolved) managerDNSServers() (map[int32][]netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DbusTimeout)
	defer cancel()

	var v dbus.Variant
	if err := r.mgr.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusResolvedInterface,
		"DNSEx",
	).Store(&v); err != nil {
		return r.managerDNSServersLegacy(ctx)
	}

	var raw []resolvedGlobalNameserverEx
	if err := dbus.Store([]any{v.Value()}, &raw); err != nil {
		return r.managerDNSServersLegacy(ctx)
	}

	out := make(map[int32][]netip.AddrPort)
	for _, server := range raw {
		if addr, ok := addrFromResolved(server.Family, server.Address); ok {
			out[server.IfIndex] = append(
				out[server.IfIndex],
				addrPort(addr, server.Port),
			)
		}
	}
	return out, nil
}

func (r *Resolved) managerDNSServersLegacy(
	ctx context.Context,
) (map[int32][]netip.AddrPort, error) {
	var v dbus.Variant
	if err := r.mgr.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusResolvedInterface,
		"DNS",
	).Store(&v); err != nil {
		return nil, fmt.Errorf("resolved: read manager DNS: %w", err)
	}

	var raw []resolvedGlobalNameserver
	if err := dbus.Store([]any{v.Value()}, &raw); err != nil {
		return nil, fmt.Errorf("resolved: decode manager DNS: %w", err)
	}

	out := make(map[int32][]netip.AddrPort)
	for _, server := range raw {
		if addr, ok := addrFromResolved(server.Family, server.Address); ok {
			out[server.IfIndex] = append(
				out[server.IfIndex],
				netip.AddrPortFrom(addr, 53),
			)
		}
	}
	return out, nil
}

func (r *Resolved) managerDomains() (map[int32][]resolvedGlobalDomain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DbusTimeout)
	defer cancel()

	var v dbus.Variant
	if err := r.mgr.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusResolvedInterface,
		"Domains",
	).Store(&v); err != nil {
		return nil, fmt.Errorf("resolved: read manager domains: %w", err)
	}

	var raw []resolvedGlobalDomain
	if err := dbus.Store([]any{v.Value()}, &raw); err != nil {
		return nil, fmt.Errorf("resolved: decode manager domains: %w", err)
	}

	out := make(map[int32][]resolvedGlobalDomain)
	for _, domain := range raw {
		out[domain.IfIndex] = append(out[domain.IfIndex], domain)
	}
	return out, nil
}

// globalDNSServers returns resolved's manager-level DNS servers.
//
// Servers that resolved associates with r.ifidx are skipped. If SetDNS later
// points that link at this provider, forwarding Requests back to the same link
// could create a DNS loop.
func (r *Resolved) globalDNSServers() ([]netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DbusTimeout)
	defer cancel()

	var v dbus.Variant
	if err := r.mgr.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusResolvedInterface,
		"DNSEx",
	).Store(&v); err != nil {
		return r.globalDNSServersLegacy(ctx)
	}

	var raw []resolvedGlobalNameserverEx
	if err := dbus.Store([]any{v.Value()}, &raw); err != nil {
		return r.globalDNSServersLegacy(ctx)
	}

	out := make([]netip.AddrPort, 0, len(raw))
	for _, server := range raw {
		if server.IfIndex == r.ifidx {
			continue
		}
		if addr, ok := addrFromResolved(server.Family, server.Address); ok {
			out = append(out, addrPort(addr, server.Port))
		}
	}
	return out, nil
}

// globalDNSServersLegacy reads Manager.DNS and assumes the default DNS port.
func (r *Resolved) globalDNSServersLegacy(
	ctx context.Context,
) ([]netip.AddrPort, error) {
	var v dbus.Variant
	if err := r.mgr.CallWithContext(
		ctx,
		"org.freedesktop.DBus.Properties.Get",
		0,
		dbusResolvedInterface,
		"DNS",
	).Store(&v); err != nil {
		return nil, fmt.Errorf("resolved: read manager DNS: %w", err)
	}

	var raw []resolvedGlobalNameserver
	if err := dbus.Store([]any{v.Value()}, &raw); err != nil {
		return nil, fmt.Errorf("resolved: decode manager DNS: %w", err)
	}

	out := make([]netip.AddrPort, 0, len(raw))
	for _, server := range raw {
		if server.IfIndex == r.ifidx {
			continue
		}
		if addr, ok := addrFromResolved(server.Family, server.Address); ok {
			out = append(out, netip.AddrPortFrom(addr, 53))
		}
	}
	return out, nil
}

// resolvedNameserver converts a Go IP address into the D-Bus tuple expected by
// resolved's SetLinkDNS method.
func resolvedNameserver(addr netip.Addr) resolvedLinkNameserver {
	if addr.Is4() {
		a := addr.As4()
		return resolvedLinkNameserver{
			Family:  unix.AF_INET,
			Address: a[:],
		}
	}
	a := addr.As16()
	return resolvedLinkNameserver{
		Family:  unix.AF_INET6,
		Address: a[:],
	}
}

// addrFromResolved decodes a resolved D-Bus address tuple.
//
// The family controls the expected byte length. Unknown families and malformed
// byte slices return ok=false so callers can skip unusable entries while still
// accepting the rest of the resolved configuration.
func addrFromResolved(family int32, raw []byte) (netip.Addr, bool) {
	switch family {
	case unix.AF_INET:
		if len(raw) != 4 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(raw)), true
	case unix.AF_INET6:
		if len(raw) != 16 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(raw)), true
	default:
		return netip.Addr{}, false
	}
}

// addrPort applies resolved's default DNS port when DNSEx reports port zero.
func addrPort(addr netip.Addr, port uint16) netip.AddrPort {
	if port == 0 {
		port = 53
	}
	return netip.AddrPortFrom(addr, port)
}

func filterAddr(
	servers []netip.AddrPort,
	exclude []netip.Addr,
) []netip.AddrPort {
	if len(exclude) == 0 {
		return servers
	}
	out := servers[:0]
	for _, server := range servers {
		if !addrExcluded(server.Addr(), exclude) {
			out = append(out, server)
		}
	}
	return out
}

func addrExcluded(addr netip.Addr, exclude []netip.Addr) bool {
	for _, candidate := range exclude {
		if candidate.IsValid() && addr == candidate {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// isDBusUnknownMethod reports whether err is the standard D-Bus error for a
// method that is not implemented by the running resolved version.
func isDBusUnknownMethod(err error) bool {
	var dbusErr dbus.Error
	return errors.As(err, &dbusErr) &&
		dbusErr.Name == dbus.ErrMsgUnknownMethod.Name
}
