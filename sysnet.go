//go:build linux

// Package linux implements gonnect/sysnet.System for Linux.
package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"syscall"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockopt"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/multirule"
	linuxconnmark "github.com/asciimoth/sysnet-linux/connmark"
	"github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/killswitch"
	"github.com/asciimoth/sysnet-linux/routing"
	linuxsubnet "github.com/asciimoth/sysnet-linux/subnet"
	linuxtun "github.com/asciimoth/sysnet-linux/tun"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	defaultTunBaseName = "gonnect"
	defaultUserMark    = 0x4d000001
)

var _ sysnet.System = (*System)(nil)

// FeatureConfig describes features requested by the caller. Effective feature
// support is the requested value degraded by the components supplied in Config.
type FeatureConfig struct {
	Tun             bool
	DefaultTun      bool
	DynTun          bool
	DynDefaultTun   bool
	TunNames        bool
	DefaultTunNames bool
	StrictMode      bool
	TunRules        bool
	MatcherRules    bool
	DNSControl      bool
	Routing         bool
	Pmark           bool
	Killswitch      bool
}

// Callbacks are optional hooks fired after successful lifecycle operations.
// Implementations must be quick; System never requires callbacks to be set.
type Callbacks struct {
	TunCreated           func(tun gtun.Tun)
	TunConfigured        func(tun gtun.Tun, opts sysnet.TunOpts)
	DefaultTunCreated    func(tun sysnet.DefaultTun)
	DefaultTunConfigured func(tun sysnet.DefaultTun, opts sysnet.DefaultTunOpts)
	DefaultTunClosed     func()
	RoutingApplied       func(config routing.Config)
	DNSConfigured        func(server netip.Addr)
	KillswitchUpdated    func(rules killswitch.AllowRules)
}

// RoutingManager is the routing.Manager surface used by System.
type RoutingManager interface {
	Apply(routing.Config) error
	Refresh() error
	Rollback(routing.Config) error
	Status() (routing.DesiredState, bool)
	Close() error
}

// ConnmarkManager is the nftables conntrack-mark surface used by System.
type ConnmarkManager interface {
	Apply(linuxconnmark.Config) error
	Rollback() error
	Close() error
}

// PmarkController is the p-mark daemon surface used by System.
type PmarkController interface {
	SetChecker(pmark.CheckFunc) (uint64, error)
	ForceProcessTraversal() error
}

// pmarkKernelPolicyController is implemented by p-mark versions that can apply
// exact comm rules synchronously in the exec tracepoint. Keep this extension
// separate from PmarkController so older custom controllers continue to work.
type pmarkKernelPolicyController interface {
	SetKernelPolicy(pmark.KernelPolicy, pmark.CheckFunc) (uint64, error)
}

// KillswitchClient is the killswitch temporary-ruleset surface used by System.
type KillswitchClient interface {
	CreateTMPRuleset(killswitch.AllowRules) (uint64, error)
	UpdateTMPRuleset(uint64, killswitch.AllowRules) error
	DeleteTMPRuleset(uint64) error
	Close() error
}

// TUNFactory creates a native TUN device.
type TUNFactory interface {
	CreateTUN(baseName string, mtu int) (gtun.Tun, error)
}

type tunFactoryFunc func(baseName string, mtu int) (gtun.Tun, error)

func (f tunFactoryFunc) CreateTUN(baseName string, mtu int) (gtun.Tun, error) {
	return f(baseName, mtu)
}

// TunConfigurator applies and reads mutable TUN state.
type TunConfigurator interface {
	SetTunMTU(gtun.Tun, int) error
	SetTunAddrs(gtun.Tun, []string) error
	AddTunAddr(gtun.Tun, string) error
	GetTunAddrs(gtun.Tun) ([]string, error)
	SetTunRoutes(gtun.Tun, []string) error
	AddTunRoute(gtun.Tun, string) error
	GetTunRotue(gtun.Tun) ([]string, error)
	SetTunName(gtun.Tun, string) ([]string, error)
}

type systemTunConfigurator struct{}

func (systemTunConfigurator) SetTunMTU(t gtun.Tun, mtu int) error {
	if err := linuxtun.SetTunMTU(t, mtu); err != nil {
		return err
	}
	return setNativeTunUp(t)
}
func (systemTunConfigurator) SetTunAddrs(t gtun.Tun, addrs []string) error {
	return linuxtun.SetTunAddrs(t, addrs)
}
func (systemTunConfigurator) AddTunAddr(t gtun.Tun, addr string) error {
	return linuxtun.AddTunAddr(t, addr)
}
func (systemTunConfigurator) GetTunAddrs(t gtun.Tun) ([]string, error) {
	return linuxtun.GetTunAddrs(t)
}
func (systemTunConfigurator) SetTunRoutes(t gtun.Tun, routes []string) error {
	return linuxtun.SetTunRoutes(t, routes)
}
func (systemTunConfigurator) AddTunRoute(t gtun.Tun, route string) error {
	return linuxtun.AddTunRoute(t, route)
}
func (systemTunConfigurator) GetTunRotue(t gtun.Tun) ([]string, error) {
	return linuxtun.GetTunRotue(t)
}

func (systemTunConfigurator) SetTunName(
	t gtun.Tun,
	name string,
) ([]string, error) {
	return linuxtun.SetTunName(t, name)
}

// PacketListenFunc opens the UDP socket backing the DefaultTun DNS server.
type PacketListenFunc func(ctx context.Context, network, address string) (net.PacketConn, error)

// TUNIndexFunc returns the kernel interface index for a TUN.
type TUNIndexFunc func(gtun.Tun) (int, error)

// Config supplies System dependencies. Privileged integrations are injected so
// tests and embedders can choose exactly which Linux components System owns.
type Config struct {
	Features  FeatureConfig
	Allocator *linuxsubnet.CombinedAllocator

	DNSProvider dns.DNSProvider

	// HostsFile is the local hosts database read before DNSProvider. System
	// reads it for each lookup. An empty value uses /etc/hosts.
	HostsFile string

	RoutingManager RoutingManager
	Connmark       ConnmarkManager
	Pmark          PmarkController
	Killswitch     KillswitchClient
	TUNFactory     TUNFactory
	TunConfig      TunConfigurator

	RuleTracker *multirule.Tracker
	OwnerLookup func(sockowner.FlowTuple) (*sockowner.SocketOwner, error)

	PacketListen PacketListenFunc
	TUNIndex     TUNIndexFunc

	AppBypassMark uint32
	AppBypassMask uint32
	UserMark      uint32
	UserMarkMask  uint32
	PmarkPriority int

	DefaultTunBaseName string

	KillswitchAllowExclude bool
	Logf                   func(format string, args ...any)
	Callbacks              Callbacks

	// ExtraClosers are resources owned by System in addition to the standard
	// injected components. They are closed by System.Close after DNS, routing,
	// and killswitch state has been released.
	ExtraClosers []io.Closer
}

// System composes the Linux DNS, TUN, routing, p-mark, and killswitch helpers.
type System struct {
	mu           sync.Mutex
	defaultTunMu sync.Mutex
	closed       bool

	features FeatureConfig

	allocator       *linuxsubnet.CombinedAllocator
	defaultTunIP    net.IP
	defaultTunCIDR  string
	defaultTunDNSIP netip.Addr

	baseName string

	outNet   gonnect.Network
	localNet gonnect.Network
	outDNS   gdns.Interface

	dnsProvider    dns.DNSProvider
	routingManager RoutingManager
	connmark       ConnmarkManager
	pmark          PmarkController
	killswitch     KillswitchClient
	tunFactory     TUNFactory
	tunConfig      TunConfigurator
	ruleTracker    *multirule.Tracker
	ownerLookup    func(sockowner.FlowTuple) (*sockowner.SocketOwner, error)
	packetListen   PacketListenFunc
	tunIndex       TUNIndexFunc

	appBypassMark uint32
	appBypassMask uint32
	userMark      uint32
	userMarkMask  uint32
	pmarkPriority int

	connmarkRequired       bool
	killswitchAllowExclude bool
	logf                   func(format string, args ...any)
	callbacks              Callbacks
	extraClosers           []io.Closer

	tuns       map[gtun.Tun]*tunState
	defaultTun *defaultTunState

	defaultTunSourceGeneration uint64
}

type tunState struct {
	tun gtun.Tun
}

// NewSystem creates a Linux System from supplied components.
func NewSystem(config Config) (*System, error) {
	logf := config.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	allocator := config.Allocator
	if allocator == nil {
		allocator = linuxsubnet.NewDefaultAllocator(
			subnet.DefaultAllocatorConfig{},
		)
	}
	appMark := config.AppBypassMark
	if appMark == 0 {
		appMark = routing.DefaultAppBypassMark
	}
	appMask := config.AppBypassMask
	if appMask == 0 {
		appMask = routing.DefaultMarkMask
	}
	userMark := config.UserMark
	if userMark == 0 {
		userMark = defaultUserMark
	}
	userMask := config.UserMarkMask
	if userMask == 0 {
		userMask = routing.DefaultMarkMask
	}
	validate := routing.DefaultConfig()
	validate.TUNIndex = 1
	validate.AppBypassMark = appMark
	validate.AppBypassMask = appMask
	validate.UserMark = userMark
	validate.UserMarkMask = userMask
	if err := routing.ValidateConfig(validate); err != nil {
		return nil, err
	}
	factory := config.TUNFactory
	if factory == nil {
		factory = tunFactoryFunc(linuxtun.CreateDefaultTUN)
	}
	tunConfig := config.TunConfig
	if tunConfig == nil {
		tunConfig = systemTunConfigurator{}
	}
	tracker := config.RuleTracker
	if tracker == nil &&
		(config.Features.MatcherRules ||
			(config.Features.TunRules && config.Features.Pmark)) {
		tracker = multirule.New()
	}
	ownerLookup := config.OwnerLookup
	if ownerLookup == nil {
		ownerLookup = sockowner.GetSockOwner
	}
	packetListen := config.PacketListen
	if packetListen == nil {
		packetListen = func(ctx context.Context, network, address string) (net.PacketConn, error) {
			var lc net.ListenConfig
			return lc.ListenPacket(ctx, network, address)
		}
	}
	tunIndex := config.TUNIndex
	if tunIndex == nil {
		tunIndex = nativeTunIndex
	}
	connmarkManager := config.Connmark
	connmarkRequired := connmarkManager != nil
	if connmarkManager == nil && config.Features.DefaultTun &&
		config.Features.Routing {
		connmarkManager = linuxconnmark.NewManager()
	}

	s := &System{
		features:               config.Features,
		allocator:              allocator,
		dnsProvider:            config.DNSProvider,
		routingManager:         config.RoutingManager,
		connmark:               connmarkManager,
		pmark:                  config.Pmark,
		killswitch:             config.Killswitch,
		tunFactory:             factory,
		tunConfig:              tunConfig,
		ruleTracker:            tracker,
		ownerLookup:            ownerLookup,
		packetListen:           packetListen,
		tunIndex:               tunIndex,
		appBypassMark:          appMark,
		appBypassMask:          appMask,
		userMark:               userMark,
		userMarkMask:           userMask,
		pmarkPriority:          config.PmarkPriority,
		connmarkRequired:       connmarkRequired,
		killswitchAllowExclude: config.KillswitchAllowExclude,
		logf:                   logf,
		callbacks:              config.Callbacks,
		baseName:               config.DefaultTunBaseName,
		extraClosers: append(
			[]io.Closer(nil),
			config.ExtraClosers...),
		tuns: make(map[gtun.Tun]*tunState),
	}
	s.reserveDefaultTunIP()
	s.outNet = s.buildMarkedNetwork()
	s.localNet = s.buildMarkedNetwork()
	if config.DNSProvider != nil {
		s.outDNS = config.DNSProvider
		resolver := newLocalThenDNSResolver(
			config.HostsFile,
			gdns.NewResolver(config.DNSProvider),
		)
		s.outNet = gonnect.NewNetworkWithResolver(s.outNet, resolver)
		s.localNet = gonnect.NewNetworkWithResolver(s.localNet, resolver)
	}
	return s, nil
}

func (s *System) reserveDefaultTunIP() {
	ip, network := s.allocator.AllocIP4()
	if ip == nil || network == nil {
		ip, network = s.allocator.AllocIP6()
	}
	if ip == nil || network == nil {
		return
	}
	s.defaultTunIP = append(net.IP(nil), ip...)
	s.defaultTunCIDR = (&net.IPNet{IP: ip, Mask: network.Mask}).String()
	if addr, ok := netip.AddrFromSlice(ip); ok {
		s.defaultTunDNSIP = addr.Unmap()
	}
}

func (s *System) buildMarkedNetwork() gonnect.Network {
	setRoutingMark := func(network, address string, c syscall.RawConn) {
		if err := sockopt.SetRoutingMark(c, s.appBypassMark); err != nil {
			s.logf("set SO_MARK on %s %s: %v", network, address, err)
		}
	}
	return gonnect.NativeConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			setRoutingMark(network, address, c)
			return nil
		},
		ControlContext: func(_ context.Context, network, address string, c syscall.RawConn) error {
			setRoutingMark(network, address, c)
			return nil
		},
		ListenCfg: &net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				setRoutingMark(network, address, c)
				return nil
			},
		},
	}.Build()
}

// Close releases every object owned by System.
func (s *System) Close() error {
	s.defaultTunMu.Lock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.defaultTunMu.Unlock()
		return nil
	}
	s.closed = true
	defaultTun := s.defaultTun
	s.defaultTun = nil
	tuns := make([]gtun.Tun, 0, len(s.tuns))
	for tun := range s.tuns {
		tuns = append(tuns, tun)
	}
	s.tuns = make(map[gtun.Tun]*tunState)
	s.mu.Unlock()

	var err error
	if defaultTun != nil {
		err = errors.Join(err, defaultTun.closeActive())
	}
	for _, tun := range tuns {
		err = errors.Join(err, tun.Close())
	}
	s.defaultTunMu.Unlock()
	if s.dnsProvider != nil {
		err = errors.Join(err, s.dnsProvider.Close())
	}
	if s.routingManager != nil {
		err = errors.Join(err, s.routingManager.Close())
	}
	if s.connmark != nil {
		err = errors.Join(err, s.connmark.Close())
	}
	if s.killswitch != nil {
		err = errors.Join(err, s.killswitch.Close())
	}
	for i := len(s.extraClosers) - 1; i >= 0; i-- {
		if s.extraClosers[i] != nil {
			err = errors.Join(err, s.extraClosers[i].Close())
		}
	}
	return err
}

// Features returns effective support after degrading requested features by
// supplied component availability.
func (s *System) Features() sysnet.Features {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.featuresLocked()
}

func (s *System) featuresLocked() sysnet.Features {
	tunOK := s.features.Tun && s.tunFactory != nil && s.tunConfig != nil
	routingOK := s.features.Routing && s.routingManager != nil
	dnsOK := s.features.DNSControl && s.dnsProvider != nil &&
		s.packetListen != nil
	defaultOK := s.features.DefaultTun && tunOK && routingOK && dnsOK
	return sysnet.Features{
		Tun:                    tunOK,
		DefaultTun:             defaultOK,
		DynTun:                 s.features.DynTun && tunOK,
		DynDefaultTun:          s.features.DynDefaultTun && defaultOK,
		TunNames:               s.features.TunNames && tunOK,
		DefaultTunNames:        false,
		StrictMode:             s.features.StrictMode && routingOK,
		DefaultTunSourceRoutes: defaultOK,
	}
}

// AllocIP returns the shared IP allocator.
func (s *System) AllocIP() subnet.IPAllocator { return s.allocator }

// AllocSubnet returns the shared subnet allocator.
func (s *System) AllocSubnet() subnet.SubnetAllocator { return s.allocator }

// OutDNS returns the DNS interface used by OutNet resolution.
func (s *System) OutDNS() gdns.Interface { return s.outDNS }

// OutNet returns app-marked outbound network.
func (s *System) OutNet() gonnect.Network {
	if s.outNet == nil {
		return &gonnect.RejectNetwork{}
	}
	return s.outNet
}

// LocalNet returns app-marked local network.
func (s *System) LocalNet() gonnect.Network {
	if s.localNet == nil {
		return &gonnect.RejectNetwork{}
	}
	return s.localNet
}

// TunNameVerify checks Linux interface name syntax and availability.
func (s *System) TunNameVerify(name string) (bool, bool) {
	if name == "" || len(name) >= unix.IFNAMSIZ || name == "." || name == ".." {
		return false, false
	}
	for _, r := range name {
		if r == '/' || r == ':' || r == 0 || r > 127 {
			return false, false
		}
	}
	_, err := net.InterfaceByName(name)
	if err == nil {
		return true, false
	}
	return true, true
}

// VerifyTunOpts validates regular TUN options.
func (s *System) VerifyTunOpts(opts sysnet.TunOpts) error {
	if !s.Features().Tun {
		return sysnet.ErrNotSupported
	}
	_, _, err := normalizeTunAddrs(opts.TunAddrs, "", "")
	if err != nil {
		return err
	}
	if _, err := normalizeTunRoutes(opts.TunRoutes); err != nil {
		return err
	}
	return nil
}

// BuildTun creates and configures a regular TUN.
func (s *System) BuildTun(opts sysnet.TunOpts) (gtun.Tun, error) {
	if err := s.VerifyTunOpts(opts); err != nil {
		return nil, err
	}
	mtu := linuxtun.NormalizeMTU(opts.MTU)
	t, err := s.tunFactory.CreateTUN(s.defaultTunBaseName(), mtu)
	if err != nil {
		return nil, err
	}
	addrs, _, err := normalizeTunAddrs(opts.TunAddrs, "", "")
	if err != nil {
		_ = t.Close()
		return nil, err
	}
	routes, err := normalizeTunRoutes(opts.TunRoutes)
	if err != nil {
		_ = t.Close()
		return nil, err
	}
	if err := s.tunConfig.SetTunMTU(t, opts.MTU); err != nil {
		_ = t.Close()
		return nil, err
	}
	if err := s.tunConfig.SetTunAddrs(t, addrs); err != nil {
		_ = t.Close()
		return nil, err
	}
	if err := s.tunConfig.SetTunRoutes(t, routes); err != nil {
		_ = t.Close()
		return nil, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = t.Close()
		return nil, net.ErrClosed
	}
	s.tuns[t] = &tunState{tun: t}
	s.mu.Unlock()
	if s.callbacks.TunCreated != nil {
		s.callbacks.TunCreated(t)
	}
	if s.callbacks.TunConfigured != nil {
		s.callbacks.TunConfigured(t, copyTunOpts(opts))
	}
	return t, nil
}

func copyTunOpts(opts sysnet.TunOpts) sysnet.TunOpts {
	return sysnet.TunOpts{
		TunAddrs:  append([]string(nil), opts.TunAddrs...),
		TunRoutes: append([]string(nil), opts.TunRoutes...),
		MTU:       opts.MTU,
	}
}

func (s *System) defaultTunBaseName() string {
	if s.baseName != "" {
		return s.baseName
	}
	return defaultTunBaseName
}

func (s *System) ownedRegularTun(t gtun.Tun) bool {
	if t == nil {
		return false
	}
	typeOfTun := reflect.TypeOf(t)
	if typeOfTun == nil || !typeOfTun.Comparable() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tuns[t]
	return ok
}

type resolvedTun struct {
	tun       gtun.Tun
	state     *defaultTunState
	isDefault bool
}

// resolveTunLocked resolves a public TUN handle to the native object that the
// configurator must use. The caller must hold defaultTunMu. The returned
// release function keeps ownership and default-TUN replacement stable for the
// complete operation.
func (s *System) resolveTunLocked(
	t gtun.Tun,
) (resolvedTun, func(), error) {
	if t == nil {
		return resolvedTun{}, nil, sysnet.ErrUnknownTun
	}

	s.mu.Lock()
	if d, ok := t.(*defaultTun); ok {
		if d == nil || d.defaultTunState == nil ||
			d.system != s || s.closed || s.defaultTun != d.defaultTunState {
			s.mu.Unlock()
			return resolvedTun{}, nil, sysnet.ErrUnknownTun
		}
		d.mu.Lock()
		if d.tun == nil {
			d.mu.Unlock()
			s.mu.Unlock()
			return resolvedTun{}, nil, sysnet.ErrUnknownTun
		}
		resolved := resolvedTun{
			tun:       d.tun,
			state:     d.defaultTunState,
			isDefault: true,
		}
		s.mu.Unlock()
		return resolved, d.mu.Unlock, nil
	}

	typeOfTun := reflect.TypeOf(t)
	if typeOfTun == nil || !typeOfTun.Comparable() {
		s.mu.Unlock()
		return resolvedTun{}, nil, sysnet.ErrUnknownTun
	}
	if _, ok := s.tuns[t]; !ok {
		s.mu.Unlock()
		return resolvedTun{}, nil, sysnet.ErrUnknownTun
	}
	s.mu.Unlock()
	return resolvedTun{tun: t}, func() {}, nil
}

// TunWarnings returns read-only runtime warnings for a regular TUN created by
// this System. sysnet-linux does not currently report regular TUN warnings.
func (s *System) TunWarnings(t gtun.Tun) []sysnet.Warning {
	if !s.ownedRegularTun(t) {
		return nil
	}
	return nil
}

func (s *System) SetTunMTU(t gtun.Tun, mtu int) error {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	resolved, release, err := s.resolveTunLocked(t)
	if err != nil {
		return err
	}
	defer release()
	if !resolved.isDefault {
		return s.tunConfig.SetTunMTU(resolved.tun, mtu)
	}
	oldMTU, err := resolved.tun.MTU()
	if err != nil {
		return err
	}
	if err := s.tunConfig.SetTunMTU(resolved.tun, mtu); err != nil {
		return errors.Join(err, s.tunConfig.SetTunMTU(resolved.tun, oldMTU))
	}
	return nil
}

func (s *System) SetTunAddrs(t gtun.Tun, addrs []string) error {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	resolved, release, err := s.resolveTunLocked(t)
	if err != nil {
		return err
	}
	defer release()
	if resolved.isDefault {
		return s.setDefaultTunAddrsLocked(resolved, addrs)
	}
	normalized, _, err := normalizeTunAddrs(addrs, "", "")
	if err != nil {
		return err
	}
	return s.tunConfig.SetTunAddrs(resolved.tun, normalized)
}

func (s *System) AddTunAddr(t gtun.Tun, addr string) error {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	resolved, release, err := s.resolveTunLocked(t)
	if err != nil {
		return err
	}
	defer release()
	normalized, _, err := normalizeTunAddrs([]string{addr}, "", "")
	if err != nil {
		return err
	}
	if len(normalized) == 0 {
		return nil
	}
	if resolved.isDefault {
		return s.addDefaultTunAddrLocked(resolved, normalized[0])
	}
	return s.tunConfig.AddTunAddr(resolved.tun, normalized[0])
}

func (s *System) GetTunAddrs(t gtun.Tun) ([]string, error) {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	resolved, release, err := s.resolveTunLocked(t)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.tunConfig.GetTunAddrs(resolved.tun)
}

func (s *System) SetTunRoutes(t gtun.Tun, routes []string) error {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	resolved, release, err := s.resolveTunLocked(t)
	if err != nil {
		return err
	}
	defer release()
	normalized, err := normalizeTunRoutes(routes)
	if err != nil {
		return err
	}
	if resolved.isDefault {
		return s.setDefaultTunRoutesLocked(resolved, normalized)
	}
	return s.tunConfig.SetTunRoutes(resolved.tun, normalized)
}

func (s *System) AddTunRoute(t gtun.Tun, route string) error {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	resolved, release, err := s.resolveTunLocked(t)
	if err != nil {
		return err
	}
	defer release()
	normalized, err := normalizeTunRoutes([]string{route})
	if err != nil {
		return err
	}
	if len(normalized) == 0 {
		return nil
	}
	if resolved.isDefault {
		routes := append([]string(nil), resolved.state.routes...)
		routes = append(routes, normalized[0])
		routes, err = normalizeTunRoutes(routes)
		if err != nil {
			return err
		}
		return s.setDefaultTunRoutesLocked(resolved, routes)
	}
	return s.tunConfig.AddTunRoute(resolved.tun, normalized[0])
}

func (s *System) GetTunRotue(t gtun.Tun) ([]string, error) {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	resolved, release, err := s.resolveTunLocked(t)
	if err != nil {
		return nil, err
	}
	defer release()
	if resolved.isDefault {
		return append([]string(nil), resolved.state.routes...), nil
	}
	return s.tunConfig.GetTunRotue(resolved.tun)
}

func (s *System) setDefaultTunAddrsLocked(
	resolved resolvedTun,
	addrs []string,
) error {
	normalized, dnsIP, err := normalizeTunAddrs(
		addrs,
		s.defaultTunCIDR,
		resolved.state.dnsIP.String(),
	)
	if err != nil {
		return err
	}
	if dnsIP != resolved.state.dnsIP {
		return fmt.Errorf(
			"default tun address update would change the DNS address: %w",
			sysnet.ErrNotSupported,
		)
	}
	return s.updateDefaultTunAddrsLocked(resolved, normalized, "")
}

func (s *System) addDefaultTunAddrLocked(
	resolved resolvedTun,
	addr string,
) error {
	if slices.Contains(resolved.state.addrs, addr) {
		return nil
	}
	addrs := append([]string(nil), resolved.state.addrs...)
	addrs = append(addrs, addr)
	normalized, dnsIP, err := normalizeTunAddrs(
		addrs,
		s.defaultTunCIDR,
		resolved.state.dnsIP.String(),
	)
	if err != nil {
		return err
	}
	if dnsIP != resolved.state.dnsIP {
		return fmt.Errorf(
			"default tun address update would change the DNS address: %w",
			sysnet.ErrNotSupported,
		)
	}
	return s.updateDefaultTunAddrsLocked(resolved, normalized, addr)
}

func (s *System) updateDefaultTunAddrsLocked(
	resolved resolvedTun,
	addrs []string,
	addedAddr string,
) error {
	state := resolved.state
	if state.routingConfig == nil {
		return sysnet.ErrUnknownTun
	}
	if err := validateDefaultTunSourceAddrs(
		addrs,
		state.routingConfig.SourceRoutes,
	); err != nil {
		return err
	}

	oldAddrs, err := s.tunConfig.GetTunAddrs(resolved.tun)
	if err != nil {
		return err
	}
	oldMainRoutes, err := s.tunConfig.GetTunRotue(resolved.tun)
	if err != nil {
		return err
	}
	oldRC := cloneDefaultTunRoutingConfig(*state.routingConfig)
	newRC := cloneDefaultTunRoutingConfig(oldRC)
	newRC.Families = routeFamilies(addrs, state.routes)

	if addedAddr == "" {
		err = s.tunConfig.SetTunAddrs(resolved.tun, addrs)
	} else {
		err = s.tunConfig.AddTunAddr(resolved.tun, addedAddr)
	}
	if err != nil {
		return errors.Join(
			err,
			s.restoreDefaultTunLinkLocked(
				resolved.tun,
				oldAddrs,
				oldMainRoutes,
			),
		)
	}
	if err := s.tunConfig.SetTunRoutes(resolved.tun, nil); err != nil {
		return errors.Join(
			err,
			s.restoreDefaultTunLinkLocked(
				resolved.tun,
				oldAddrs,
				oldMainRoutes,
			),
		)
	}
	if err := s.routingManager.Apply(newRC); err != nil {
		return errors.Join(
			err,
			s.restoreDefaultTunLinkLocked(
				resolved.tun,
				oldAddrs,
				oldMainRoutes,
			),
			s.restoreDefaultTunRoutingLocked(oldRC, newRC),
		)
	}

	state.addrs = append([]string(nil), addrs...)
	state.routingConfig = &newRC
	return nil
}

func (s *System) setDefaultTunRoutesLocked(
	resolved resolvedTun,
	routes []string,
) error {
	state := resolved.state
	if state.routingConfig == nil {
		return sysnet.ErrUnknownTun
	}
	oldMainRoutes, err := s.tunConfig.GetTunRotue(resolved.tun)
	if err != nil {
		return err
	}
	oldRC := cloneDefaultTunRoutingConfig(*state.routingConfig)
	newRC := cloneDefaultTunRoutingConfig(oldRC)
	newRC.Families = routeFamilies(state.addrs, routes)

	if err := s.tunConfig.SetTunRoutes(resolved.tun, nil); err != nil {
		return errors.Join(
			err,
			s.tunConfig.SetTunRoutes(resolved.tun, oldMainRoutes),
		)
	}
	if err := s.routingManager.Apply(newRC); err != nil {
		return errors.Join(
			err,
			s.tunConfig.SetTunRoutes(resolved.tun, oldMainRoutes),
			s.restoreDefaultTunRoutingLocked(oldRC, newRC),
		)
	}

	state.routes = append([]string(nil), routes...)
	state.routingConfig = &newRC
	return nil
}

func (s *System) restoreDefaultTunLinkLocked(
	t gtun.Tun,
	addrs, routes []string,
) error {
	return errors.Join(
		s.tunConfig.SetTunAddrs(t, addrs),
		s.tunConfig.SetTunRoutes(t, routes),
	)
}

func (s *System) restoreDefaultTunRoutingLocked(
	oldRC, failedRC routing.Config,
) error {
	return errors.Join(
		s.routingManager.Rollback(failedRC),
		s.routingManager.Apply(oldRC),
	)
}

func validateDefaultTunSourceAddrs(
	addrs []string,
	sourceRoutes []routing.SourceRoute,
) error {
	assigned := make(map[netip.Addr]struct{}, len(addrs))
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return err
		}
		assigned[prefix.Addr()] = struct{}{}
	}
	for _, route := range sourceRoutes {
		if _, ok := assigned[route.Source]; !ok {
			return fmt.Errorf(
				"default tun address update removes source route address %s",
				route.Source,
			)
		}
	}
	return nil
}

func cloneDefaultTunRoutingConfig(config routing.Config) routing.Config {
	cloned := config
	if config.SourceRoutes != nil {
		cloned.SourceRoutes = append(
			[]routing.SourceRoute(nil),
			config.SourceRoutes...,
		)
	}
	return cloned
}

func (s *System) SetTunName(t gtun.Tun, name string) ([]string, error) {
	if !s.ownedRegularTun(t) {
		return nil, sysnet.ErrUnknownTun
	}
	return s.tunConfig.SetTunName(t, name)
}

func nativeTunIndex(t gtun.Tun) (int, error) {
	if t == nil || t.File() == nil {
		return 0, sysnet.ErrUnknownTun
	}
	ifr, err := unix.NewIfreq("")
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(
		int(t.File().Fd()),
		unix.TUNGETIFF,
		ifr,
	); err != nil {
		return 0, err
	}
	link, err := netlink.LinkByName(ifr.Name())
	if err != nil {
		return 0, err
	}
	return link.Attrs().Index, nil
}

func setNativeTunUp(t gtun.Tun) error {
	index, err := nativeTunIndex(t)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func normalizeTunAddrs(
	addrs []string,
	fallbackCIDR, dnsIP string,
) ([]string, netip.Addr, error) {
	var fallbackPrefix netip.Prefix
	if fallbackCIDR != "" {
		var err error
		fallbackPrefix, err = netip.ParsePrefix(fallbackCIDR)
		if err != nil {
			return nil, netip.Addr{}, err
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(addrs)+1)
	containsDNS := false
	containsFallbackAddr := false
	dnsAddr, _ := netip.ParseAddr(dnsIP)
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		if prefix.Addr().IsLoopback() {
			continue
		}
		cidr := prefix.String()
		if !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
		if dnsAddr.IsValid() && prefix.Contains(dnsAddr) {
			containsDNS = true
		}
		if fallbackPrefix.IsValid() && prefix.Addr() == fallbackPrefix.Addr() {
			containsFallbackAddr = true
		}
	}
	if fallbackPrefix.IsValid() && !containsFallbackAddr {
		cidr := fallbackPrefix.String()
		if !seen[cidr] {
			out = append(out, cidr)
		}
		if dnsAddr.IsValid() && fallbackPrefix.Contains(dnsAddr) {
			containsDNS = true
		}
	}
	if dnsAddr.IsValid() && containsDNS {
		return out, dnsAddr, nil
	}
	if fallbackPrefix.IsValid() {
		return out, fallbackPrefix.Addr(), nil
	}
	return out, netip.Addr{}, nil
}

func normalizeTunRoutes(routes []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return nil, err
		}
		if prefix.Addr().IsLoopback() {
			continue
		}
		cidr := prefix.String()
		if !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	return out, nil
}

func normalizeTunSourceRoutes(
	tunAddrs []string,
	routes []sysnet.TunSourceRoute,
) ([]routing.SourceRoute, error) {
	if routes == nil {
		return nil, nil
	}

	assigned := make(map[netip.Addr]struct{}, len(tunAddrs))
	for _, tunAddr := range tunAddrs {
		prefix, err := netip.ParsePrefix(tunAddr)
		if err != nil {
			return nil, err
		}
		assigned[prefix.Addr()] = struct{}{}
	}

	normalized := make([]routing.SourceRoute, 0, len(routes))
	seen := make(map[netip.Prefix]netip.Addr, len(routes))
	for i, route := range routes {
		if !route.Destination.IsValid() ||
			route.Destination.Addr().Is4In6() {
			return nil, fmt.Errorf(
				"source route %d has an invalid destination prefix",
				i,
			)
		}
		if !validTunSourceRouteAddr(route.Source) {
			return nil, fmt.Errorf(
				"source route %d has an invalid source address",
				i,
			)
		}
		if route.Destination.Addr().Is4() != route.Source.Is4() {
			return nil, fmt.Errorf(
				"source route %d uses different address families",
				i,
			)
		}
		if _, ok := assigned[route.Source]; !ok {
			return nil, fmt.Errorf(
				"source route %d source %s is not assigned to the TUN",
				i,
				route.Source,
			)
		}

		destination := route.Destination.Masked()
		if source, ok := seen[destination]; ok {
			if source != route.Source {
				return nil, fmt.Errorf(
					"source route destination %s has conflicting sources",
					destination,
				)
			}
			continue
		}
		seen[destination] = route.Source
		normalized = append(normalized, routing.SourceRoute{
			Destination: destination,
			Source:      route.Source,
		})
	}

	return normalized, nil
}

func validTunSourceRouteAddr(addr netip.Addr) bool {
	return addr.IsValid() &&
		!addr.Is4In6() &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast() &&
		!addr.IsLoopback() &&
		addr.Zone() == "" &&
		(addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast())
}

func routeFamilies(addrs, routes []string) routing.FamilySet {
	var f routing.FamilySet
	for _, value := range append(append([]string{}, addrs...), routes...) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		if prefix.Addr().Is4() {
			f.IPv4 = true
		} else if prefix.Addr().Is6() {
			f.IPv6 = true
		}
	}
	if !f.IPv4 && !f.IPv6 {
		return routing.BothFamilies
	}
	return f
}

func hexMark(mark uint32) string {
	return fmt.Sprintf("0x%x", mark)
}
