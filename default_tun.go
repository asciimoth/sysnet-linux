//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/fwmark"
	linuxconnmark "github.com/asciimoth/sysnet-linux/connmark"
	linuxdns "github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/killswitch"
	"github.com/asciimoth/sysnet-linux/routing"
	gtunconfig "github.com/asciimoth/sysnet-linux/tun"
)

type defaultTunState struct {
	mu sync.Mutex

	system           *System
	public           *defaultTun
	tun              gtun.Tun
	server           *gdns.Server
	dnsIP            netip.Addr
	generation       uint64
	sourceGeneration uint64
	addrs            []string
	routes           []string

	routingConfig *routing.Config
	ruleIDs       []uint64
	killswitchID  uint64
	pmarkChecker  bool
	dnsIfidxSet   bool
	connmarkSet   bool
}

type defaultTun struct {
	*defaultTunState
}

var _ sysnet.DefaultTun = (*defaultTun)(nil)

// DefaultTunSource is the Linux default-TUN extension that identifies the
// current native packet source. BuildDefaultTun returns an object that
// implements this interface.
//
// The public object is stable while one default TUN is active. Its source
// generation changes only when the native TUN is replaced. An I/O call that
// was already using the old source can return an error that matches
// os.ErrClosed. A caller can compare SourceGeneration before it retries.
type DefaultTunSource interface {
	sysnet.DefaultTun
	SourceGeneration() uint64
}

var _ DefaultTunSource = (*defaultTun)(nil)

type dnsInterfaceIndexer interface {
	SetInterfaceIndex(int) error
}

// VerifyDefaultTunOpts validates DefaultTun options without mutating host state.
func (s *System) VerifyDefaultTunOpts(opts sysnet.DefaultTunOpts) error {
	features := s.Features()
	if !features.DefaultTun {
		return sysnet.ErrNotSupported
	}
	if len(opts.SourceRoutes) > 0 && !features.DefaultTunSourceRoutes {
		return sysnet.ErrNotSupported
	}
	if len(opts.Exclude) > 0 && len(opts.Include) > 0 {
		return errors.New(
			"default tun exclude and include rules are mutually exclusive",
		)
	}
	if opts.Strict && !s.Features().StrictMode {
		return sysnet.ErrNotSupported
	}
	if len(opts.Exclude) > 0 || len(opts.Include) > 0 {
		s.mu.Lock()
		tunRulesSupported := s.tunRulesSupportedLocked()
		s.mu.Unlock()
		if !tunRulesSupported {
			return sysnet.ErrNotSupported
		}
	}
	for _, rule := range append(append([]sysnet.Rule{}, opts.Exclude...), opts.Include...) {
		if _, err := compileRule(rule); err != nil {
			return err
		}
	}
	addrs, _, err := normalizeTunAddrs(
		opts.TunAddrs,
		s.defaultTunCIDR,
		opts.DnsIP,
	)
	if err != nil {
		return err
	}
	if _, err := normalizeTunSourceRoutes(
		addrs,
		opts.SourceRoutes,
	); err != nil {
		return err
	}
	_, err = normalizeTunRoutes(opts.TunRoutes)
	return err
}

// BuildDefaultTun creates or rebuilds the single active DefaultTun.
func (s *System) BuildDefaultTun(
	opts sysnet.DefaultTunOpts,
) (sysnet.DefaultTun, error) {
	if err := s.VerifyDefaultTunOpts(opts); err != nil {
		return nil, err
	}
	addrs, dnsIP, err := normalizeTunAddrs(
		opts.TunAddrs,
		s.defaultTunCIDR,
		opts.DnsIP,
	)
	if err != nil {
		return nil, err
	}
	if !dnsIP.IsValid() {
		return nil, errors.New("default tun DNS IP is unavailable")
	}
	routes, err := normalizeTunRoutes(opts.TunRoutes)
	if err != nil {
		return nil, err
	}
	sourceRoutes, err := normalizeTunSourceRoutes(addrs, opts.SourceRoutes)
	if err != nil {
		return nil, err
	}

	s.defaultTunMu.Lock()
	locked := true
	callClosedCallback := false
	defer func() {
		if locked {
			s.defaultTunMu.Unlock()
		}
		if callClosedCallback && s.callbacks.DefaultTunClosed != nil {
			s.callbacks.DefaultTunClosed()
		}
	}()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	tunRulesSupported := s.tunRulesSupportedLocked()
	state := s.defaultTun
	rebuilding := state != nil
	mtu := gtunconfig.NormalizeMTU(opts.MTU)
	if state == nil {
		t, err := s.tunFactory.CreateTUN(s.defaultTunBaseName(), mtu)
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		s.defaultTunSourceGeneration++
		state = &defaultTunState{
			system:           s,
			tun:              t,
			sourceGeneration: s.defaultTunSourceGeneration,
		}
		state.public = &defaultTun{defaultTunState: state}
		s.defaultTun = state
	}
	s.mu.Unlock()

	nativeTun := stateTun(state)
	var oldNativeTun gtun.Tun
	tunRecreated := false
	if rebuilding {
		var err error
		nativeTun, oldNativeTun, tunRecreated, err =
			s.prepareDefaultTunLink(state, mtu)
		if err != nil {
			return nil, err
		}
	}

	state.mu.Lock()
	oldServer := state.server
	oldDNSIP := state.dnsIP
	oldRuleIDs := append([]uint64(nil), state.ruleIDs...)
	oldPmarkChecker := state.pmarkChecker
	state.mu.Unlock()

	var (
		server                = oldServer
		serverReplaced        bool
		pmarkCheckerInstalled bool
		connmarkSet           bool
		ruleIDs               []uint64
		appliedRC             *routing.Config
	)
	fail := func(cause error) error {
		err := cause
		if tunRecreated && nativeTun != nil {
			err = errors.Join(err, nativeTun.Close())
		}
		for _, id := range ruleIDs {
			s.unregisterRule(id)
		}
		if serverReplaced && server != nil {
			server.Detach()
			err = errors.Join(err, server.Close())
		}
		if !oldPmarkChecker && pmarkCheckerInstalled {
			_, e := s.pmark.SetChecker(nil)
			err = errors.Join(err, e)
		}
		if appliedRC != nil {
			state.mu.Lock()
			state.routingConfig = appliedRC
			state.mu.Unlock()
		}
		if connmarkSet && s.connmark != nil {
			err = errors.Join(err, s.connmark.Rollback())
		}
		s.mu.Lock()
		active := s.defaultTun == state
		if active {
			s.defaultTun = nil
		}
		s.mu.Unlock()
		if active {
			err = errors.Join(err, state.closeActive())
			callClosedCallback = true
		}
		return err
	}

	if err := s.tunConfig.SetTunMTU(nativeTun, opts.MTU); err != nil {
		return nil, fail(err)
	}
	if err := s.tunConfig.SetTunAddrs(nativeTun, addrs); err != nil {
		return nil, fail(err)
	}
	// The routing manager owns DefaultTun routes in its dedicated VPN table.
	// Keep the main table free of routes through this TUN. The application
	// bypass rule looks up main, so any matching route through the TUN can send
	// a VPN transport back into its own tunnel. An empty replacement also
	// removes connected main-table routes that SetTunAddrs can create.
	if err := s.tunConfig.SetTunRoutes(nativeTun, nil); err != nil {
		return nil, fail(err)
	}
	if tunRecreated && server != nil && oldDNSIP == dnsIP {
		server.Detach()
		if err := server.Close(); err != nil {
			return nil, fail(err)
		}
		if oldServer == server {
			oldServer = nil
		}
		server = nil
	}
	if server == nil || oldDNSIP != dnsIP || tunRecreated {
		conn, err := s.packetListen(
			context.Background(),
			"udp",
			net.JoinHostPort(dnsIP.String(), "53"),
		)
		if err != nil {
			return nil, fail(err)
		}
		server = gdns.NewServer(conn, nil, nil)
		serverReplaced = true
	} else if server != nil {
		server.Detach()
	}

	var pmarkConfig defaultTunPmarkConfig
	if tunRulesSupported {
		var err error
		pmarkConfig, err = s.defaultTunChecker(opts)
		if err != nil {
			return nil, fail(err)
		}
		ruleIDs = pmarkConfig.ruleIDs
	}
	if pmarkConfig.check != nil {
		var err error
		if controller, ok := s.pmark.(pmarkKernelPolicyController); ok {
			_, err = controller.SetKernelPolicy(
				pmarkConfig.kernelPolicy,
				pmarkConfig.check,
			)
		} else {
			_, err = s.pmark.SetChecker(pmarkConfig.check)
		}
		if err != nil {
			return nil, fail(err)
		}
		pmarkCheckerInstalled = true
		if err := s.pmark.ForceProcessTraversal(); err != nil {
			return nil, fail(err)
		}
	}

	index, err := s.tunIndex(nativeTun)
	if err != nil {
		return nil, fail(err)
	}
	if err := s.setDefaultTunDNSInterface(state, index); err != nil {
		return nil, fail(err)
	}
	rc := routing.DefaultConfig()
	rc.TUNIndex = index
	rc.AppBypassMark = s.appBypassMark
	rc.AppBypassMask = s.appBypassMask
	rc.UserMark = s.userMark
	rc.UserMarkMask = s.userMarkMask
	rc.Families = routeFamilies(addrs, routes)
	rc.SourceRoutes = sourceRoutes
	if len(opts.Include) > 0 {
		rc.Mode = routing.ModeInclude
	} else {
		rc.Mode = routing.ModeExclude
	}
	if opts.Strict {
		rc.Strictness = routing.Strict
	} else {
		rc.Strictness = routing.NonStrict
	}
	if err := s.routingManager.Apply(rc); err != nil {
		if errors.Is(err, routing.ErrApplyFailedGuardActive) {
			err = errors.Join(err, s.routingManager.Rollback(rc))
		}
		return nil, fail(err)
	}
	appliedRC = &rc
	if ok, err := s.applyConnmark(); err != nil {
		return nil, fail(err)
	} else {
		connmarkSet = ok
	}
	if err := s.dnsProvider.SetDNS(dnsIP); err != nil {
		return nil, fail(err)
	}
	if err := s.updateKillswitch(state, rc.Mode); err != nil {
		return nil, fail(err)
	}

	var sourceGeneration uint64
	if tunRecreated {
		s.mu.Lock()
		s.defaultTunSourceGeneration++
		sourceGeneration = s.defaultTunSourceGeneration
		s.mu.Unlock()
	}
	state.mu.Lock()
	generation := state.generation + 1
	if tunRecreated {
		state.sourceGeneration = sourceGeneration
		state.tun = nativeTun
	}
	storedRC := rc
	if rc.SourceRoutes != nil {
		storedRC.SourceRoutes = make(
			[]routing.SourceRoute,
			len(rc.SourceRoutes),
		)
		copy(storedRC.SourceRoutes, rc.SourceRoutes)
	}
	state.server = server
	state.dnsIP = dnsIP
	state.ruleIDs = ruleIDs
	state.routingConfig = &storedRC
	state.pmarkChecker = pmarkCheckerInstalled
	state.dnsIfidxSet = s.dnsProviderSupportsInterfaceIndex()
	state.connmarkSet = connmarkSet
	state.generation = generation
	state.addrs = append([]string(nil), addrs...)
	state.routes = append([]string(nil), routes...)
	wrapper := state.public
	state.mu.Unlock()
	if tunRecreated && oldNativeTun != nil {
		_ = oldNativeTun.Close()
	}
	for _, id := range oldRuleIDs {
		s.unregisterRule(id)
	}
	if serverReplaced && oldServer != nil {
		oldServer.Detach()
		_ = oldServer.Close()
	}

	locked = false
	s.defaultTunMu.Unlock()
	if s.callbacks.DefaultTunCreated != nil {
		s.callbacks.DefaultTunCreated(wrapper)
	}
	if s.callbacks.RoutingApplied != nil {
		callbackRC := rc
		if rc.SourceRoutes != nil {
			callbackRC.SourceRoutes = make(
				[]routing.SourceRoute,
				len(rc.SourceRoutes),
			)
			copy(callbackRC.SourceRoutes, rc.SourceRoutes)
		}
		s.callbacks.RoutingApplied(callbackRC)
	}
	if s.callbacks.DNSConfigured != nil {
		s.callbacks.DNSConfigured(dnsIP)
	}
	if s.callbacks.DefaultTunConfigured != nil {
		s.callbacks.DefaultTunConfigured(wrapper, opts.Copy())
	}
	return wrapper, nil
}

func (s *System) prepareDefaultTunLink(
	state *defaultTunState,
	mtu int,
) (gtun.Tun, gtun.Tun, bool, error) {
	state.mu.Lock()
	t := state.tun
	state.mu.Unlock()

	if _, err := s.tunIndex(t); err == nil {
		return t, nil, false, nil
	}

	replacement, err := s.tunFactory.CreateTUN(s.defaultTunBaseName(), mtu)
	if err != nil {
		return nil, nil, false, err
	}
	if err := validateDefaultTunReplacement(t, replacement); err != nil {
		return nil, nil, false, errors.Join(err, replacement.Close())
	}
	return replacement, t, true, nil
}

func validateDefaultTunReplacement(old, replacement gtun.Tun) error {
	if old == nil || replacement == nil {
		return errors.New("default tun replacement source is unavailable")
	}
	if old.IsNative() != replacement.IsNative() ||
		old.MWO() != replacement.MWO() ||
		old.MRO() != replacement.MRO() ||
		old.BatchSize() != replacement.BatchSize() {
		return errors.New(
			"default tun replacement has incompatible I/O metadata",
		)
	}
	return nil
}

func stateTun(state *defaultTunState) gtun.Tun {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.tun
}

type defaultTunPmarkConfig struct {
	ruleIDs      []uint64
	check        pmark.CheckFunc
	kernelPolicy pmark.KernelPolicy
}

func (s *System) defaultTunChecker(
	opts sysnet.DefaultTunOpts,
) (defaultTunPmarkConfig, error) {
	if s.ruleTracker == nil {
		return defaultTunPmarkConfig{}, nil
	}
	priority64, err := strconv.ParseInt(strconv.Itoa(s.pmarkPriority), 10, 8)
	if err != nil {
		return defaultTunPmarkConfig{}, fmt.Errorf(
			"pmark priority %d is outside int8 range",
			s.pmarkPriority,
		)
	}
	priority := int8(priority64)
	rules := opts.Exclude
	if len(opts.Include) > 0 {
		rules = opts.Include
	}
	var ids []uint64
	var exactCommRules []pmark.ExactCommRule
	hasFallbackRule := false
	for _, rule := range rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return defaultTunPmarkConfig{}, err
		}
		if compiled.process == nil {
			continue
		}
		id := s.ruleTracker.RegisterRule(compiled.process)
		ids = append(ids, id)
		if rule.Type != "comm" {
			hasFallbackRule = true
			continue
		}
		comm, supported, err := pmark.ExactCommFromRegexp(rule.Rule)
		if err != nil {
			return defaultTunPmarkConfig{}, err
		}
		if !supported {
			hasFallbackRule = true
			continue
		}
		exactCommRules = append(exactCommRules, pmark.ExactCommRule{
			Comm:     comm,
			Priority: priority,
			Mark:     fwmark.ToMark(s.userMark),
		})
	}
	check := func(info pmark.ProcessInfo) (int8, uint64, bool) {
		s.ruleTracker.ApplyProcess(info)
		if len(ids) == 0 {
			return 0, 0, false
		}
		for _, id := range ids {
			if s.ruleTracker.Matches(info.Key, id) {
				return priority, fwmark.ToMark(s.userMark), true
			}
		}
		return 0, 0, false
	}
	kernelPolicy := pmark.KernelPolicy{CommRules: exactCommRules}
	switch {
	case !hasFallbackRule:
		kernelPolicy.Mode = pmark.KernelPolicyAuthoritative
	case len(exactCommRules) != 0:
		kernelPolicy.Mode = pmark.KernelPolicyPositiveOnly
	default:
		kernelPolicy.Mode = pmark.KernelPolicyUserspaceOnly
	}
	return defaultTunPmarkConfig{
		ruleIDs:      ids,
		check:        check,
		kernelPolicy: kernelPolicy,
	}, nil
}

func (s *System) updateKillswitch(
	state *defaultTunState,
	mode routing.Mode,
) error {
	if !s.features.Killswitch || s.killswitch == nil {
		return nil
	}
	rules := killswitch.AllowRules{
		EnableV4:     true,
		EnableV6:     true,
		AllowedMarks: []string{hexMark(s.appBypassMark)},
	}
	if mode == routing.ModeExclude && s.killswitchAllowExclude {
		rules.AllowedMarks = append(rules.AllowedMarks, hexMark(s.userMark))
	}
	state.mu.Lock()
	id := state.killswitchID
	state.mu.Unlock()
	var err error
	if id == 0 {
		id, err = s.killswitch.CreateTMPRuleset(rules)
	} else {
		err = s.killswitch.UpdateTMPRuleset(id, rules)
	}
	if err != nil {
		return err
	}
	state.mu.Lock()
	state.killswitchID = id
	state.mu.Unlock()
	if s.callbacks.KillswitchUpdated != nil {
		s.callbacks.KillswitchUpdated(rules)
	}
	return nil
}

func (s *System) applyConnmark() (bool, error) {
	if s.connmark == nil {
		return false, nil
	}
	config := linuxconnmark.Config{
		Marks: []linuxconnmark.Mark{
			{Value: s.appBypassMark, Mask: s.appBypassMask},
			{Value: s.userMark, Mask: s.userMarkMask},
		},
	}
	if err := s.connmark.Apply(config); err != nil {
		if s.connmarkRequired {
			return false, err
		}
		s.logf("default tun connmark setup skipped: %v", err)
		return false, nil
	}
	return true, nil
}

func (s *System) dnsProviderSupportsInterfaceIndex() bool {
	_, ok := s.dnsProvider.(dnsInterfaceIndexer)
	return ok
}

func (s *System) setDefaultTunDNSInterface(
	state *defaultTunState,
	ifidx int,
) error {
	provider, ok := s.dnsProvider.(dnsInterfaceIndexer)
	if !ok {
		return nil
	}
	if err := provider.SetInterfaceIndex(ifidx); err != nil {
		return err
	}
	state.mu.Lock()
	state.dnsIfidxSet = true
	state.mu.Unlock()
	return nil
}

func (s *System) clearDefaultTunDNSInterface() error {
	provider, ok := s.dnsProvider.(dnsInterfaceIndexer)
	if !ok {
		return nil
	}
	return provider.SetInterfaceIndex(0)
}

// DefaultTunWarnings returns read-only runtime warnings for an active
// DefaultTun created by this System.
func (s *System) DefaultTunWarnings(t sysnet.DefaultTun) []sysnet.Warning {
	d, ok := t.(*defaultTun)
	if !ok || d == nil || d.defaultTunState == nil {
		return nil
	}

	s.mu.Lock()
	active := !s.closed && s.defaultTun == d.defaultTunState
	provider, resolved := s.dnsProvider.(*linuxdns.Resolved)
	s.mu.Unlock()
	if !active || !resolved {
		return nil
	}

	d.mu.Lock()
	wrapperActive := d.server != nil
	nativeTun := d.tun
	dnsIP := d.dnsIP
	d.mu.Unlock()
	if !wrapperActive {
		return nil
	}

	ifidx, err := s.tunIndex(nativeTun)
	if err != nil || ifidx <= 0 || int64(ifidx) > int64(1<<31-1) {
		return nil
	}
	ifidx32 := int32(ifidx) //nolint:gosec // ifidx is bounds-checked above.
	warnings := provider.DefaultTunDNSRouteWarnings(ifidx32, dnsIP)
	return append([]sysnet.Warning(nil), warnings...)
}

func (d *defaultTun) SetDns(resolver gdns.Interface) {
	d.system.defaultTunMu.Lock()
	defer d.system.defaultTunMu.Unlock()
	d.system.mu.Lock()
	active := !d.system.closed && d.system.defaultTun == d.defaultTunState
	d.system.mu.Unlock()
	if !active {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.server == nil {
		return
	}
	if resolver == nil {
		d.server.Detach()
		return
	}
	d.server.Attach(resolver)
}

func (d *defaultTun) Close() error {
	d.system.defaultTunMu.Lock()
	d.system.mu.Lock()
	active := d.system.defaultTun == d.defaultTunState
	if active {
		d.system.defaultTun = nil
	}
	d.system.mu.Unlock()
	if !active {
		d.system.defaultTunMu.Unlock()
		return nil
	}
	err := d.closeActive()
	d.system.defaultTunMu.Unlock()
	if d.system.callbacks.DefaultTunClosed != nil {
		d.system.callbacks.DefaultTunClosed()
	}
	return err
}

func (d *defaultTunState) closeActive() error {
	d.mu.Lock()
	server := d.server
	d.server = nil
	rc := d.routingConfig
	d.routingConfig = nil
	ksID := d.killswitchID
	d.killswitchID = 0
	pmarkChecker := d.pmarkChecker
	d.pmarkChecker = false
	dnsIfidxSet := d.dnsIfidxSet
	d.dnsIfidxSet = false
	connmarkSet := d.connmarkSet
	d.connmarkSet = false
	tun := d.tun
	d.tun = nil
	d.unregisterRulesLocked()
	d.mu.Unlock()

	var err error
	if server != nil {
		server.Detach()
		err = errors.Join(err, server.Close())
	}
	if d.system.dnsProvider != nil {
		err = errors.Join(err, d.system.dnsProvider.UnsetDNS())
	}
	if dnsIfidxSet {
		err = errors.Join(err, d.system.clearDefaultTunDNSInterface())
	}
	if rc != nil && d.system.routingManager != nil {
		err = errors.Join(err, d.system.routingManager.Rollback(*rc))
	}
	if connmarkSet && d.system.connmark != nil {
		err = errors.Join(err, d.system.connmark.Rollback())
	}
	if ksID != 0 && d.system.killswitch != nil {
		err = errors.Join(err, d.system.killswitch.DeleteTMPRuleset(ksID))
	}
	if pmarkChecker && d.system.pmark != nil {
		_, e := d.system.pmark.SetChecker(nil)
		err = errors.Join(err, e)
	}
	if tun != nil {
		err = errors.Join(err, tun.Close())
	}
	return err
}

func (d *defaultTunState) unregisterRulesLocked() {
	for _, id := range d.ruleIDs {
		d.system.unregisterRule(id)
	}
	d.ruleIDs = nil
}

func (s *System) unregisterRule(id uint64) {
	if s.ruleTracker != nil {
		s.ruleTracker.UnregisterRule(id)
	}
}

// SourceGeneration returns the identity generation of the current native TUN.
// The value changes only when the native source changes.
func (d *defaultTun) SourceGeneration() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sourceGeneration
}

func (d *defaultTun) nativeTun() gtun.Tun {
	d.system.mu.Lock()
	defer d.system.mu.Unlock()
	if d.system.closed || d.system.defaultTun != d.defaultTunState {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tun
}

func (d *defaultTun) File() *os.File {
	if t := d.nativeTun(); t != nil {
		return t.File()
	}
	return nil
}

func (d *defaultTun) IsNative() bool {
	if t := d.nativeTun(); t != nil {
		return t.IsNative()
	}
	return false
}

func (d *defaultTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if t := d.nativeTun(); t != nil {
		return t.Read(bufs, sizes, offset)
	}
	return 0, os.ErrClosed
}
func (d *defaultTun) Write(bufs [][]byte, offset int) (int, error) {
	if t := d.nativeTun(); t != nil {
		return t.Write(bufs, offset)
	}
	return 0, os.ErrClosed
}
func (d *defaultTun) MWO() int {
	if t := d.nativeTun(); t != nil {
		return t.MWO()
	}
	return 0
}
func (d *defaultTun) MRO() int {
	if t := d.nativeTun(); t != nil {
		return t.MRO()
	}
	return 0
}
func (d *defaultTun) MTU() (int, error) {
	if t := d.nativeTun(); t != nil {
		return t.MTU()
	}
	return 0, os.ErrClosed
}
func (d *defaultTun) Name() (string, error) {
	if t := d.nativeTun(); t != nil {
		return t.Name()
	}
	return "", os.ErrClosed
}
func (d *defaultTun) Events() <-chan gtun.Event {
	if t := d.nativeTun(); t != nil {
		return t.Events()
	}
	return closedDefaultTunEvents
}
func (d *defaultTun) BatchSize() int {
	if t := d.nativeTun(); t != nil {
		return max(1, t.BatchSize())
	}
	return 1
}

var closedDefaultTunEvents = func() <-chan gtun.Event {
	events := make(chan gtun.Event)
	close(events)
	return events
}()
