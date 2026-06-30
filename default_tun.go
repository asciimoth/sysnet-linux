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
	"github.com/asciimoth/sysnet-linux/killswitch"
	"github.com/asciimoth/sysnet-linux/routing"
	gtunconfig "github.com/asciimoth/sysnet-linux/tun"
)

type defaultTunState struct {
	mu sync.Mutex

	system     *System
	tun        gtun.Tun
	server     *gdns.Server
	dnsIP      netip.Addr
	generation uint64

	routingConfig *routing.Config
	ruleIDs       []uint64
	killswitchID  uint64
	pmarkChecker  bool
	dnsIfidxSet   bool
	connmarkSet   bool
}

type defaultTun struct {
	*defaultTunState
	generation uint64
}

var _ sysnet.DefaultTun = (*defaultTun)(nil)

type dnsInterfaceIndexer interface {
	SetInterfaceIndex(int) error
}

// VerifyDefaultTunOpts validates DefaultTun options without mutating host state.
func (s *System) VerifyDefaultTunOpts(opts sysnet.DefaultTunOpts) error {
	if !s.Features().DefaultTun {
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
	if _, _, err := normalizeTunAddrs(
		opts.TunAddrs,
		s.defaultTunCIDR,
		opts.DnsIP,
	); err != nil {
		return err
	}
	_, err := normalizeTunRoutes(opts.TunRoutes)
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

	s.mu.Lock()
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
		state = &defaultTunState{system: s, tun: t}
		s.defaultTun = state
	}
	s.mu.Unlock()

	tunRecreated := false
	if rebuilding {
		var err error
		tunRecreated, err = s.ensureDefaultTunLink(state, mtu)
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
	fail := func(cause error) (sysnet.DefaultTun, error) {
		err := cause
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
			if s.callbacks.DefaultTunClosed != nil {
				s.callbacks.DefaultTunClosed()
			}
		}
		return nil, err
	}

	if err := s.tunConfig.SetTunMTU(state.tun, opts.MTU); err != nil {
		return fail(err)
	}
	if err := s.tunConfig.SetTunAddrs(state.tun, addrs); err != nil {
		return fail(err)
	}
	if err := s.tunConfig.SetTunRoutes(state.tun, routes); err != nil {
		return fail(err)
	}
	if tunRecreated && server != nil && oldDNSIP == dnsIP {
		server.Detach()
		if err := server.Close(); err != nil {
			return fail(err)
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
			return fail(err)
		}
		server = gdns.NewServer(conn, nil, nil)
		serverReplaced = true
	} else if server != nil {
		server.Detach()
	}

	var check pmark.CheckFunc
	if tunRulesSupported {
		var err error
		ruleIDs, check, err = s.defaultTunChecker(opts)
		if err != nil {
			return fail(err)
		}
	}
	if check != nil {
		if _, err := s.pmark.SetChecker(check); err != nil {
			return fail(err)
		}
		pmarkCheckerInstalled = true
		if err := s.pmark.ForceProcessTraversal(); err != nil {
			return fail(err)
		}
	}

	index, err := s.tunIndex(state.tun)
	if err != nil {
		return fail(err)
	}
	if err := s.setDefaultTunDNSInterface(state, index); err != nil {
		return fail(err)
	}
	rc := routing.DefaultConfig()
	rc.TUNIndex = index
	rc.AppBypassMark = s.appBypassMark
	rc.AppBypassMask = s.appBypassMask
	rc.UserMark = s.userMark
	rc.UserMarkMask = s.userMarkMask
	rc.Families = routeFamilies(addrs, routes)
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
		return fail(err)
	}
	appliedRC = &rc
	if ok, err := s.applyConnmark(); err != nil {
		return fail(err)
	} else {
		connmarkSet = ok
	}
	if err := s.dnsProvider.SetDNS(dnsIP); err != nil {
		return fail(err)
	}
	if err := s.updateKillswitch(state, rc.Mode); err != nil {
		return fail(err)
	}

	state.mu.Lock()
	generation := state.generation + 1
	state.server = server
	state.dnsIP = dnsIP
	state.ruleIDs = ruleIDs
	state.routingConfig = &rc
	state.pmarkChecker = pmarkCheckerInstalled
	state.dnsIfidxSet = s.dnsProviderSupportsInterfaceIndex()
	state.connmarkSet = connmarkSet
	state.generation = generation
	state.mu.Unlock()
	for _, id := range oldRuleIDs {
		s.unregisterRule(id)
	}
	if serverReplaced && oldServer != nil {
		oldServer.Detach()
		_ = oldServer.Close()
	}

	wrapper := &defaultTun{defaultTunState: state, generation: generation}
	if s.callbacks.DefaultTunCreated != nil {
		s.callbacks.DefaultTunCreated(wrapper)
	}
	if s.callbacks.RoutingApplied != nil {
		s.callbacks.RoutingApplied(rc)
	}
	if s.callbacks.DNSConfigured != nil {
		s.callbacks.DNSConfigured(dnsIP)
	}
	if s.callbacks.DefaultTunConfigured != nil {
		s.callbacks.DefaultTunConfigured(wrapper, opts.Copy())
	}
	return wrapper, nil
}

func (s *System) ensureDefaultTunLink(
	state *defaultTunState,
	mtu int,
) (bool, error) {
	state.mu.Lock()
	t := state.tun
	state.mu.Unlock()

	if _, err := s.tunIndex(t); err == nil {
		return false, nil
	}

	replacement, err := s.tunFactory.CreateTUN(s.defaultTunBaseName(), mtu)
	if err != nil {
		return false, err
	}

	state.mu.Lock()
	old := state.tun
	state.tun = replacement
	state.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	return true, nil
}

func (s *System) defaultTunChecker(
	opts sysnet.DefaultTunOpts,
) ([]uint64, pmark.CheckFunc, error) {
	if s.ruleTracker == nil {
		return nil, func(pmark.ProcessInfo) (int8, uint64, bool) {
			return 0, 0, false
		}, nil
	}
	priority64, err := strconv.ParseInt(strconv.Itoa(s.pmarkPriority), 10, 8)
	if err != nil {
		return nil, nil, fmt.Errorf(
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
	for _, rule := range rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, nil, err
		}
		if compiled.process == nil {
			continue
		}
		id := s.ruleTracker.RegisterRule(compiled.process)
		ids = append(ids, id)
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
	return ids, check, nil
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

func (d *defaultTun) SetDns(resolver gdns.Interface) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.generation != d.defaultTunState.generation || d.server == nil {
		return
	}
	if resolver == nil {
		d.server.Detach()
		return
	}
	d.server.Attach(resolver)
}

func (d *defaultTun) Close() error {
	d.system.mu.Lock()
	active := d.system.defaultTun == d.defaultTunState &&
		d.generation == d.defaultTunState.generation
	if active {
		d.system.defaultTun = nil
	}
	d.system.mu.Unlock()
	if !active {
		return nil
	}
	err := d.closeActive()
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
	err = errors.Join(err, d.tun.Close())
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

func (d *defaultTun) File() *os.File { return d.tun.File() }
func (d *defaultTun) IsNative() bool { return d.tun.IsNative() }
func (d *defaultTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.tun.Read(bufs, sizes, offset)
}
func (d *defaultTun) Write(bufs [][]byte, offset int) (int, error) {
	return d.tun.Write(bufs, offset)
}
func (d *defaultTun) MWO() int                  { return d.tun.MWO() }
func (d *defaultTun) MRO() int                  { return d.tun.MRO() }
func (d *defaultTun) MTU() (int, error)         { return d.tun.MTU() }
func (d *defaultTun) Name() (string, error)     { return d.tun.Name() }
func (d *defaultTun) Events() <-chan gtun.Event { return d.tun.Events() }
func (d *defaultTun) BatchSize() int            { return d.tun.BatchSize() }
