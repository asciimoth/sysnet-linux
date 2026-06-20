//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/fwmark"
	"github.com/asciimoth/sysnet-linux/killswitch"
	"github.com/asciimoth/sysnet-linux/routing"
)

type defaultTunState struct {
	mu sync.Mutex

	system     *System
	tun        gtun.Tun
	server     *gdns.Server
	generation uint64

	routingConfig *routing.Config
	ruleIDs       []uint64
	killswitchID  uint64
}

type defaultTun struct {
	*defaultTunState
	generation uint64
}

var _ sysnet.DefaultTun = (*defaultTun)(nil)

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
		if !s.features.TunRules || s.pmark == nil || s.ruleTracker == nil {
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
	state := s.defaultTun
	if state == nil {
		t, err := s.tunFactory.CreateTUN(defaultTunBaseName, opts.MTU)
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		state = &defaultTunState{system: s, tun: t}
		s.defaultTun = state
	}
	state.generation++
	generation := state.generation
	s.mu.Unlock()

	state.mu.Lock()
	if state.server != nil {
		state.server.Detach()
	}
	state.unregisterRulesLocked()
	state.mu.Unlock()

	if err := s.tunConfig.SetTunMTU(state.tun, opts.MTU); err != nil {
		return nil, err
	}
	if err := s.tunConfig.SetTunAddrs(state.tun, addrs); err != nil {
		return nil, err
	}
	if err := s.tunConfig.SetTunRoutes(state.tun, routes); err != nil {
		return nil, err
	}
	if state.server == nil {
		conn, err := s.packetListen(
			context.Background(),
			"udp",
			net.JoinHostPort(dnsIP.String(), "53"),
		)
		if err != nil {
			return nil, err
		}
		state.mu.Lock()
		state.server = gdns.NewServer(conn, nil)
		state.mu.Unlock()
	}

	ruleIDs, check, err := s.defaultTunChecker(opts)
	if err != nil {
		return nil, err
	}
	if s.pmark != nil {
		if _, err := s.pmark.SetChecker(check); err != nil {
			return nil, err
		}
		if err := s.pmark.ForceProcessTraversal(); err != nil {
			return nil, err
		}
	}

	index, err := s.tunIndex(state.tun)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	if err := s.dnsProvider.SetDNS(dnsIP); err != nil {
		return nil, err
	}
	if err := s.updateKillswitch(state, rc.Mode); err != nil {
		return nil, err
	}

	state.mu.Lock()
	state.ruleIDs = ruleIDs
	state.routingConfig = &rc
	state.generation = generation
	state.mu.Unlock()

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

func (s *System) defaultTunChecker(
	opts sysnet.DefaultTunOpts,
) ([]uint64, pmark.CheckFunc, error) {
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
	if rc != nil && d.system.routingManager != nil {
		err = errors.Join(err, d.system.routingManager.Rollback(*rc))
	}
	if ksID != 0 && d.system.killswitch != nil {
		err = errors.Join(err, d.system.killswitch.DeleteTMPRuleset(ksID))
	}
	if d.system.pmark != nil {
		_, e := d.system.pmark.SetChecker(nil)
		err = errors.Join(err, e)
	}
	err = errors.Join(err, d.tun.Close())
	return err
}

func (d *defaultTunState) unregisterRulesLocked() {
	for _, id := range d.ruleIDs {
		d.system.ruleTracker.UnregisterRule(id)
	}
	d.ruleIDs = nil
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
