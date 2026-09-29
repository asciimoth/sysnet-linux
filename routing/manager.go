//go:build linux

package routing

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var (
	ErrApplyFailedGuardActive = errors.New(
		"routing: apply failed with transition guard active",
	)
	ErrRollbackIncomplete = errors.New("routing: rollback incomplete")
)

// Manager reconciles package-owned Linux routes and rules.
type Manager struct {
	mu        sync.Mutex
	adapter   netlinkAdapter
	closed    bool
	applied   *DesiredState
	closeDone chan struct{}
	closeErr  error

	monitorDone      chan struct{}
	monitorWait      sync.WaitGroup
	monitorSubscribe routeSubscribeFunc
	monitorOptions   netlink.RouteSubscribeOptions
	monitorNamespace *netns.NsHandle
	monitorDebounce  time.Duration
	monitorRetry     time.Duration
}

// NewManager creates a Manager backed by a real netlink handle.
//
// The manager monitors main-table route changes. While a non-strict policy is
// active, it rebuilds the safe table after changes settle. The update is
// asynchronous, so route changes can cause a short fail-closed interval before
// the safe table matches the main table. Strict policies do not use the safe
// table and do not require a refresh.
func NewManager() (*Manager, error) {
	adapter, err := newRealAdapter()
	if err != nil {
		return nil, err
	}
	namespace, err := netns.Get()
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("open route monitor namespace: %w", err)
	}
	manager := newManagerWithAdapter(adapter)
	manager.monitorNamespace = &namespace
	manager.monitorOptions.Namespace = &namespace
	if err := manager.startRouteMonitor(
		netlink.RouteSubscribeWithOptions,
	); err != nil {
		_ = adapter.Close()
		_ = namespace.Close()
		return nil, fmt.Errorf("monitor main routes: %w", err)
	}
	return manager, nil
}

func newManagerWithAdapter(adapter netlinkAdapter) *Manager {
	return &Manager{
		adapter:         adapter,
		monitorDebounce: defaultRouteMonitorDebounce,
		monitorRetry:    defaultRouteMonitorRetry,
	}
}

// Apply validates config, snapshots main, compiles desired routing state, and
// reconciles the package-owned priority block and tables.
func (m *Manager) Apply(config Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	config = cloneConfig(config)
	if err := m.ensureOpen(); err != nil {
		return err
	}
	if err := config.validate(); err != nil {
		return err
	}
	if err := m.adapter.LinkByIndex(config.TUNIndex); err != nil {
		if errors.Is(err, ErrTUNLinkNotFound) {
			return err
		}
		return fmt.Errorf("lookup TUN link %d: %w", config.TUNIndex, err)
	}
	snapshot, err := m.snapshotMain(config)
	if err != nil {
		return err
	}
	desired, err := CompileDesiredState(config, snapshot)
	if err != nil {
		return err
	}
	if err := m.applyDesired(desired); err != nil {
		return err
	}
	m.applied = &desired
	return nil
}

// Refresh immediately rebuilds the safe table from the current main table
// while preserving currently applied rules and VPN routes. NewManager also
// calls this operation automatically after main-table route changes settle.
func (m *Manager) Refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return err
	}
	if m.applied == nil {
		return errors.New("routing: refresh called before apply")
	}
	return m.refreshLocked()
}

func (m *Manager) refreshLocked() error {
	config := m.applied.Config
	guardInstalled := false
	fail := func(err error) error {
		if guardInstalled {
			return fmt.Errorf("%w: %w", ErrApplyFailedGuardActive, err)
		}
		return err
	}
	for _, family := range familyConstants(config.Families) {
		if err := m.adapter.AddRule(
			transitionGuard(config, family),
		); err != nil {
			return fail(fmt.Errorf("install transition guard: %w", err))
		}
		guardInstalled = true
	}
	snapshot, err := m.snapshotMain(config)
	if err != nil {
		return fail(err)
	}
	desired, err := CompileDesiredState(config, snapshot)
	if err != nil {
		return fail(err)
	}
	if err := m.flushTable(config, config.SafeTable); err != nil {
		return fail(err)
	}
	for _, route := range desired.SafeRoutes {
		if err := m.adapter.ReplaceRoute(route); err != nil {
			return fail(fmt.Errorf("install safe route %s: %w", route.Dst, err))
		}
	}
	for _, family := range familyConstants(config.Families) {
		if err := m.adapter.DeleteRule(
			transitionGuard(config, family),
		); err != nil {
			return fail(fmt.Errorf("remove transition guard: %w", err))
		}
	}
	guardInstalled = false
	m.applied = &desired
	return nil
}

// Status returns the last successfully applied desired state.
func (m *Manager) Status() (DesiredState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applied == nil {
		return DesiredState{}, false
	}
	state := *m.applied
	state.Config = cloneConfig(state.Config)
	state.Rules = cloneRules(state.Rules)
	state.VPNRoutes = cloneRoutes(state.VPNRoutes)
	state.SafeRoutes = cloneRoutes(state.SafeRoutes)
	return state, true
}

// Rollback removes all package-owned rules and flushes package-owned tables.
// It is idempotent and does not require knowing the active mode.
func (m *Manager) Rollback(config Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return err
	}
	if err := config.validate(); err != nil {
		return err
	}
	configs := []Config{config}
	if m.applied != nil {
		configs = append(configs, m.applied.Config)
	}
	ruleScopes := ownedRuleScopes(configs)
	tableTargets := ownedTableTargets(configs)
	errs := make([]error, 0, len(ruleScopes)+len(tableTargets))
	for _, scope := range ruleScopes {
		errs = append(
			errs,
			m.deleteOwnedRules(scope.config, scope.family, nil),
		)
	}
	for _, target := range tableTargets {
		errs = append(
			errs,
			m.flushTableFamily(target.family, target.table),
		)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrRollbackIncomplete, err)
	}
	m.applied = nil
	return nil
}

// Close stops route monitoring and closes the underlying netlink handle. It
// does not rollback state.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		done := m.closeDone
		m.mu.Unlock()
		if done != nil {
			<-done
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.closeErr
	}
	m.closed = true
	closeDone := make(chan struct{})
	m.closeDone = closeDone
	done := m.monitorDone
	if done != nil {
		close(done)
		m.monitorDone = nil
	}
	m.mu.Unlock()

	m.monitorWait.Wait()
	err := m.adapter.Close()
	if m.monitorNamespace != nil {
		err = errors.Join(err, m.monitorNamespace.Close())
	}
	m.mu.Lock()
	m.closeErr = err
	close(closeDone)
	m.mu.Unlock()
	return err
}

func (m *Manager) ensureOpen() error {
	if m.closed {
		return errors.New("routing: manager is closed")
	}
	return nil
}

func (m *Manager) snapshotMain(config Config) (Snapshot, error) {
	var snapshot Snapshot
	for _, family := range familyConstants(config.Families) {
		routes, err := m.adapter.ListRoutes(family, unix.RT_TABLE_MAIN)
		if err != nil {
			return Snapshot{}, fmt.Errorf("list main routes: %w", err)
		}
		snapshot.MainRoutes = append(snapshot.MainRoutes, routes...)
	}
	return snapshot, nil
}

func (m *Manager) applyDesired(desired DesiredState) error {
	config := desired.Config
	guardInstalled := false
	configs := []Config{config}
	if m.applied != nil {
		configs = append(configs, m.applied.Config)
	}
	guards := transitionGuards(configs)
	desiredRules := make(map[Rule]bool, len(desired.Rules))
	for _, rule := range desired.Rules {
		desiredRules[rule] = true
	}

	fail := func(err error) error {
		if guardInstalled {
			return fmt.Errorf("%w: %w", ErrApplyFailedGuardActive, err)
		}
		return err
	}

	for _, guard := range guards {
		if err := m.adapter.AddRule(guard); err != nil {
			return fail(fmt.Errorf("install transition guard: %w", err))
		}
		guardInstalled = true
	}
	if m.applied != nil {
		for _, rule := range m.applied.Rules {
			if desiredRules[rule] || keepRule(rule, guards) {
				continue
			}
			if !sameRulePriorityAsGuard(rule, guards) {
				continue
			}
			if err := m.adapter.DeleteRule(rule); err != nil {
				return fail(fmt.Errorf(
					"remove obsolete rule at transition priority: %w",
					err,
				))
			}
		}
	}

	for _, target := range ownedTableTargets(configs) {
		if err := m.flushTableFamily(target.family, target.table); err != nil {
			return fail(err)
		}
	}
	for _, route := range desired.VPNRoutes {
		if err := m.adapter.ReplaceRoute(route); err != nil {
			return fail(fmt.Errorf("install VPN route %s: %w", route.Dst, err))
		}
	}
	for _, route := range desired.SafeRoutes {
		if err := m.adapter.ReplaceRoute(route); err != nil {
			return fail(fmt.Errorf("install safe route %s: %w", route.Dst, err))
		}
	}
	for _, scope := range ownedRuleScopes(configs) {
		if err := m.deleteOwnedRules(
			scope.config,
			scope.family,
			guards,
		); err != nil {
			return fail(err)
		}
	}
	for _, rule := range desired.Rules {
		if err := m.adapter.AddRule(rule); err != nil {
			return fail(
				fmt.Errorf("install rule priority %d: %w", rule.Priority, err),
			)
		}
	}
	for _, guard := range guards {
		if desiredRules[guard] {
			continue
		}
		if err := m.adapter.DeleteRule(guard); err != nil {
			return fail(fmt.Errorf("remove transition guard: %w", err))
		}
	}
	guardInstalled = false
	return nil
}

type ownedRuleScope struct {
	config Config
	family int
}

func ownedRuleScopes(configs []Config) []ownedRuleScope {
	type key struct {
		family       int
		priorityBase int
		prioritySpan int
	}
	seen := make(map[key]bool)
	var out []ownedRuleScope
	for _, config := range configs {
		for _, family := range familyConstants(config.Families) {
			key := key{
				family:       family,
				priorityBase: config.PriorityBase,
				prioritySpan: config.PrioritySpan,
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ownedRuleScope{config: config, family: family})
		}
	}
	return out
}

type ownedTableTarget struct {
	family int
	table  int
}

func ownedTableTargets(configs []Config) []ownedTableTarget {
	seen := make(map[ownedTableTarget]bool)
	var out []ownedTableTarget
	for _, config := range configs {
		for _, family := range familyConstants(config.Families) {
			for _, table := range []int{config.VPNTable, config.SafeTable} {
				target := ownedTableTarget{family: family, table: table}
				if seen[target] {
					continue
				}
				seen[target] = true
				out = append(out, target)
			}
		}
	}
	return out
}

func transitionGuards(configs []Config) []Rule {
	seen := make(map[Rule]bool)
	var out []Rule
	for _, config := range configs {
		for _, family := range familyConstants(config.Families) {
			guard := transitionGuard(config, family)
			if seen[guard] {
				continue
			}
			seen[guard] = true
			out = append(out, guard)
		}
	}
	return out
}

func (m *Manager) deleteOwnedRules(
	config Config,
	family int,
	keep []Rule,
) error {
	rules, err := m.adapter.ListRules(family)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	errs := make([]error, 0, len(rules))
	for _, rule := range rules {
		if rule.Priority < config.PriorityBase ||
			rule.Priority >= config.PriorityBase+config.PrioritySpan {
			continue
		}
		if keepRule(rule, keep) {
			continue
		}
		errs = append(errs, m.adapter.DeleteRule(rule))
	}
	return errors.Join(errs...)
}

func keepRule(rule Rule, keep []Rule) bool {
	for _, candidate := range keep {
		if rule == candidate || rule == listedRule(candidate) {
			return true
		}
	}
	return false
}

// listedRule returns the fields preserved by the netlink dependency when it
// reads a rule from the kernel. The dependency does not copy the action or an
// eight-bit table from the kernel message into netlink.Rule.
func listedRule(rule Rule) Rule {
	rule.Action = RuleLookup
	if rule.Table < 256 {
		rule.Table = 0
	}
	return rule
}

func sameRulePriorityAsGuard(rule Rule, guards []Rule) bool {
	for _, guard := range guards {
		if rule.Family == guard.Family && rule.Priority == guard.Priority {
			return true
		}
	}
	return false
}

func (m *Manager) flushTable(config Config, table int) error {
	families := familyConstants(config.Families)
	errs := make([]error, 0, len(families))
	for _, family := range families {
		errs = append(errs, m.flushTableFamily(family, table))
	}
	return errors.Join(errs...)
}

func (m *Manager) flushTableFamily(family, table int) error {
	routes, err := m.adapter.ListRoutes(family, table)
	if err != nil {
		return fmt.Errorf("list table %d: %w", table, err)
	}
	errs := make([]error, 0, len(routes))
	for _, route := range routes {
		errs = append(errs, m.adapter.DeleteRoute(route))
	}
	return errors.Join(errs...)
}
