//go:build linux

package routing

import (
	"errors"
	"fmt"
	"sync"

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
	mu      sync.Mutex
	adapter netlinkAdapter
	closed  bool
	applied *DesiredState
}

// NewManager creates a Manager backed by a real netlink handle.
func NewManager() (*Manager, error) {
	adapter, err := newRealAdapter()
	if err != nil {
		return nil, err
	}
	return newManagerWithAdapter(adapter), nil
}

func newManagerWithAdapter(adapter netlinkAdapter) *Manager {
	return &Manager{adapter: adapter}
}

// Apply validates config, snapshots main, compiles desired routing state, and
// reconciles the package-owned priority block and tables.
func (m *Manager) Apply(config Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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

// Refresh rebuilds the safe table from the current main table while preserving
// currently applied rules and VPN routes.
func (m *Manager) Refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureOpen(); err != nil {
		return err
	}
	if m.applied == nil {
		return errors.New("routing: refresh called before apply")
	}
	config := m.applied.Config
	snapshot, err := m.snapshotMain(config)
	if err != nil {
		return err
	}
	desired, err := CompileDesiredState(config, snapshot)
	if err != nil {
		return err
	}
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
	var errs []error
	for _, family := range familyConstants(config.Families) {
		errs = append(errs, m.deleteOwnedRules(config, family, nil))
	}
	errs = append(errs, m.flushTable(config, config.VPNTable))
	errs = append(errs, m.flushTable(config, config.SafeTable))
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrRollbackIncomplete, err)
	}
	m.applied = nil
	return nil
}

// Close closes the underlying netlink handle. It does not rollback state.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	return m.adapter.Close()
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

	if err := m.flushTable(config, config.VPNTable); err != nil {
		return fail(err)
	}
	if err := m.flushTable(config, config.SafeTable); err != nil {
		return fail(err)
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
	for _, family := range familyConstants(config.Families) {
		if err := m.deleteOwnedRules(config, family, map[int]bool{
			config.PriorityBase + ruleOffsetTransitionGuard: true,
		}); err != nil {
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
	for _, family := range familyConstants(config.Families) {
		if err := m.adapter.DeleteRule(
			transitionGuard(config, family),
		); err != nil {
			return fail(fmt.Errorf("remove transition guard: %w", err))
		}
	}
	guardInstalled = false
	return nil
}

func (m *Manager) deleteOwnedRules(
	config Config,
	family int,
	keep map[int]bool,
) error {
	rules, err := m.adapter.ListRules(family)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	var errs []error
	for _, rule := range rules {
		if rule.Priority < config.PriorityBase ||
			rule.Priority >= config.PriorityBase+config.PrioritySpan {
			continue
		}
		if keep[rule.Priority] {
			continue
		}
		errs = append(errs, m.adapter.DeleteRule(rule))
	}
	return errors.Join(errs...)
}

func (m *Manager) flushTable(config Config, table int) error {
	var errs []error
	for _, family := range familyConstants(config.Families) {
		routes, err := m.adapter.ListRoutes(family, table)
		if err != nil {
			errs = append(errs, fmt.Errorf("list table %d: %w", table, err))
			continue
		}
		for _, route := range routes {
			errs = append(errs, m.adapter.DeleteRoute(route))
		}
	}
	return errors.Join(errs...)
}
