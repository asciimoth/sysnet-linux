//go:build linux

// Package connmark mirrors sysnet packet marks through conntrack marks so
// inbound replies are marked before distribution rpfilter chains run.
package connmark

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

const (
	tableName       = "sysnet_linux_connmark"
	outputChain     = "output"
	preroutingChain = "prerouting"
)

// Mark describes a packet-mark selector whose value should be mirrored through
// conntrack.
type Mark struct {
	Value uint32
	Mask  uint32
}

// Config is the complete connmark ruleset owned by Manager.
type Config struct {
	Marks []Mark
}

// Manager reconciles the package-owned nftables connmark table.
type Manager struct {
	mu      sync.Mutex
	conn    *nftables.Conn
	applied bool
}

// NewManager creates a Manager backed by the current network namespace.
func NewManager() *Manager {
	conn, _ := nftables.New()
	return newManagerWithConn(conn)
}

func newManagerWithConn(conn *nftables.Conn) *Manager {
	return &Manager{conn: conn}
}

// Apply replaces the package-owned connmark table with rules for config.
func (m *Manager) Apply(config Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn == nil {
		return errors.New("connmark: nftables connection is unavailable")
	}
	marks, err := normalizeMarks(config.Marks)
	if err != nil {
		return err
	}
	if err := m.rollbackLocked(); err != nil {
		return err
	}
	if len(marks) == 0 {
		m.applied = false
		return nil
	}

	table := connmarkTable()
	policy := nftables.ChainPolicyAccept
	preroutingPriority := nftables.ChainPriority( //nolint
		*nftables.ChainPriorityConntrack + 1,
	)
	output := &nftables.Chain{
		Name:     outputChain,
		Table:    table,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeRoute,
		Policy:   &policy,
	}
	prerouting := &nftables.Chain{
		Name:     preroutingChain,
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(preroutingPriority),
		Type:     nftables.ChainTypeFilter,
		Policy:   &policy,
	}

	m.conn.AddTable(table)
	m.conn.AddChain(output)
	m.conn.AddChain(prerouting)
	for _, mark := range marks {
		m.conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: output,
			Exprs: saveMarkExprs(mark),
		})
		m.conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: prerouting,
			Exprs: restoreMarkExprs(mark),
		})
	}
	if err := m.conn.Flush(); err != nil {
		_ = m.rollbackLocked()
		return fmt.Errorf("connmark: apply nftables rules: %w", err)
	}
	m.applied = true
	return nil
}

// Rollback deletes the package-owned connmark table.
func (m *Manager) Rollback() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rollbackLocked()
}

// Close releases Manager state. nftables.Conn is transient by default, so there
// is no persistent kernel socket to close.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied = false
	return nil
}

func (m *Manager) rollbackLocked() error {
	if m.conn == nil {
		m.applied = false
		return nil
	}
	tables, err := m.conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("connmark: list nftables tables: %w", err)
	}
	table := connmarkTable()
	if slices.ContainsFunc(tables, func(t *nftables.Table) bool {
		return t.Name == table.Name && t.Family == table.Family
	}) {
		m.conn.DelTable(table)
		if err := m.conn.Flush(); err != nil {
			return fmt.Errorf("connmark: delete nftables table: %w", err)
		}
	}
	m.applied = false
	return nil
}

func connmarkTable() *nftables.Table {
	return &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
}

func normalizeMarks(in []Mark) ([]Mark, error) {
	out := make([]Mark, 0, len(in))
	for _, mark := range in {
		if mark.Mask == 0 {
			return nil, errors.New("connmark: mark mask must be non-zero")
		}
		duplicate := slices.ContainsFunc(out, func(existing Mark) bool {
			return existing == mark
		})
		if !duplicate {
			out = append(out, mark)
		}
	}
	for i, a := range out {
		for _, b := range out[i+1:] {
			if marksOverlap(a, b) {
				return nil, errors.New("connmark: mark selectors overlap")
			}
		}
	}
	return out, nil
}

func marksOverlap(a, b Mark) bool {
	common := a.Mask & b.Mask
	return (a.Value & common) == (b.Value & common)
}

func saveMarkExprs(mark Mark) []expr.Any {
	return append(matchMetaMarkExprs(mark), setCTMarkExprs(mark.Value)...)
}

func restoreMarkExprs(mark Mark) []expr.Any {
	return append(matchCTMarkExprs(mark), setMetaMarkExprs(mark.Value)...)
}

func matchMetaMarkExprs(mark Mark) []expr.Any {
	return matchMarkExprs(
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		mark,
	)
}

func matchCTMarkExprs(mark Mark) []expr.Any {
	return matchMarkExprs(
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		mark,
	)
}

func matchMarkExprs(load expr.Any, mark Mark) []expr.Any {
	return []expr.Any{
		load,
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(mark.Mask),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(mark.Value & mark.Mask),
		},
	}
}

func setCTMarkExprs(mark uint32) []expr.Any {
	return []expr.Any{
		immediateMark(mark),
		&expr.Ct{
			Key:            expr.CtKeyMARK,
			Register:       1,
			SourceRegister: true,
		},
	}
}

func setMetaMarkExprs(mark uint32) []expr.Any {
	return []expr.Any{
		immediateMark(mark),
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			Register:       1,
			SourceRegister: true,
		},
	}
}

func immediateMark(mark uint32) expr.Any {
	return &expr.Immediate{
		Register: 1,
		Data:     binaryutil.NativeEndian.PutUint32(mark),
	}
}
