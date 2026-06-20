//go:build linux

package linux

import (
	"net"
	"sync"

	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/multirule"
)

type socketMatcher struct {
	mu          sync.Mutex
	closed      bool
	tracker     *multirule.Tracker
	ownerLookup func(sockowner.FlowTuple) (*sockowner.SocketOwner, error)
	ruleIDs     []uint64
	direct      func(*sockowner.SocketOwner) bool
}

// BuildMatcher builds a socket-owner based matcher for LocalNet/TUN flows.
func (s *System) BuildMatcher(rule sysnet.Rule) (sysnet.Matcher, error) {
	if !s.features.MatcherRules ||
		s.ruleTracker == nil ||
		s.ownerLookup == nil {
		return nil, sysnet.ErrNotSupported
	}
	compiled, err := compileRule(rule)
	if err != nil {
		return nil, err
	}
	m := &socketMatcher{
		tracker:     s.ruleTracker,
		ownerLookup: s.ownerLookup,
		direct:      compiled.owner,
	}
	if compiled.process != nil {
		id := s.ruleTracker.RegisterRule(func(info pmark.ProcessInfo) bool {
			return compiled.process(info)
		})
		m.ruleIDs = append(m.ruleIDs, id)
	}
	return m, nil
}

func (m *socketMatcher) Match(flow sockowner.FlowTuple) (bool, error) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return false, net.ErrClosed
	}
	owner, err := m.ownerLookup(flow)
	if err != nil || owner == nil {
		return false, err
	}
	if m.direct != nil && m.direct(owner) {
		return true, nil
	}
	for _, pid := range owner.PIDs {
		pid32, ok := pidToUint32(pid)
		if !ok {
			continue
		}
		for _, id := range m.ruleIDs {
			if m.tracker.MatchesPID(pid32, id) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (m *socketMatcher) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	ids := append([]uint64(nil), m.ruleIDs...)
	m.ruleIDs = nil
	m.mu.Unlock()
	for _, id := range ids {
		m.tracker.UnregisterRule(id)
	}
	return nil
}
