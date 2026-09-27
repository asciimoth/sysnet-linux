//go:build linux

package linux

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/multirule"
)

type socketMatcher struct {
	mu            sync.Mutex
	closed        bool
	tracker       *multirule.Tracker
	ownerLookup   func(sockowner.FlowTuple) (*sockowner.SocketOwner, error)
	ruleIDs       []uint64
	direct        func(*sockowner.SocketOwner) bool
	process       func(pmark.ProcessInfo) bool
	processFields matcherProcessFields
}

// BuildMatcher builds a socket-owner based matcher for LocalNet/TUN flows.
func (s *System) BuildMatcher(rule sysnet.Rule) (sysnet.Matcher, error) {
	key := sysnet.MatcherProfileKey{
		Family:    sysnet.FamilyIPv4,
		Transport: sysnet.TransportTCP,
	}
	if err := s.CheckRule(
		rule,
		sysnet.RuleContext{Matcher: &key},
	).Err(); err != nil {
		return nil, err
	}
	compiled, err := compileRule(rule)
	if err != nil {
		return nil, err
	}
	m := &socketMatcher{
		tracker:       s.ruleTracker,
		ownerLookup:   s.ownerLookup,
		direct:        compiled.owner,
		process:       compiled.process,
		processFields: compiled.matcherFields,
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
	var processErr error
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
		if m.process == nil || m.processFields == 0 {
			continue
		}
		info, err := readMatcherProcessInfo(pid32, m.processFields)
		if err != nil {
			processErr = errors.Join(processErr, err)
			continue
		}
		if m.process(info) {
			return true, nil
		}
	}
	return false, processErr
}

// readMatcherProcessInfo reads one bounded procfs entry. This lets command-line
// and absolute executable rules work even when p-mark is not active. It also
// keeps a procfs permission or lifetime race distinct from a confirmed
// nonmatch.
func readMatcherProcessInfo(
	pid uint32,
	fields matcherProcessFields,
) (pmark.ProcessInfo, error) {
	procDir := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))
	info := pmark.ProcessInfo{Key: pmark.ProcessKey{Tgid: pid}}
	if fields&matcherProcessComm != 0 {
		// #nosec G304 -- the root is fixed and pid contains only decimal digits.
		comm, err := os.ReadFile(filepath.Join(procDir, "comm"))
		if err != nil {
			return pmark.ProcessInfo{}, fmt.Errorf(
				"read process %d comm: %w",
				pid,
				err,
			)
		}
		info.Comm = strings.TrimSuffix(string(comm), "\n")
	}
	if fields&matcherProcessCmdline != 0 {
		// #nosec G304 -- the root is fixed and pid contains only decimal digits.
		cmdline, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
		if err != nil {
			return pmark.ProcessInfo{}, fmt.Errorf(
				"read process %d command line: %w",
				pid,
				err,
			)
		}
		parts := bytes.Split(bytes.Trim(cmdline, "\x00"), []byte{0})
		args := make([]string, 0, len(parts))
		for _, part := range parts {
			if len(part) != 0 {
				args = append(args, string(part))
			}
		}
		info.Cmdline = strings.Join(args, " ")
	}
	if fields&matcherProcessExecutable != 0 {
		executable, err := os.Readlink(filepath.Join(procDir, "exe"))
		if err != nil {
			return pmark.ProcessInfo{}, fmt.Errorf(
				"read process %d executable: %w",
				pid,
				err,
			)
		}
		info.Exe = executable
	}
	return info, nil
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
