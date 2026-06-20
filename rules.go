//go:build linux

package linux

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	pmark "github.com/asciimoth/p-mark"
)

const (
	maxExecCompletions     = 10
	maxExecCompletionScan  = 512
	execCompletionReadSize = 32
)

var supportedRules = []sysnet.RuleTypeInfo{
	{Type: "comm", Description: "Process command regexp matcher."},
	{Type: "exec", Description: "Process executable path matcher."},
	{Type: "cmd", Description: "Process command line regexp matcher."},
	{Type: "pid", Description: "Process PID."},
	{Type: "user", Description: "Name of user owning process."},
	{Type: "uid", Description: "UID owning process."},
	{Type: "group", Description: "Name of group owning process."},
	{Type: "gid", Description: "GID owning process."},
}

type compiledRule struct {
	process func(pmark.ProcessInfo) bool
	owner   func(*sockowner.SocketOwner) bool
}

// ListRules reports rule types supported by enabled integrations.
func (s *System) ListRules() sysnet.RulesInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var info sysnet.RulesInfo
	if s.tunRulesSupportedLocked() {
		info.TunRules = append(info.TunRules, supportedRules...)
	}
	if s.features.MatcherRules && s.ruleTracker != nil && s.ownerLookup != nil {
		info.MatcherRules = append(info.MatcherRules, supportedRules...)
	}
	return info
}

func (s *System) tunRulesSupportedLocked() bool {
	return s.features.TunRules &&
		s.features.Pmark &&
		s.pmark != nil &&
		s.ruleTracker != nil
}

// RuleVerify checks whether a rule value is syntactically valid.
func (s *System) RuleVerify(rule sysnet.Rule) bool {
	_, err := compileRule(rule)
	return err == nil
}

// RuleCompl returns quick best-effort completions for rules whose value space is
// enumerable without process traversal. Account completions are read from the
// local passwd and group databases, and executable path completion inspects only
// one directory with a small scan cap so large filesystems cannot make
// completion expensive.
func (s *System) RuleCompl(rule sysnet.Rule) (out []string) {
	defer func() {
		if r := recover(); r != nil {
			s.logCompletionErrorf("panic completing %s rule: %v", rule.Type, r)
			out = nil
		}
	}()

	var err error
	switch rule.Type {
	case "user":
		out, err = completePasswdRule(rule.Rule, false, "/etc/passwd")
	case "uid":
		out, err = completePasswdRule(rule.Rule, true, "/etc/passwd")
	case "group":
		out, err = completeGroupRule(rule.Rule, false, "/etc/group")
	case "gid":
		out, err = completeGroupRule(rule.Rule, true, "/etc/group")
	case "exec", "exe":
		out, err = completeExecRule(rule.Rule)
	default:
		return nil
	}
	if err != nil {
		s.logCompletionErrorf(
			"complete %s rule %q: %v",
			rule.Type,
			rule.Rule,
			err,
		)
		return nil
	}
	return out
}

func (s *System) logCompletionErrorf(format string, args ...any) {
	if s == nil || s.logf == nil {
		return
	}
	s.logf("rule completion: "+format, args...)
}

func completePasswdRule(
	prefix string,
	ids bool,
	path string,
) ([]string, error) {
	return completeColonFileRule(prefix, ids, path, 0, 2)
}

func completeGroupRule(prefix string, ids bool, path string) ([]string, error) {
	return completeColonFileRule(prefix, ids, path, 0, 2)
}

func completeColonFileRule(
	prefix string,
	ids bool,
	path string,
	nameField int,
	idField int,
) ([]string, error) {
	// #nosec G304 -- completion reads fixed account database paths.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0)
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) <= nameField || len(fields) <= idField {
			continue
		}
		value := fields[nameField]
		if ids {
			value = fields[idField]
		}
		if value == "" || seen[value] || !strings.HasPrefix(value, prefix) {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, nil
	}
	sort.Strings(values)
	return values, nil
}

func completeExecRule(prefix string) (values []string, err error) {
	if !filepath.IsAbs(prefix) {
		return nil, nil
	}
	dir, base := execCompletionDirBase(prefix)
	// #nosec G304 -- executable completion intentionally inspects the requested directory.
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	for scanned := 0; scanned < maxExecCompletionScan &&
		len(values) < maxExecCompletions; {
		want := min(
			execCompletionReadSize,
			maxExecCompletionScan-scanned,
		)
		names, err := f.Readdirnames(want)
		scanned += len(names)
		for _, name := range names {
			if name == "." || name == ".." || !strings.HasPrefix(name, base) {
				continue
			}
			values = append(values, filepath.Join(dir, name))
			if len(values) == maxExecCompletions {
				break
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(names) == 0 {
			break
		}
	}
	if len(values) == 0 {
		return nil, nil
	}
	sort.Strings(values)
	return values, nil
}

func execCompletionDirBase(prefix string) (dir string, base string) {
	if strings.HasSuffix(prefix, string(os.PathSeparator)) {
		return filepath.Clean(prefix), ""
	}
	return filepath.Dir(prefix), filepath.Base(prefix)
}

func compileRule(rule sysnet.Rule) (compiledRule, error) {
	switch rule.Type {
	case "comm":
		re, err := regexp.Compile(rule.Rule)
		if err != nil {
			return compiledRule{}, err
		}
		return compiledRule{
			process: func(info pmark.ProcessInfo) bool { return re.MatchString(info.Comm) },
			owner:   func(owner *sockowner.SocketOwner) bool { return re.MatchString(owner.Comm) },
		}, nil
	case "cmd":
		re, err := regexp.Compile(rule.Rule)
		if err != nil {
			return compiledRule{}, err
		}
		return compiledRule{
			process: func(info pmark.ProcessInfo) bool { return re.MatchString(info.Cmdline) },
			owner:   func(*sockowner.SocketOwner) bool { return false },
		}, nil
	case "exec":
		match, err := compileExec(rule.Rule)
		if err != nil {
			return compiledRule{}, err
		}
		return compiledRule{
			process: func(info pmark.ProcessInfo) bool { return match(info.Exe) },
			owner:   func(owner *sockowner.SocketOwner) bool { return owner.ProcName != "" && match(owner.ProcName) },
		}, nil
	case "pid":
		values, err := parseUint32List(rule.Rule)
		if err != nil {
			return compiledRule{}, err
		}
		return compiledRule{
			process: func(info pmark.ProcessInfo) bool { return values[info.Key.Tgid] },
			owner: func(owner *sockowner.SocketOwner) bool {
				for _, pid := range owner.PIDs {
					pid32, ok := pidToUint32(pid)
					if ok && values[pid32] {
						return true
					}
				}
				return false
			},
		}, nil
	case "user":
		u, err := user.Lookup(rule.Rule)
		if err != nil {
			return compiledRule{}, err
		}
		return compileRule(sysnet.Rule{Type: "uid", Rule: u.Uid})
	case "uid":
		values, err := parseUint32List(rule.Rule)
		if err != nil {
			return compiledRule{}, err
		}
		return compiledRule{
			process: func(info pmark.ProcessInfo) bool {
				uid, _, ok := processStatusIDs(info.Key.Tgid)
				return ok && values[uid]
			},
			owner: func(owner *sockowner.SocketOwner) bool {
				return owner.UID != nil && values[*owner.UID]
			},
		}, nil
	case "group":
		g, err := user.LookupGroup(rule.Rule)
		if err != nil {
			return compiledRule{}, err
		}
		return compileRule(sysnet.Rule{Type: "gid", Rule: g.Gid})
	case "gid":
		values, err := parseUint32List(rule.Rule)
		if err != nil {
			return compiledRule{}, err
		}
		return compiledRule{
			process: func(info pmark.ProcessInfo) bool {
				_, gid, ok := processStatusIDs(info.Key.Tgid)
				return ok && values[gid]
			},
			owner: func(owner *sockowner.SocketOwner) bool {
				return owner.GID != nil && values[*owner.GID]
			},
		}, nil
	default:
		return compiledRule{}, fmt.Errorf(
			"%w: rule type %q",
			sysnet.ErrNotSupported,
			rule.Type,
		)
	}
}

func compileExec(pattern string) (func(string) bool, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty exec rule")
	}
	if strings.HasPrefix(pattern, ".") &&
		(pattern == "." || strings.HasPrefix(pattern, "./") || strings.HasPrefix(pattern, "../")) {
		return nil, fmt.Errorf("relative exec path %q", pattern)
	}
	if strings.Contains(pattern, "/") && !filepath.IsAbs(pattern) {
		return nil, fmt.Errorf("relative exec path %q", pattern)
	}
	if strings.ContainsAny(pattern, "*?[") {
		if _, err := filepath.Match(pattern, pattern); err != nil {
			return nil, err
		}
		return func(exe string) bool {
			ok, _ := filepath.Match(pattern, exe)
			return ok
		}, nil
	}
	if !strings.Contains(pattern, "/") {
		return func(exe string) bool { return strings.HasSuffix(exe, pattern) }, nil
	}
	return func(exe string) bool { return exe == pattern }, nil
}

func parseUint32List(value string) (map[uint32]bool, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty numeric rule")
	}
	out := make(map[uint32]bool, len(fields))
	for _, field := range fields {
		n, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, err
		}
		out[uint32(n)] = true
	}
	return out, nil
}

func pidToUint32(pid int) (uint32, bool) {
	n, err := strconv.ParseUint(strconv.Itoa(pid), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

func processStatusIDs(pid uint32) (uid uint32, gid uint32, ok bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, false
	}
	var gotUID, gotGID bool
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			n, err := strconv.ParseUint(fields[1], 10, 32)
			if err == nil {
				uid, gotUID = uint32(n), true
			}
		case "Gid:":
			n, err := strconv.ParseUint(fields[1], 10, 32)
			if err == nil {
				gid, gotGID = uint32(n), true
			}
		}
	}
	return uid, gid, gotUID && gotGID
}
