// nolint
package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/asciimoth/sysnet-linux/dns/resolvconffile"
)

func TestDebianResolvconfForwardsToOriginalAfterSetDNS(t *testing.T) {
	upstream := startTestDNSUpstream(t, [4]byte{10, 2, 0, 1})
	env := newFakeDebianResolvconfEnv(
		"nameserver " + upstream.addrPort.Addr().String() + "\n",
	)
	env.dial = redirectDNSDial(upstream.addrPort)

	r, err := NewDebianResolvconf(env.env(), "sysnet-linux")
	if err != nil {
		t.Fatalf("NewDebianResolvconf: %v", err)
	}
	defer closeDebianResolvconf(t, r)

	assertAResponse(t, r, "before.example.", [4]byte{10, 2, 0, 1})

	managed := netip.MustParseAddr("100.64.0.1")
	if err := r.SetDNS(managed); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	assertDebianResolvconfCommand(
		t,
		env.commands[0],
		"resolvconf",
		[]string{"-a", "sysnet-linux"},
		managed,
	)
	assertAResponse(t, r, "after.example.", [4]byte{10, 2, 0, 1})
}

func TestDebianResolvconfSetDNSCanBeRepeatedAndAvoidsManagedLoop(t *testing.T) {
	upstream := startTestDNSUpstream(t, [4]byte{10, 2, 0, 2})
	managedA := netip.MustParseAddr("100.64.0.1")
	managedB := netip.MustParseAddr("100.64.0.2")
	env := newFakeDebianResolvconfEnv(strings.Join([]string{
		"nameserver " + managedA.String(),
		"nameserver " + upstream.addrPort.Addr().String(),
		"",
	}, "\n"))
	env.dial = redirectDNSDial(upstream.addrPort)

	r, err := NewDebianResolvconf(env.env(), "sysnet-linux")
	if err != nil {
		t.Fatalf("NewDebianResolvconf: %v", err)
	}
	defer closeDebianResolvconf(t, r)

	if err := r.SetDNS(managedA); err != nil {
		t.Fatalf("SetDNS(A): %v", err)
	}
	if err := r.SetDNS(managedB); err != nil {
		t.Fatalf("SetDNS(B): %v", err)
	}
	if len(env.commands) != 2 {
		t.Fatalf("commands = %d, want 2", len(env.commands))
	}
	assertDebianResolvconfCommand(
		t,
		env.commands[1],
		"resolvconf",
		[]string{"-a", "sysnet-linux"},
		managedB,
	)
	assertAResponse(t, r, "repeat.example.", [4]byte{10, 2, 0, 2})
}

func TestDebianResolvconfUnsetDNSIsIdempotent(t *testing.T) {
	env := newFakeDebianResolvconfEnv("nameserver 192.0.2.1\n")
	r, err := NewDebianResolvconf(
		env.env(),
		"sysnet-linux",
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewDebianResolvconf: %v", err)
	}
	defer closeDebianResolvconf(t, r)

	if err := r.SetDNS(netip.MustParseAddr("100.64.0.1")); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	if err := r.UnsetDNS(); err != nil {
		t.Fatalf("UnsetDNS: %v", err)
	}
	if err := r.UnsetDNS(); err != nil {
		t.Fatalf("second UnsetDNS: %v", err)
	}
	if len(env.commands) != 2 {
		t.Fatalf("commands = %d, want add and one delete", len(env.commands))
	}
	assertFakeCommand(
		t,
		env.commands[1],
		"resolvconf",
		[]string{"-d", "sysnet-linux"},
		"",
	)
}

func TestDebianResolvconfCloseDeletesActiveManagedState(t *testing.T) {
	env := newFakeDebianResolvconfEnv("nameserver 192.0.2.1\n")
	r, err := NewDebianResolvconf(
		env.env(),
		"sysnet-linux",
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewDebianResolvconf: %v", err)
	}
	if err := r.SetDNS(netip.MustParseAddr("100.64.0.1")); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if len(env.commands) != 2 {
		t.Fatalf("commands = %d, want add and delete", len(env.commands))
	}
	assertFakeCommand(
		t,
		env.commands[1],
		"resolvconf",
		[]string{"-d", "sysnet-linux"},
		"",
	)
}

func TestDebianResolvconfUsesFallbackWhenNoOriginalUpstream(t *testing.T) {
	fallback := startTestDNSUpstream(t, [4]byte{10, 2, 0, 3})
	env := newFakeDebianResolvconfEnv("# no nameservers\n")

	r, err := NewDebianResolvconf(env.env(), "sysnet-linux", fallback.addrPort)
	if err != nil {
		t.Fatalf("NewDebianResolvconf: %v", err)
	}
	defer closeDebianResolvconf(t, r)

	assertAResponse(t, r, "fallback.example.", [4]byte{10, 2, 0, 3})
}

func TestDebianResolvconfSurfacesCommandErrors(t *testing.T) {
	env := newFakeDebianResolvconfEnv("nameserver 192.0.2.1\n")
	env.commandErr = errors.New("resolvconf failed")
	r, err := NewDebianResolvconf(
		env.env(),
		"sysnet-linux",
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewDebianResolvconf: %v", err)
	}
	defer closeDebianResolvconf(t, r)

	if err := r.SetDNS(netip.MustParseAddr("100.64.0.1")); err == nil {
		t.Fatal("SetDNS error = nil, want command error")
	}
}

func closeDebianResolvconf(t *testing.T, r *DebianResolvconf) {
	t.Helper()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func assertDebianResolvconfCommand(
	t *testing.T,
	cmd fakeCommand,
	wantName string,
	wantArgs []string,
	wantServer netip.Addr,
) {
	t.Helper()
	cfg, err := resolvconffile.Parse(strings.NewReader(cmd.stdin))
	if err != nil {
		t.Fatalf("parse command stdin: %v", err)
	}
	if len(cfg.Nameservers) != 1 || cfg.Nameservers[0] != wantServer {
		t.Fatalf("nameservers = %v, want only %s", cfg.Nameservers, wantServer)
	}
	if !strings.Contains(cmd.stdin, "generated by "+debianResolvconfOwner) {
		t.Fatalf("stdin does not look provider-owned:\n%s", cmd.stdin)
	}
	assertFakeCommand(t, cmd, wantName, wantArgs, cmd.stdin)
}

func assertFakeCommand(
	t *testing.T,
	cmd fakeCommand,
	wantName string,
	wantArgs []string,
	wantStdin string,
) {
	t.Helper()
	if cmd.name != wantName {
		t.Fatalf("command name = %q, want %q", cmd.name, wantName)
	}
	if !reflect.DeepEqual(cmd.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", cmd.args, wantArgs)
	}
	if cmd.stdin != wantStdin {
		t.Fatalf("command stdin = %q, want %q", cmd.stdin, wantStdin)
	}
}

type fakeDebianResolvconfEnv struct {
	files      map[string][]byte
	readErr    error
	commandErr error
	dial       func(context.Context, string, string) (net.Conn, error)
	commands   []fakeCommand
}

type fakeCommand struct {
	name  string
	args  []string
	stdin string
	err   error
}

func newFakeDebianResolvconfEnv(contents string) *fakeDebianResolvconfEnv {
	return &fakeDebianResolvconfEnv{
		files: map[string][]byte{
			resolvconffile.Path: []byte(contents),
		},
	}
}

func (e *fakeDebianResolvconfEnv) env() Env {
	return Env{
		ReadFile:       e.readFile,
		Dial:           e.dial,
		CommandContext: e.commandContext,
	}
}

func (e *fakeDebianResolvconfEnv) readFile(path string) ([]byte, error) {
	if e.readErr != nil {
		return nil, e.readErr
	}
	bs, ok := e.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), bs...), nil
}

func (e *fakeDebianResolvconfEnv) commandContext(
	_ context.Context,
	name string,
	args ...string,
) Cmd {
	return &fakeCmd{
		env:  e,
		name: name,
		args: append([]string(nil), args...),
	}
}

type fakeCmd struct {
	env   *fakeDebianResolvconfEnv
	name  string
	args  []string
	stdin io.Reader
}

func (c *fakeCmd) SetStdin(r io.Reader) {
	c.stdin = r
}

func (c *fakeCmd) Run() error {
	var stdin []byte
	if c.stdin != nil {
		stdin, _ = io.ReadAll(c.stdin)
	}
	c.env.commands = append(c.env.commands, fakeCommand{
		name:  c.name,
		args:  append([]string(nil), c.args...),
		stdin: string(stdin),
		err:   c.env.commandErr,
	})
	return c.env.commandErr
}
