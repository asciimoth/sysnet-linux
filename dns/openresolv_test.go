// nolint
package dns

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/asciimoth/sysnet-linux/dns/resolvconffile"
)

func TestOpenresolvForwardsToOriginalAfterSetDNS(t *testing.T) {
	upstream := startTestDNSUpstream(t, [4]byte{10, 3, 0, 1})
	env := newFakeDebianResolvconfEnv(
		"nameserver " + upstream.addrPort.Addr().String() + "\n",
	)

	r, err := NewOpenresolv(
		env.env(),
		testNetwork(),
		redirectDNSNetwork(upstream.addrPort),
		"sysnet-linux",
	)
	if err != nil {
		t.Fatalf("NewOpenresolv: %v", err)
	}
	defer closeOpenresolv(t, r)

	assertAResponse(t, r, "before.example.", [4]byte{10, 3, 0, 1})

	managed := netip.MustParseAddr("100.64.0.1")
	if err := r.SetDNS(managed); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	assertOpenresolvCommand(
		t,
		env.commands[0],
		"resolvconf",
		[]string{"-m", "0", "-x", "-a", "sysnet-linux"},
		managed,
	)
	assertAResponse(t, r, "after.example.", [4]byte{10, 3, 0, 1})
}

func TestOpenresolvSetDNSCanBeRepeatedAndAvoidsManagedLoop(t *testing.T) {
	upstream := startTestDNSUpstream(t, [4]byte{10, 3, 0, 2})
	managedA := netip.MustParseAddr("100.64.0.1")
	managedB := netip.MustParseAddr("100.64.0.2")
	env := newFakeDebianResolvconfEnv(strings.Join([]string{
		"nameserver " + managedA.String(),
		"nameserver " + upstream.addrPort.Addr().String(),
		"",
	}, "\n"))

	r, err := NewOpenresolv(
		env.env(),
		testNetwork(),
		redirectDNSNetwork(upstream.addrPort),
		"sysnet-linux",
	)
	if err != nil {
		t.Fatalf("NewOpenresolv: %v", err)
	}
	defer closeOpenresolv(t, r)

	if err := r.SetDNS(managedA); err != nil {
		t.Fatalf("SetDNS(A): %v", err)
	}
	if err := r.SetDNS(managedB); err != nil {
		t.Fatalf("SetDNS(B): %v", err)
	}
	if len(env.commands) != 2 {
		t.Fatalf("commands = %d, want 2", len(env.commands))
	}
	assertOpenresolvCommand(
		t,
		env.commands[1],
		"resolvconf",
		[]string{"-m", "0", "-x", "-a", "sysnet-linux"},
		managedB,
	)
	assertAResponse(t, r, "repeat.example.", [4]byte{10, 3, 0, 2})
}

func TestOpenresolvUnsetDNSIsIdempotent(t *testing.T) {
	env := newFakeDebianResolvconfEnv("nameserver 192.0.2.1\n")
	r, err := NewOpenresolv(
		env.env(),
		testNetwork(),
		testNetwork(),
		"sysnet-linux",
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewOpenresolv: %v", err)
	}
	defer closeOpenresolv(t, r)

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
		[]string{"-f", "-d", "sysnet-linux"},
		"",
	)
}

func TestOpenresolvCloseDeletesActiveManagedState(t *testing.T) {
	env := newFakeDebianResolvconfEnv("nameserver 192.0.2.1\n")
	r, err := NewOpenresolv(
		env.env(),
		testNetwork(),
		testNetwork(),
		"sysnet-linux",
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewOpenresolv: %v", err)
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
		[]string{"-f", "-d", "sysnet-linux"},
		"",
	)
}

func TestOpenresolvUsesFallbackWhenNoOriginalUpstream(t *testing.T) {
	fallback := startTestDNSUpstream(t, [4]byte{10, 3, 0, 3})
	env := newFakeDebianResolvconfEnv("# no nameservers\n")

	r, err := NewOpenresolv(
		env.env(),
		testNetwork(),
		testNetwork(),
		"sysnet-linux",
		fallback.addrPort,
	)
	if err != nil {
		t.Fatalf("NewOpenresolv: %v", err)
	}
	defer closeOpenresolv(t, r)

	assertAResponse(t, r, "fallback.example.", [4]byte{10, 3, 0, 3})
}

func TestOpenresolvSurfacesCommandErrors(t *testing.T) {
	env := newFakeDebianResolvconfEnv("nameserver 192.0.2.1\n")
	env.commandErr = errors.New("resolvconf failed")
	r, err := NewOpenresolv(
		env.env(),
		testNetwork(),
		testNetwork(),
		"sysnet-linux",
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewOpenresolv: %v", err)
	}
	defer closeOpenresolv(t, r)

	if err := r.SetDNS(netip.MustParseAddr("100.64.0.1")); err == nil {
		t.Fatal("SetDNS error = nil, want command error")
	}
}

func closeOpenresolv(t *testing.T, r *Openresolv) {
	t.Helper()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func assertOpenresolvCommand(
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
	if !strings.Contains(cmd.stdin, "generated by "+openresolvOwner) {
		t.Fatalf("stdin does not look provider-owned:\n%s", cmd.stdin)
	}
	assertFakeCommand(t, cmd, wantName, wantArgs, cmd.stdin)
}
