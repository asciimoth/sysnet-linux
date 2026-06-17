// nolint
package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/sysnet-linux/dns/resolvconffile"
)

func TestDirectForwardsToOriginalAfterSetDNS(t *testing.T) {
	upstream := startTestDNSUpstream(t, [4]byte{10, 1, 0, 1})
	env := newFakeDirectEnv(
		"nameserver " + upstream.addrPort.Addr().String() + "\n",
	)

	d, err := NewDirect(
		env.env(),
		testNetwork(),
		redirectDNSNetwork(upstream.addrPort),
	)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	defer closeDirect(t, d)

	assertAResponse(t, d, "before.example.", [4]byte{10, 1, 0, 1})

	managed := netip.MustParseAddr("100.64.0.1")
	if err := d.SetDNS(managed); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	assertFakeResolvconf(t, env, managed)
	assertAResponse(t, d, "after.example.", [4]byte{10, 1, 0, 1})
}

func TestDirectSetDNSCanBeRepeatedAndAvoidsManagedLoop(t *testing.T) {
	upstream := startTestDNSUpstream(t, [4]byte{10, 1, 0, 2})
	managedA := netip.MustParseAddr("100.64.0.1")
	managedB := netip.MustParseAddr("100.64.0.2")
	env := newFakeDirectEnv(strings.Join([]string{
		"nameserver " + managedA.String(),
		"nameserver " + upstream.addrPort.Addr().String(),
		"",
	}, "\n"))

	d, err := NewDirect(
		env.env(),
		testNetwork(),
		redirectDNSNetwork(upstream.addrPort),
	)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	defer closeDirect(t, d)

	if err := d.SetDNS(managedA); err != nil {
		t.Fatalf("SetDNS(A): %v", err)
	}
	if err := d.SetDNS(managedB); err != nil {
		t.Fatalf("SetDNS(B): %v", err)
	}
	assertFakeResolvconf(t, env, managedB)
	assertAResponse(t, d, "repeat.example.", [4]byte{10, 1, 0, 2})
}

func TestDirectUnsetDNSIsIdempotentAndRestoresOriginal(t *testing.T) {
	original := "nameserver 192.0.2.1\nsearch example.com\n"
	env := newFakeDirectEnv(original)
	d, err := NewDirect(
		env.env(),
		testNetwork(),
		testNetwork(),
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	defer closeDirect(t, d)

	if err := d.SetDNS(netip.MustParseAddr("100.64.0.1")); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	if err := d.UnsetDNS(); err != nil {
		t.Fatalf("UnsetDNS: %v", err)
	}
	if err := d.UnsetDNS(); err != nil {
		t.Fatalf("second UnsetDNS: %v", err)
	}
	if got := string(env.files[resolvconffile.Path]); got != original {
		t.Fatalf("resolv.conf = %q, want original %q", got, original)
	}
}

func TestDirectCloseRollsBackAbsentOriginal(t *testing.T) {
	env := newFakeDirectEnvAbsent()
	d, err := NewDirect(
		env.env(),
		testNetwork(),
		testNetwork(),
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	if err := d.SetDNS(netip.MustParseAddr("100.64.0.1")); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := env.files[resolvconffile.Path]; ok {
		t.Fatal("resolv.conf still exists after Close, want removed")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestDirectSkipsRollbackWhenCurrentFileIsExternallyChanged(t *testing.T) {
	env := newFakeDirectEnv("nameserver 192.0.2.1\n")
	d, err := NewDirect(
		env.env(),
		testNetwork(),
		testNetwork(),
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	defer closeDirect(t, d)

	if err := d.SetDNS(netip.MustParseAddr("100.64.0.1")); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	external := "nameserver 203.0.113.1\n"
	env.files[resolvconffile.Path] = []byte(external)
	if err := d.UnsetDNS(); err != nil {
		t.Fatalf("UnsetDNS: %v", err)
	}
	if got := string(env.files[resolvconffile.Path]); got != external {
		t.Fatalf("resolv.conf = %q, want external change %q", got, external)
	}
}

func TestDirectUsesFallbackWhenNoOriginalUpstream(t *testing.T) {
	fallback := startTestDNSUpstream(t, [4]byte{10, 1, 0, 3})
	env := newFakeDirectEnv("# no nameservers\n")

	d, err := NewDirect(
		env.env(),
		testNetwork(),
		testNetwork(),
		fallback.addrPort,
	)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	defer closeDirect(t, d)

	assertAResponse(t, d, "fallback.example.", [4]byte{10, 1, 0, 3})
}

func TestDirectSurfacesFileErrors(t *testing.T) {
	env := newFakeDirectEnv("nameserver 192.0.2.1\n")
	env.writeErr = errors.New("write failed")
	d, err := NewDirect(
		env.env(),
		testNetwork(),
		testNetwork(),
		netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	defer closeDirect(t, d)

	if err := d.SetDNS(netip.MustParseAddr("100.64.0.1")); err == nil {
		t.Fatal("SetDNS error = nil, want write error")
	}
}

func closeDirect(t *testing.T, d *Direct) {
	t.Helper()
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func assertFakeResolvconf(
	t *testing.T,
	env *fakeDirectEnv,
	want netip.Addr,
) {
	t.Helper()
	bs, ok := env.files[resolvconffile.Path]
	if !ok {
		t.Fatal("resolv.conf missing")
	}
	cfg, err := resolvconffile.Parse(strings.NewReader(string(bs)))
	if err != nil {
		t.Fatalf("parse resolv.conf: %v", err)
	}
	if len(cfg.Nameservers) != 1 || cfg.Nameservers[0] != want {
		t.Fatalf("nameservers = %v, want only %s", cfg.Nameservers, want)
	}
	if !directResolvconfOwned(bs) {
		t.Fatalf("resolv.conf does not look provider-owned:\n%s", bs)
	}
}

type fakeDirectEnv struct {
	files     map[string][]byte
	readErr   error
	writeErr  error
	removeErr error
}

func newFakeDirectEnv(contents string) *fakeDirectEnv {
	return &fakeDirectEnv{
		files: map[string][]byte{
			resolvconffile.Path: []byte(contents),
		},
	}
}

func newFakeDirectEnvAbsent() *fakeDirectEnv {
	return &fakeDirectEnv{files: make(map[string][]byte)}
}

func (e *fakeDirectEnv) env() Env {
	return Env{
		ReadFile:  e.readFile,
		WriteFile: e.writeFile,
		Remove:    e.remove,
	}
}

func (e *fakeDirectEnv) readFile(path string) ([]byte, error) {
	if e.readErr != nil {
		return nil, e.readErr
	}
	bs, ok := e.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), bs...), nil
}

func (e *fakeDirectEnv) writeFile(
	path string,
	data []byte,
	_ os.FileMode,
) error {
	if e.writeErr != nil {
		return e.writeErr
	}
	e.files[path] = append([]byte(nil), data...)
	return nil
}

func (e *fakeDirectEnv) remove(path string) error {
	if e.removeErr != nil {
		return e.removeErr
	}
	if _, ok := e.files[path]; !ok {
		return os.ErrNotExist
	}
	delete(e.files, path)
	return nil
}

func testNetwork() gonnect.Network {
	return gonnect.NativeConfig{}.Build()
}

type redirectNetwork struct {
	gonnect.Network
	target netip.AddrPort
}

func redirectDNSNetwork(target netip.AddrPort) gonnect.Network {
	return redirectNetwork{
		Network: testNetwork(),
		target:  target,
	}
}

func (n redirectNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err == nil && port == "53" {
		address = n.target.String()
	}
	return n.Network.Dial(ctx, network, address)
}
