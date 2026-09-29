//nolint:testpackage // Tests exercise package-private routing and fake environments.
package dns

import (
	"errors"
	"net/netip"
	"testing"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-linux/dns/resolvconffile"
)

func TestReviewResolvedChoosesLongestMatchingDomain(t *testing.T) {
	router := resolvedRouteFunc([]resolvedUpstreamRoute{
		{name: "public", domains: []string{".", "verylong.public.example."}},
		{name: "private", domains: []string{"corp.example."}},
	})
	got := router(
		&gdns.Message{
			Questions: []gdns.Question{{Name: "secret.corp.example."}},
		},
	)
	if got != "private" {
		t.Fatalf("private query routed to %q; want private", got)
	}
}

func TestResolvedRouteChoosesBestDomainForEachQuestion(t *testing.T) {
	router := resolvedRouteFunc([]resolvedUpstreamRoute{
		{name: "mixed", domains: []string{".", "long.unrelated.example."}},
		{name: "corp", domains: []string{"corp.example."}},
		{name: "deep", domains: []string{"deep.corp.example."}},
	})
	tests := []struct {
		name string
		want string
	}{
		{"host.deep.corp.example.", "deep"},
		{"host.corp.example.", "corp"},
		{"public.example.", "mixed"},
	}
	for _, test := range tests {
		msg := &gdns.Message{Questions: []gdns.Question{{Name: test.name}}}
		if got := router(msg); got != test.want {
			t.Errorf("route(%q) = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestReviewDNSRollbackCanRetry(t *testing.T) {
	original := "nameserver 192.0.2.1\n"
	env := newFakeDirectEnv(original)
	d, err := NewDirect(env.env(), testNetwork(), testNetwork())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.SetDNS(netip.MustParseAddr("100.64.0.1")); err != nil {
		t.Fatal(err)
	}
	env.writeErr = errors.New("temporary restore failure")
	if err := d.UnsetDNS(); err == nil {
		t.Fatal("expected injected failure")
	}
	env.writeErr = nil
	if err := d.UnsetDNS(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if got := string(env.files[resolvconffile.Path]); got != original {
		t.Fatalf("retry and Close left managed DNS installed: %q", got)
	}
}

func TestDirectCloseRetriesFailedRollback(t *testing.T) {
	original := "nameserver 192.0.2.1\n"
	env := newFakeDirectEnv(original)
	d, err := NewDirect(env.env(), testNetwork(), testNetwork())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetDNS(netip.MustParseAddr("100.64.0.1")); err != nil {
		t.Fatal(err)
	}
	env.writeErr = errors.New("temporary restore failure")
	if err := d.Close(); err == nil {
		t.Fatal("first Close succeeded, want restore error")
	}
	env.writeErr = nil
	if err := d.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if got := string(env.files[resolvconffile.Path]); got != original {
		t.Fatalf("resolv.conf = %q, want %q", got, original)
	}
}

func TestResolvconfBackendsRetryFailedUnset(t *testing.T) {
	tests := []struct {
		name string
		new  func(*fakeDebianResolvconfEnv) (DNSProvider, error)
	}{
		{
			name: "Debian",
			new: func(env *fakeDebianResolvconfEnv) (DNSProvider, error) {
				return NewDebianResolvconf(
					env.env(), testNetwork(), testNetwork(), "test",
					netip.MustParseAddrPort("127.0.0.1:53"),
				)
			},
		},
		{
			name: "openresolv",
			new: func(env *fakeDebianResolvconfEnv) (DNSProvider, error) {
				return NewOpenresolv(
					env.env(), testNetwork(), testNetwork(), "test",
					netip.MustParseAddrPort("127.0.0.1:53"),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := newFakeDebianResolvconfEnv("nameserver 192.0.2.1\n")
			provider, err := test.new(env)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = provider.Close() })
			if err := provider.SetDNS(
				netip.MustParseAddr("100.64.0.1"),
			); err != nil {
				t.Fatal(err)
			}
			env.commandErr = errors.New("temporary delete failure")
			if err := provider.UnsetDNS(); err == nil {
				t.Fatal("first UnsetDNS succeeded, want command error")
			}
			env.commandErr = nil
			if err := provider.UnsetDNS(); err != nil {
				t.Fatalf("retry UnsetDNS: %v", err)
			}
			if len(env.commands) != 3 {
				t.Fatalf(
					"commands = %d, want add and two delete attempts",
					len(env.commands),
				)
			}
		})
	}
}

func TestResolvconfBackendsRetryFailedCloseCleanup(t *testing.T) {
	tests := []struct {
		name string
		new  func(*fakeDebianResolvconfEnv) (DNSProvider, error)
	}{
		{
			name: "Debian",
			new: func(env *fakeDebianResolvconfEnv) (DNSProvider, error) {
				return NewDebianResolvconf(
					env.env(), testNetwork(), testNetwork(), "test",
					netip.MustParseAddrPort("127.0.0.1:53"),
				)
			},
		},
		{
			name: "openresolv",
			new: func(env *fakeDebianResolvconfEnv) (DNSProvider, error) {
				return NewOpenresolv(
					env.env(), testNetwork(), testNetwork(), "test",
					netip.MustParseAddrPort("127.0.0.1:53"),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := newFakeDebianResolvconfEnv("nameserver 192.0.2.1\n")
			provider, err := test.new(env)
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.SetDNS(
				netip.MustParseAddr("100.64.0.1"),
			); err != nil {
				t.Fatal(err)
			}
			env.commandErr = errors.New("temporary delete failure")
			if err := provider.Close(); err == nil {
				t.Fatal("first Close succeeded, want command error")
			}
			env.commandErr = nil
			if err := provider.Close(); err != nil {
				t.Fatalf("retry Close: %v", err)
			}
			if len(env.commands) != 3 {
				t.Fatalf(
					"commands = %d, want add and two delete attempts",
					len(env.commands),
				)
			}
		})
	}
}
