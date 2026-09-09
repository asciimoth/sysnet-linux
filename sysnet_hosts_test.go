//go:build linux

package linux_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	gdns "github.com/asciimoth/gonnect/dns"
)

func TestSystemOutNetDialUsesHostsFileBeforeAndAfterDNSChange(t *testing.T) {
	const host = "hosts-outnet.test"
	const localAddress = "127.0.0.2"

	hostsFile := filepath.Join(t.TempDir(), "hosts")
	writeResolverTestHostsFile(
		t,
		hostsFile,
		localAddress+" "+host+"\n",
	)
	listener := listenResolverTestTCP(t, "0.0.0.0:0")
	provider := newResolverTestDNSProvider()
	provider.setHost(host, netip.MustParseAddr("127.0.0.3"))
	system := newResolverTestSystemWithHostsFile(t, provider, hostsFile)

	for _, stage := range []string{"before SetDNS", "after SetDNS"} {
		t.Run(stage, func(t *testing.T) {
			remote := dialResolverTestTCP(
				t,
				system.OutNet(),
				host,
				listener,
			)
			if remote != localAddress {
				t.Fatalf("remote address = %s, want %s", remote, localAddress)
			}
			assertResolverTestNoQuestions(t, provider)
		})

		if stage == "before SetDNS" {
			managed := netip.MustParseAddr("100.64.0.53")
			if err := provider.SetDNS(managed); err != nil {
				t.Fatalf("SetDNS: %v", err)
			}
			provider.setHost(host, netip.MustParseAddr("127.0.0.4"))
		}
	}
}

func TestSystemLocalNetDialUsesHostsFile(t *testing.T) {
	const host = "hosts-localnet.test"
	const localAddress = "127.0.0.2"

	hostsFile := filepath.Join(t.TempDir(), "hosts")
	writeResolverTestHostsFile(
		t,
		hostsFile,
		localAddress+" "+host+"\n",
	)
	listener := listenResolverTestTCP(t, "0.0.0.0:0")
	provider := newResolverTestDNSProvider()
	provider.setHost(host, netip.MustParseAddr("127.0.0.3"))
	system := newResolverTestSystemWithHostsFile(t, provider, hostsFile)

	remote := dialResolverTestTCP(t, system.LocalNet(), host, listener)
	if remote != localAddress {
		t.Fatalf("remote address = %s, want %s", remote, localAddress)
	}
	assertResolverTestNoQuestions(t, provider)
}

func TestSystemOutNetLocalhostRemainsLocal(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		hostsFile := filepath.Join(t.TempDir(), "hosts")
		writeResolverTestHostsFile(t, hostsFile, "")
		listener := listenResolverTestTCP(t, "127.0.0.1:0")
		provider := newResolverTestDNSProvider()
		system := newResolverTestSystemWithHostsFile(t, provider, hostsFile)

		remote := dialResolverTestTCP(
			t,
			system.OutNet(),
			"LOCALHOST.",
			listener,
		)
		if remote != "127.0.0.1" {
			t.Fatalf("remote address = %s, want 127.0.0.1", remote)
		}
		assertResolverTestNoQuestions(t, provider)
	})

	t.Run("IPv6", func(t *testing.T) {
		var listenConfig net.ListenConfig
		listener, err := listenConfig.Listen(
			context.Background(),
			"tcp6",
			"[::1]:0",
		)
		if err != nil {
			t.Skipf("IPv6 loopback is not available: %v", err)
		}
		tcpListener, ok := listener.(*net.TCPListener)
		if !ok {
			_ = listener.Close()
			t.Fatalf("listener type = %T, want *net.TCPListener", listener)
		}
		t.Cleanup(func() { _ = tcpListener.Close() })

		hostsFile := filepath.Join(t.TempDir(), "hosts")
		writeResolverTestHostsFile(t, hostsFile, "")
		provider := newResolverTestDNSProvider()
		system := newResolverTestSystemWithHostsFile(t, provider, hostsFile)
		conn, err := system.OutNet().Dial(
			resolverTestContext(t),
			"tcp6",
			net.JoinHostPort(
				"localhost",
				netPortString(resolverTestTCPPort(t, tcpListener)),
			),
		)
		if err != nil {
			t.Fatalf("Dial localhost: %v", err)
		}
		defer func() { _ = conn.Close() }()
		acceptResolverTestTCP(t, tcpListener)

		remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			t.Fatalf("split remote address: %v", err)
		}
		if remoteHost != "::1" {
			t.Fatalf("remote address = %s, want ::1", remoteHost)
		}
		assertResolverTestNoQuestions(t, provider)
	})
}

func TestSystemOutNetHostsFileSyntax(t *testing.T) {
	hostsFile := filepath.Join(t.TempDir(), "hosts")
	writeResolverTestHostsFile(t, hostsFile, `
# Full-line comment and blank lines are ignored.
not-an-address invalid-before.test
192.0.2.10 canonical.test first-alias.test Hosts-Mixed.Test. # inline comment
2001:db8::10	second-alias.test	HOSTS-MIXED.TEST
::ffff:192.0.2.10 mapped.test hosts-mixed.test
192.0.2.11 other.test hosts-mixed.test
missing-address-field
192.0.2.12 first-name.test second-name.test
bad-address invalid-middle.test
192.0.2.13 valid-after-invalid.test
`)
	provider := newResolverTestDNSProvider()
	system := newResolverTestSystemWithHostsFile(t, provider, hostsFile)
	ctx := resolverTestContext(t)

	tests := []struct {
		name string
		host string
		want []netip.Addr
	}{
		{
			name: "case trailing dot multiple lines and duplicate",
			host: "hOsTs-MiXeD.TeSt.",
			want: resolverTestAddresses(
				"192.0.2.10",
				"2001:db8::10",
				"192.0.2.11",
			),
		},
		{
			name: "multiple aliases",
			host: "second-name.test",
			want: resolverTestAddresses("192.0.2.12"),
		},
		{
			name: "valid line after invalid lines",
			host: "valid-after-invalid.test",
			want: resolverTestAddresses("192.0.2.13"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := system.OutNet().LookupNetIP(ctx, "ip", test.host)
			if err != nil {
				t.Fatalf("LookupNetIP: %v", err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("LookupNetIP = %v, want %v", got, test.want)
			}
			assertResolverTestNoQuestions(t, provider)
		})
	}
}

func TestSystemOutNetHostsFileFamilySpecificFallback(t *testing.T) {
	hostsFile := filepath.Join(t.TempDir(), "hosts")
	writeResolverTestHostsFile(t, hostsFile, `
192.0.2.40 v4-only.test
2001:db8::40 v6-only.test
192.0.2.41 dual-stack.test
2001:db8::41 dual-stack.test
`)
	provider := newResolverTestDNSProvider()
	provider.setHost(
		"v4-only.test",
		netip.MustParseAddr("198.51.100.40"),
		netip.MustParseAddr("2001:db8:1::40"),
	)
	provider.setHost(
		"v6-only.test",
		netip.MustParseAddr("198.51.100.60"),
		netip.MustParseAddr("2001:db8:1::60"),
	)
	provider.setHost(
		"dual-stack.test",
		netip.MustParseAddr("198.51.100.41"),
		netip.MustParseAddr("2001:db8:1::41"),
	)
	system := newResolverTestSystemWithHostsFile(t, provider, hostsFile)
	ctx := resolverTestContext(t)

	tests := []struct {
		name      string
		network   string
		host      string
		want      []netip.Addr
		questions []uint16
	}{
		{
			name:    "IPv4 hosts entry with IPv4 request",
			network: "ip4",
			host:    "v4-only.test",
			want:    resolverTestAddresses("192.0.2.40"),
		},
		{
			name:      "IPv4 hosts entry with IPv6 request",
			network:   "ip6",
			host:      "v4-only.test",
			want:      resolverTestAddresses("2001:db8:1::40"),
			questions: []uint16{gdns.TypeAAAA},
		},
		{
			name:    "IPv6 hosts entry with IPv6 request",
			network: "ip6",
			host:    "v6-only.test",
			want:    resolverTestAddresses("2001:db8::40"),
		},
		{
			name:      "IPv6 hosts entry with IPv4 request",
			network:   "ip4",
			host:      "v6-only.test",
			want:      resolverTestAddresses("198.51.100.60"),
			questions: []uint16{gdns.TypeA},
		},
		{
			name:    "both hosts families with unspecified request",
			network: "ip",
			host:    "dual-stack.test",
			want: resolverTestAddresses(
				"192.0.2.41",
				"2001:db8::41",
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := system.OutNet().LookupNetIP(
				ctx,
				test.network,
				test.host,
			)
			if err != nil {
				t.Fatalf("LookupNetIP: %v", err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("LookupNetIP = %v, want %v", got, test.want)
			}
			assertResolverTestQuestions(
				t,
				provider.takeQuestions(),
				test.host,
				test.questions...,
			)
		})
	}
}

func TestSystemOutNetReloadsHostsFileForEachDial(t *testing.T) {
	const host = "dynamic-host.test"

	directory := t.TempDir()
	hostsFile := filepath.Join(directory, "hosts")
	writeResolverTestHostsFile(t, hostsFile, "# no entry\n")
	listener := listenResolverTestTCP(t, "0.0.0.0:0")
	provider := newResolverTestDNSProvider()
	provider.setHost(host, netip.MustParseAddr("127.0.0.1"))
	system := newResolverTestSystemWithHostsFile(t, provider, hostsFile)

	remote := dialResolverTestTCP(t, system.OutNet(), host, listener)
	if remote != "127.0.0.1" {
		t.Fatalf("DNS remote address = %s, want 127.0.0.1", remote)
	}
	assertResolverTestQuestions(
		t,
		provider.takeQuestions(),
		host,
		gdns.TypeA,
		gdns.TypeAAAA,
	)

	writeResolverTestHostsFile(t, hostsFile, "127.0.0.2 "+host+"\n")
	remote = dialResolverTestTCP(t, system.OutNet(), host, listener)
	if remote != "127.0.0.2" {
		t.Fatalf("updated hosts remote address = %s, want 127.0.0.2", remote)
	}
	assertResolverTestNoQuestions(t, provider)

	replacement := filepath.Join(directory, "hosts.new")
	writeResolverTestHostsFile(t, replacement, "127.0.0.3 "+host+"\n")
	if err := os.Rename(replacement, hostsFile); err != nil {
		t.Fatalf("replace hosts file: %v", err)
	}
	remote = dialResolverTestTCP(t, system.OutNet(), host, listener)
	if remote != "127.0.0.3" {
		t.Fatalf("replaced hosts remote address = %s, want 127.0.0.3", remote)
	}
	assertResolverTestNoQuestions(t, provider)

	provider.setHost(host, netip.MustParseAddr("127.0.0.4"))
	writeResolverTestHostsFile(t, replacement, "# entry removed\n")
	if err := os.Rename(replacement, hostsFile); err != nil {
		t.Fatalf("replace hosts file after removing entry: %v", err)
	}
	remote = dialResolverTestTCP(t, system.OutNet(), host, listener)
	if remote != "127.0.0.4" {
		t.Fatalf("restored DNS remote address = %s, want 127.0.0.4", remote)
	}
	assertResolverTestQuestions(
		t,
		provider.takeQuestions(),
		host,
		gdns.TypeA,
		gdns.TypeAAAA,
	)
}

func TestSystemOutNetLookupIPLiteralDoesNotUseDNSProvider(t *testing.T) {
	hostsFile := filepath.Join(t.TempDir(), "hosts")
	writeResolverTestHostsFile(t, hostsFile, "")
	provider := newResolverTestDNSProvider()
	system := newResolverTestSystemWithHostsFile(t, provider, hostsFile)
	ctx := resolverTestContext(t)

	tests := []struct {
		name    string
		network string
		host    string
		want    []netip.Addr
		wantErr bool
	}{
		{
			name:    "IPv4 literal",
			network: "ip4",
			host:    "192.0.2.70",
			want:    resolverTestAddresses("192.0.2.70"),
		},
		{
			name:    "IPv6 literal",
			network: "ip6",
			host:    "2001:db8::70",
			want:    resolverTestAddresses("2001:db8::70"),
		},
		{
			name:    "literal family mismatch",
			network: "ip4",
			host:    "2001:db8::70",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := system.OutNet().LookupNetIP(
				ctx,
				test.network,
				test.host,
			)
			switch {
			case test.wantErr:
				var dnsErr *net.DNSError
				if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
					t.Fatalf(
						"LookupNetIP error = %v, want not-found DNS error",
						err,
					)
				}
			case err != nil:
				t.Fatalf("LookupNetIP: %v", err)
			case !slices.Equal(got, test.want):
				t.Fatalf("LookupNetIP = %v, want %v", got, test.want)
			}
			assertResolverTestNoQuestions(t, provider)
		})
	}
}

func assertResolverTestNoQuestions(
	t *testing.T,
	provider *resolverTestDNSProvider,
) {
	t.Helper()
	if got := provider.takeQuestions(); len(got) != 0 {
		t.Fatalf("DNS questions = %v, want none", got)
	}
}

func resolverTestAddresses(addresses ...string) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, netip.MustParseAddr(address))
	}
	return result
}

func writeResolverTestHostsFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write hosts file: %v", err)
	}
}
