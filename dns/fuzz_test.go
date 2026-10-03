//go:build linux

// nolint
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-linux/dns/resolvconffile"
	"github.com/godbus/dbus/v5"
)

func FuzzUntrustedInput(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("# systemd-resolved\nnameserver 127.0.0.53\n"),
		[]byte("hosts: files resolve dns\n"),
		[]byte("udp\x001.1.1.1\x0053"),
		append([]byte{4, 0, 0, 0}, 127, 0, 0, 1),
	} {
		f.Add(seed)
	}
	for selector := byte(0); selector < 12; selector++ {
		f.Add([]byte{selector, 'f', 'u', 'z', 'z'})
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		if len(data) > 64<<10 {
			data = data[:64<<10]
		}
		switch data[0] % 12 {
		case 0:
			owner := ResolvOwner(data[1:])
			withNewline := append(append([]byte(nil), data[1:]...), '\n')
			if got := ResolvOwner(withNewline); got != owner {
				t.Fatalf(
					"owner changed after final newline: %q != %q",
					got,
					owner,
				)
			}
			_, _ = resolvconfNameservers(data[1:])
			_ = directResolvconfOwned(data[1:])
		case 1:
			env := Env{
				ReadFile: func(string) ([]byte, error) { return data[1:], nil },
			}
			_ = IsLibnssResolveUsed(env)
		case 2:
			parts := splitFuzzFields(string(data[1:]), 3)
			_, _ = resolveDialAddr(parts[0], parts[1], parts[2])
		case 3:
			family := int32(0)
			if len(data) >= 5 {
				family = int32(
					binary.LittleEndian.Uint32(data[1:5]),
				) //nolint:gosec
			}
			_, _ = addrFromResolved(family, data[min(5, len(data)):])
		case 4:
			value := string(data[1:])
			_ = normalizeResolvedDomain(value)
			_ = dnsNameMatchesDomain(value, value)
			_ = hasRootDNSRoute(splitFuzzFields(value, 16))
		case 5:
			addr, _ := netip.ParseAddr(string(data[1:]))
			var port uint16
			if len(data) >= 2 {
				port = binary.LittleEndian.Uint16(data[:2])
			}
			_ = addrPort(addr, port)
			_ = serverURLs(dedupeServers([]netip.AddrPort{
				netip.AddrPortFrom(addr, port),
			}))
		case 6:
			value := string(data[1:])
			body := []any{value, data[1:], value}
			if len(data)%2 == 0 {
				body = body[:len(data)%4]
			}
			_ = resolvedSignalNeedsSync(&dbus.Signal{
				Name: value,
				Path: dbus.ObjectPath(value),
				Body: body,
			})
			_ = resolvedSignalNeedsSync(nil)
		case 7:
			servers := fuzzAddrPorts(data[1:])
			parts := splitFuzzFields(string(data[1:]), 8)
			linkDomains := make([]resolvedLinkDomain, 0, len(parts))
			globalDomains := make([]resolvedGlobalDomain, 0, len(parts))
			for i, part := range parts {
				linkDomains = append(linkDomains, resolvedLinkDomain{
					Domain:      part,
					RoutingOnly: i%2 == 0,
				})
				globalDomains = append(globalDomains, resolvedGlobalDomain{
					IfIndex:     int32(i),
					Domain:      part,
					RoutingOnly: i%2 != 0,
				})
			}
			builder := resolvedRouteBuilder{}
			builder.addLink(servers, linkDomains)
			builder.addGlobal(servers, globalDomains)
			builder.addDefault(servers)
			routes, _ := builder.config()
			route := resolvedRouteFunc(routes)
			_ = route(&gdns.Message{Questions: []gdns.Question{{
				Name: string(data[1:]),
			}}})
			_ = route(nil)
		case 8:
			servers := fuzzAddrPorts(data[1:])
			parts := splitFuzzFields(string(data[1:]), 8)
			managed := netip.Addr{}
			if len(servers) != 0 {
				managed = servers[0].Addr()
			}
			_ = resolvedDefaultTunDNSRouteWarnings(resolvedRouteSnapshot{
				ManagedIfIndex: int32(len(data)),
				ManagedDNS:     managed,
				ManagedLink: resolvedLinkDNSRoute{
					IfIndex: int32(len(data)),
					Servers: servers,
					Domains: parts,
				},
				Links: []resolvedLinkDNSRoute{{
					IfIndex: -1,
					Servers: append([]netip.AddrPort(nil), servers...),
					Domains: append([]string(nil), parts...),
				}},
				Global: resolvedDNSRoute{Servers: servers, Domains: parts},
			})
			_, _ = resolvedIfIndex(len(data))
			_, _ = resolvedOptionalIfIndex(-len(data))
			if managed.IsValid() {
				_ = resolvedNameserver(managed)
			}
		case 9:
			failure := errors.New("fuzz failure")
			env := Env{
				ReadFile: func(string) ([]byte, error) { return data[1:], nil },
				DbusPing: func(context.Context, string, string) error {
					if len(data)%2 == 0 {
						return nil
					}
					return failure
				},
				DbusReadString: func(
					context.Context, string, string, string, string,
				) (string, error) {
					return string(data[1:]), nil
				},
				ResolvconfStyle: func() string { return string(data[1:]) },
				NmIsUsingResolved: func() error {
					if len(data)%3 == 0 {
						return nil
					}
					return failure
				},
				Logf: func(string, ...any) {},
			}
			_, _ = DnsMode(context.Background(), env)
		case 10:
			fuzzDNSProviderState(data[1:])
		case 11:
			fuzzResolvedState(data[1:])
		}
	})
}

func fuzzResolvedState(data []byte) {
	if len(data) == 0 {
		return
	}
	ifidx := int32(data[0]%32 + 1)
	bus := newFakeResolvedBus(ifidx)
	server := netip.AddrFrom4([4]byte{100, 64, data[0], 53})
	upstream := netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{192, 0, 2, data[0]}),
		53,
	)
	bus.setLinkDNS(upstream)
	bus.setLinkDomains(resolvedLinkDomain{Domain: ".", RoutingOnly: true})
	bus.setManagerDNS(0, upstream)
	bus.setManagerDomains(0, resolvedGlobalDomain{
		Domain: ".", RoutingOnly: true,
	})
	if len(data) > 1 && data[1]&1 != 0 {
		bus.revertErr = map[int32]error{
			ifidx: dbus.Error{
				Name: "org.freedesktop.resolve1.NoSuchLink",
				Body: []any{string(data)},
			},
		}
	}
	resolved, err := NewResolved(
		Env{ResolvedBus: func() (DBusConn, error) { return bus, nil }},
		testNetwork(),
		testNetwork(),
		int(ifidx),
		upstream,
	)
	if err != nil {
		return
	}
	for i, operation := range data[:min(len(data), 32)] {
		switch operation % 8 {
		case 0:
			_ = resolved.SetDNS(server)
		case 1:
			_ = resolved.UnsetDNS()
		case 2:
			_ = resolved.SetInterfaceIndex(int(operation%32 + 1))
		case 3:
			_ = resolved.UpdateInterfaceIndex(int(operation%32 + 1))
		case 4:
			bus.setLinkDNS(fuzzAddrPorts(data[i:])...)
		case 5:
			bus.setLinkDomains(resolvedLinkDomain{
				Domain:      string(data[i:min(len(data), i+16)]),
				RoutingOnly: operation&1 != 0,
			})
		case 6:
			bus.mu.Lock()
			signals := append([]chan<- *dbus.Signal(nil), bus.signals...)
			bus.mu.Unlock()
			for _, signalsChannel := range signals {
				select {
				case signalsChannel <- &dbus.Signal{
					Name: dbusPropertiesChanged,
					Path: dbus.ObjectPath(dbusResolvedPath),
				}:
				default:
				}
			}
		case 7:
			_ = resolved.DefaultTunDNSRouteWarnings(ifidx, server)
		}
	}
	_ = resolved.Close()
	_ = resolved.Close()
}

func fuzzDNSProviderState(data []byte) {
	if len(data) == 0 {
		return
	}
	original := string(data[1:])
	if data[0]&1 == 0 {
		original = "# " + original + "\nnameserver 192.0.2.1\n"
	}
	server := netip.AddrFrom4([4]byte{100, 64, data[0], 1})
	fallback := netip.MustParseAddrPort("192.0.2.53:53")

	switch data[0] % 3 {
	case 0:
		env := newFakeDirectEnv(original)
		provider, err := NewDirect(
			env.env(), testNetwork(), testNetwork(), fallback,
		)
		if err != nil {
			return
		}
		for _, operation := range data[1:min(len(data), 17)] {
			switch operation % 3 {
			case 0:
				_ = provider.SetDNS(server)
			case 1:
				env.files[resolvconffile.Path] = append([]byte(nil), data...)
			case 2:
				_ = provider.UnsetDNS()
			}
		}
		_ = provider.Close()
		_ = provider.Close()
	case 1:
		env := newFakeDebianResolvconfEnv(original)
		provider, err := NewDebianResolvconf(
			env.env(), testNetwork(), testNetwork(), "fuzz", fallback,
		)
		if err != nil {
			return
		}
		fuzzResolvconfProviderState(
			provider.SetDNS,
			provider.UnsetDNS,
			data,
			server,
		)
		_ = provider.Close()
		_ = provider.Close()
	case 2:
		env := newFakeDebianResolvconfEnv(original)
		provider, err := NewOpenresolv(
			env.env(), testNetwork(), testNetwork(), "fuzz", fallback,
		)
		if err != nil {
			return
		}
		fuzzResolvconfProviderState(
			provider.SetDNS,
			provider.UnsetDNS,
			data,
			server,
		)
		_ = provider.Close()
		_ = provider.Close()
	}
}

func fuzzResolvconfProviderState(
	set func(netip.Addr) error,
	unset func() error,
	data []byte,
	server netip.Addr,
) {
	for _, operation := range data[1:min(len(data), 17)] {
		if operation&1 == 0 {
			_ = set(server)
		} else {
			_ = unset()
		}
	}
}

func fuzzAddrPorts(data []byte) []netip.AddrPort {
	servers := make([]netip.AddrPort, 0, min(len(data)/4+1, 8))
	for len(data) != 0 && len(servers) < 8 {
		var raw [16]byte
		n := min(len(data), len(raw))
		copy(raw[:], data[:n])
		addr := netip.AddrFrom16(raw)
		if data[0]&1 == 0 {
			addr = netip.AddrFrom4([4]byte(raw[:4]))
		}
		port := uint16(0)
		if len(data) >= 2 {
			port = binary.LittleEndian.Uint16(data[:2])
		}
		servers = append(servers, netip.AddrPortFrom(addr, port))
		data = data[n:]
	}
	return servers
}

func splitFuzzFields(value string, count int) []string {
	out := make([]string, count)
	field := 0
	for i := 0; i < len(value) && field < count-1; i++ {
		if value[i] != 0 {
			continue
		}
		out[field] = value[:i]
		value = value[i+1:]
		field++
		i = -1
	}
	out[field] = value
	return out
}
