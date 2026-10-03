//go:build linux

// nolint
package linux

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/killswitch"
)

func FuzzUntrustedInput(f *testing.F) {
	completionRoot := f.TempDir()
	for _, name := range []string{"alpha", "beta", "tool[1]"} {
		if err := os.WriteFile(
			filepath.Join(completionRoot, name),
			[]byte("fuzz"),
			0o600,
		); err != nil {
			f.Fatal(err)
		}
	}
	for _, seed := range [][]byte{
		[]byte("\x00^ssh(d)?$"),
		[]byte("\x011 2 4294967295"),
		[]byte("\x02root:x:0:0:root:/root:/bin/sh"),
		[]byte("\x03Name:\ttest\nUid:\t1000\nGid:\t1000\n"),
		[]byte("\x04localhost\x00127.0.0.1 localhost\n::1 localhost"),
		[]byte("\x0510.0.0.1/24\x000.0.0.0/0"),
		[]byte("\x0610.0.0.1/24\x0010.0.0.1"),
		[]byte("\x07arg0\x00arg1"),
		[]byte("\x08tun0\x0010.0.0.1/32"),
		[]byte("\x09system-state"),
		[]byte("\x0aauto-state"),
		[]byte("\x0bcompletion"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		if len(data) > 64<<10 {
			data = data[:64<<10]
		}
		input := string(data[1:])
		switch data[0] % 12 {
		case 0:
			types := [...]string{
				"comm", "cmd", "exec", "pid", "uid", "gid", input,
			}
			compiled, err := compileRule(sysnet.Rule{
				Type: types[len(data)%len(types)],
				Rule: input,
			})
			if err == nil {
				info := pmark.ProcessInfo{
					Comm:    input,
					Cmdline: input,
					Exe:     input,
				}
				owner := &sockowner.SocketOwner{Comm: input, ProcName: input}
				if compiled.process != nil {
					_ = compiled.process(info)
				}
				if compiled.owner != nil {
					_ = compiled.owner(owner)
				}
			}
		case 1:
			_, _ = parseUint32List(input)
			_, _ = compileExec(input)
		case 2:
			_ = completeColonFileData(data[1:], input, len(data)%2 == 0, 0, 2)
		case 3:
			_, _, _ = parseProcessStatusIDs(data[1:])
		case 4:
			parts := strings.SplitN(input, "\x00", 2)
			hosts := ""
			if len(parts) == 2 {
				hosts = parts[1]
			}
			networks := [...]string{"ip", "ip4", "ip6", input}
			_, _, _ = lookupLocalHostData(
				[]byte(hosts), networks[len(data)%len(networks)], parts[0],
				nil, make(map[netip.Addr]struct{}),
			)
		case 5:
			values := limitedStrings(input)
			_, _, _ = normalizeTunAddrs(values, input, input)
			_, _ = normalizeTunRoutes(values)
		case 6:
			values := limitedStrings(input)
			routes := make([]sysnet.TunSourceRoute, 0, len(values)/2)
			for i := 0; i+1 < len(values); i += 2 {
				dst, _ := netip.ParsePrefix(values[i])
				src, _ := netip.ParseAddr(values[i+1])
				routes = append(routes, sysnet.TunSourceRoute{
					Destination: dst,
					Source:      src,
				})
			}
			_, _ = normalizeTunSourceRoutes(values, routes)
		case 7:
			_ = parseProcessCmdline(data[1:])
		case 8:
			values := limitedStrings(input)
			system := &System{
				baseName:       input,
				defaultTunCIDR: input,
			}
			_ = system.CheckTunOpts(sysnet.TunOpts{
				Name:      input,
				TunAddrs:  values,
				TunRoutes: values,
				MTU:       len(data),
			})
			sourceRoutes := make([]sysnet.TunSourceRoute, 0, len(values)/2)
			for i := 0; i+1 < len(values); i += 2 {
				dst, _ := netip.ParsePrefix(values[i])
				src, _ := netip.ParseAddr(values[i+1])
				sourceRoutes = append(sourceRoutes, sysnet.TunSourceRoute{
					Destination: dst,
					Source:      src,
				})
			}
			_ = system.CheckDefaultTunOpts(sysnet.DefaultTunOpts{
				Name:         input,
				TunAddrs:     values,
				TunRoutes:    values,
				SourceRoutes: sourceRoutes,
				DnsIP:        input,
				Exclude: []sysnet.Rule{{
					Type: "pid",
					Rule: input,
				}},
			})
			_ = system.CheckRule(
				sysnet.Rule{Type: "comm", Rule: input},
				sysnet.RuleContext{Routing: &sysnet.RoutingProfileKey{}},
			)
		case 9:
			fuzzSystemState(data[1:])
		case 10:
			fuzzAutoConstructor(data[1:])
		case 11:
			prefix := filepath.Join(completionRoot, filepath.Base(input))
			_, _ = completeExecRule(prefix)
			_, _ = completeColonFileRule(input, false, filepath.Join(
				completionRoot,
				"missing",
			), 0, 2)
		}
	})
}

func fuzzSystemState(data []byte) {
	factory := &fakeTUNFactory{}
	configurator := &fakeTunConfig{}
	routingManager := &fakeRouting{}
	connmarkManager := &fakeConnmark{}
	provider := newFakeDNSProvider()
	injected := errors.New("fuzz system failure")
	if len(data) > 0 && data[0]&1 != 0 {
		routingManager.applyErr = injected
	}
	if len(data) > 1 && data[1]&1 != 0 {
		connmarkManager.applyErr = injected
	}
	if len(data) > 2 && data[2]&1 != 0 {
		provider.setErr = injected
	}
	system, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:           true,
			DefaultTun:    true,
			DynTun:        true,
			DynDefaultTun: true,
			TunNames:      true,
			StrictMode:    true,
			DNSControl:    true,
			Routing:       true,
			Killswitch:    true,
		},
		DNSProvider:    provider,
		RoutingManager: routingManager,
		Connmark:       connmarkManager,
		Killswitch:     &fakeKillswitch{},
		TUNFactory:     factory,
		TunConfig:      configurator,
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       func(gtun.Tun) (int, error) { return 10, nil },
	})
	if err != nil {
		return
	}

	regularOpts := sysnet.TunOpts{
		TunAddrs:  []string{"192.0.2.2/32", "2001:db8::2/128"},
		TunRoutes: []string{"198.51.100.0/24", "2001:db8:1::/64"},
		MTU:       1280,
	}
	defaultOpts := sysnet.DefaultTunOpts{
		TunAddrs:  []string{"100.64.0.2/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "100.64.0.2",
		MTU:       1280,
	}
	var regular gtun.Tun
	var defaultTun sysnet.DefaultTun
	for _, operation := range data[:min(len(data), 32)] {
		switch operation % 10 {
		case 0:
			regular, _ = system.BuildTun(regularOpts)
		case 1:
			if regular != nil {
				_ = system.SetTunAddrs(regular, regularOpts.TunAddrs)
				_ = system.SetTunRoutes(regular, regularOpts.TunRoutes)
			}
		case 2:
			if regular != nil {
				_ = system.AddTunAddr(regular, "192.0.2.3/32")
				_ = system.AddTunRoute(regular, "203.0.113.0/24")
			}
		case 3:
			if regular != nil {
				_ = system.SetTunName(regular, "fuzz-tun")
			}
		case 4:
			defaultTun, _ = system.BuildDefaultTun(defaultOpts)
		case 5:
			if defaultTun != nil {
				_ = system.SetTunAddrs(defaultTun, defaultOpts.TunAddrs)
				_ = system.SetTunRoutes(defaultTun, defaultOpts.TunRoutes)
			}
		case 6:
			if defaultTun != nil {
				_ = defaultTun.SetDNS(newFakeDNSProvider())
			}
		case 7:
			if regular != nil {
				_ = regular.Close()
			}
		case 8:
			if defaultTun != nil {
				_ = defaultTun.Close()
			}
		case 9:
			_ = system.Capabilities()
		}
	}
	_ = system.Close()
	_ = system.Close()
}

func fuzzAutoConstructor(data []byte) {
	injected := errors.New("fuzz constructor failure")
	oldEnv := autoSystemEnv
	defer func() { autoSystemEnv = oldEnv }()
	flag := func(index int) bool { return len(data) > index && data[index]&1 != 0 }
	autoSystemEnv = systemAutoEnvironment{
		hasCapability: func(int) bool { return flag(0) },
		probeTUN: func(TUNFactory, func(time.Duration), func(string, ...any)) error {
			if flag(1) {
				return injected
			}
			return nil
		},
		waitTUNProbeRetry: func(time.Duration) {},
		newRoutingManager: func() (RoutingManager, error) {
			if flag(2) {
				return nil, injected
			}
			return &fakeRouting{}, nil
		},
		newDNSProvider: func(
			SystemConfig,
			gonnect.Network,
			gonnect.Network,
		) (dns.DNSProvider, error) {
			if flag(3) {
				return nil, injected
			}
			return newFakeDNSProvider(), nil
		},
		newPmark: func(
			SystemConfig,
			func(string, ...any),
		) (PmarkController, []io.Closer, error) {
			if flag(4) {
				return nil, nil, injected
			}
			return &fakePmark{}, nil, nil
		},
		newKillswitch: func(string, killswitch.Logf) KillswitchClient {
			return &fakeKillswitch{}
		},
	}
	features := FeatureConfig{
		Tun: flag(5), Routing: flag(6), DNSControl: flag(7),
		Pmark: flag(8), Killswitch: flag(9), MatcherRules: flag(10),
	}
	// Keep native connmark creation out of the unprivileged harness.
	features.DefaultTun = false
	// A zero FeatureConfig enables the production defaults. Keep at least one
	// harmless feature enabled so this harness only uses the fakes above.
	if features == (FeatureConfig{}) {
		features.MatcherRules = true
	}
	system, err := New(SystemConfig{
		Features:           features,
		DefaultTunBaseName: string(data),
	})
	if err == nil {
		_ = system.Close()
	}
}

func limitedStrings(value string) []string {
	values := strings.Split(value, "\x00")
	if len(values) > 32 {
		values = values[:32]
	}
	return values
}
