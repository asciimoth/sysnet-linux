//go:build linux

// nolint
package routing

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func FuzzUntrustedInput(f *testing.F) {
	f.Add([]byte("10.0.0.0/8\x0010.0.0.1"))
	f.Add([]byte("::/0\x00fe80::1"))
	f.Add([]byte("manager-state-sequence"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64<<10 {
			input = input[:64<<10]
		}
		config := DefaultConfig()
		config.TUNIndex = fuzzInt(input, 0)
		config.VPNTable = fuzzInt(input, 4)
		config.SafeTable = fuzzInt(input, 8)
		config.PriorityBase = fuzzInt(input, 12)
		config.PrioritySpan = fuzzInt(input, 16)
		config.AppBypassMark = fuzzUint32(input, 20)
		config.AppBypassMask = fuzzUint32(input, 24)
		config.UserMark = fuzzUint32(input, 28)
		config.UserMarkMask = fuzzUint32(input, 32)
		config.Mode = Mode(fuzzInt(input, 36))
		config.Strictness = Strictness(fuzzInt(input, 40))
		config.Families = FamilySet{
			IPv4: fuzzByte(input, 44)&1 != 0,
			IPv6: fuzzByte(input, 45)&1 != 0,
		}
		config.TunnelFamilies = FamilySet{
			IPv4: fuzzByte(input, 46)&1 != 0,
			IPv6: fuzzByte(input, 47)&1 != 0,
		}
		parts := splitPair(string(input))
		dst, _ := netip.ParsePrefix(parts[0])
		src, _ := netip.ParseAddr(parts[1])
		config.SourceRoutes = []SourceRoute{{Destination: dst, Source: src}}
		_ = ValidateConfig(config)
		_, _ = CompileDesiredState(config, Snapshot{})

		family := unix.AF_INET
		if fuzzByte(input, 48)&1 != 0 {
			family = unix.AF_INET6
		}
		rawIP := net.IP(append([]byte(nil), input...))
		if len(rawIP) > net.IPv6len {
			rawIP = rawIP[:net.IPv6len]
		}
		rawRoute := netlink.Route{
			Family: family,
			Table:  fuzzInt(input, 49),
			Dst: &net.IPNet{
				IP:   rawIP,
				Mask: net.IPMask(append([]byte(nil), rawIP...)),
			},
			Gw:  rawIP,
			Src: rawIP,
			MultiPath: []*netlink.NexthopInfo{
				nil,
				{
					LinkIndex: fuzzInt(input, 51),
					Gw:        append(net.IP(nil), rawIP...),
					Flags:     fuzzInt(input, 53),
				},
			},
		}
		if fuzzByte(input, 55)&1 != 0 {
			mpls := fuzzInt(input, 56)
			rawRoute.MPLSDst = &mpls
		}
		if route, ok := routeFromNetlink(rawRoute); ok {
			_, _ = routeToNetlink(route)
			_ = ClassifySafeRoute(route, config.TUNIndex)
		}

		mask := fuzzUint32(input, 58)
		rawRule := *netlink.NewRule()
		rawRule.Family = family
		rawRule.Priority = fuzzInt(input, 62)
		rawRule.Table = fuzzInt(input, 64)
		rawRule.Mark = fuzzUint32(input, 66)
		rawRule.Mask = &mask
		rawRule.Type = fuzzByte(input, 70)
		normalizedRule := ruleFromNetlink(rawRule)
		_ = ruleToNetlink(normalizedRule)

		validConfig := DefaultConfig()
		validConfig.TUNIndex = max(1, fuzzInt(input, 71))
		validConfig.UserMark = fuzzUint32(input, 73)
		if validConfig.UserMark == validConfig.AppBypassMark {
			validConfig.UserMark++
		}
		if dst.IsValid() && src.IsValid() &&
			dst.Addr().Is4() == src.Is4() {
			validConfig.SourceRoutes = []SourceRoute{{
				Destination: dst.Masked(),
				Source:      src,
			}}
		}
		var snapshot Snapshot
		if route, ok := routeFromNetlink(rawRoute); ok {
			snapshot.MainRoutes = []Route{route}
		}
		_, _ = CompileDesiredState(validConfig, snapshot)
		_, _ = TransitionGuardRules(validConfig)

		arbitraryRoute := Route{
			Family:          family,
			Dst:             dst,
			Gateway:         src,
			PreferredSource: src,
			Scope:           fuzzInt(input, 77),
			Multipath: []Nexthop{{
				LinkIndex: fuzzInt(input, 79),
				Gateway:   src,
				Flags:     fuzzInt(input, 81),
			}},
		}
		_, _ = routeToNetlink(arbitraryRoute)
		_ = ClassifySafeRoute(arbitraryRoute, validConfig.TUNIndex)

		fuzzManagerState(input, validConfig, arbitraryRoute)
		fuzzMonitorState(input, validConfig, arbitraryRoute)
	})
}

func fuzzManagerState(input []byte, config Config, candidate Route) {
	config.TUNIndex = 10
	config.VPNTable = DefaultVPNTable
	config.SafeTable = DefaultSafeTable
	config.PriorityBase = DefaultPriorityBase
	config.PrioritySpan = DefaultPrioritySpan
	config.AppBypassMark = DefaultAppBypassMark
	config.AppBypassMask = DefaultMarkMask
	config.UserMark = fuzzUint32(input, 3)
	config.UserMarkMask = DefaultMarkMask
	if config.UserMark == config.AppBypassMark {
		config.UserMark++
	}
	config.Families = BothFamilies
	config.TunnelFamilies = BothFamilies

	adapter := newFakeAdapter()
	if candidate.Dst.IsValid() {
		candidate.Table = unix.RT_TABLE_MAIN
		candidate.LinkIndex = 2
		candidate.Type = RouteTypeUnicast
		adapter.routes = append(adapter.routes, candidate, candidate)
	}
	adapter.rules = append(adapter.rules, Rule{
		Family: unix.AF_INET, Priority: config.PriorityBase,
		Action: RuleLookup, Table: config.VPNTable,
	})
	injected := errors.New("fuzz adapter failure")
	if len(input) > 1 && input[1]&1 != 0 {
		adapter.replaceRouteErr = injected
	}
	if len(input) > 2 && input[2]&1 != 0 {
		adapter.listRoutesErr = injected
	}
	if len(input) > 3 && input[3]&1 != 0 {
		adapter.addRuleErr = func(Rule) error { return injected }
	}

	manager := newManagerWithAdapter(adapter)
	for _, operation := range input[:min(len(input), 32)] {
		switch operation % 5 {
		case 0:
			_ = manager.Apply(config)
		case 1:
			_ = manager.Refresh()
		case 2:
			_, _ = manager.Status()
		case 3:
			_ = manager.Rollback(config)
		case 4:
			adapter.replaceRouteErr = nil
			adapter.listRoutesErr = nil
			adapter.addRuleErr = nil
		}
	}
	_ = manager.Close()
	_ = manager.Close()
}

func fuzzMonitorState(input []byte, config Config, candidate Route) {
	adapter := newFakeAdapter()
	if candidate.Dst.IsValid() {
		candidate.Table = unix.RT_TABLE_MAIN
		candidate.LinkIndex = 2
		candidate.Type = RouteTypeUnicast
		adapter.routes = append(adapter.routes, candidate)
	}
	manager := newManagerWithAdapter(adapter)
	manager.monitorDebounce = time.Nanosecond
	manager.monitorRetry = time.Nanosecond
	var events chan<- netlink.RouteUpdate
	if err := manager.startRouteMonitor(func(
		out chan<- netlink.RouteUpdate,
		done <-chan struct{},
		_ netlink.RouteSubscribeOptions,
	) error {
		events = out
		go func() {
			<-done
			close(out)
		}()
		return nil
	}); err != nil {
		return
	}
	config.TUNIndex = 10
	config.Strictness = NonStrict
	_ = manager.Apply(config)
	for _, operation := range input[:min(len(input), 32)] {
		table := unix.RT_TABLE_MAIN
		if operation&1 != 0 {
			table = config.SafeTable
		}
		select {
		case events <- netlink.RouteUpdate{Route: netlink.Route{Table: table}}:
		default:
		}
		if operation&2 != 0 {
			runtime.Gosched()
		}
	}
	_ = manager.Close()
}

func fuzzUint32(data []byte, offset int) uint32 {
	if len(data) < offset+4 {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}

func fuzzInt(data []byte, offset int) int {
	if len(data) < offset+2 {
		return 0
	}
	return int(binary.LittleEndian.Uint16(data[offset : offset+2]))
}

func fuzzByte(data []byte, offset int) byte {
	if len(data) <= offset {
		return 0
	}
	return data[offset]
}

func splitPair(value string) [2]string {
	for i := range len(value) {
		if value[i] == 0 {
			return [2]string{value[:i], value[i+1:]}
		}
	}
	return [2]string{value, value}
}
