//go:build linux

// nolint
package tun

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func FuzzUntrustedInput(f *testing.F) {
	for _, seed := range []string{
		"10.0.0.1/24", "10.0.0.1", "fd00::1/64", "::ffff:192.0.2.1/120", "bad",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			input = input[:64<<10]
		}
		prefix, err := parseTunAddrPrefix(input)
		if err == nil {
			_, _ = netlinkAddrFromPrefix(prefix)
			_, _ = netlinkRouteFromPrefix(1, prefix)
		}
		_, _ = parseTunRoutePrefix(input)
		values := strings.Split(input, "\x00")
		if len(values) > 32 {
			values = values[:32]
		}
		_, _ = parseTunAddrPrefixes(values)
		_, _ = parseTunRoutePrefixes(values)
		_ = randomTUNNameSuffixLength(input)
		_ = defaultTUNName(input, input)

		raw := []byte(input)
		mask := net.CIDRMask(len(raw)%129, 128)
		ip := net.IP(append([]byte(nil), raw...))
		if len(ip) > net.IPv6len {
			ip = ip[:net.IPv6len]
		}
		_, _ = prefixFromIPNet(
			&net.IPNet{IP: ip, Mask: mask},
			netlink.FAMILY_ALL,
		)
		addr, _ := netip.AddrFromSlice(ip)
		_ = netIPFromAddr(addr)

		flags := 0
		if len(raw) >= 4 {
			flags = int(binary.LittleEndian.Uint32(raw[:4]))
		}
		current := []netlink.Addr{
			{
				IPNet: &net.IPNet{
					IP:   append(net.IP(nil), ip...),
					Mask: net.IPMask(append([]byte(nil), raw...)),
				},
				Flags: flags,
			},
			{},
		}
		desired, _ := parseTunAddrPrefixes(values)
		_, _ = normalizeTunAddrPrefixSet(desired)
		_, _ = planTunAddrReconciliation(current, desired)
		for _, prefix := range desired {
			_, _ = planTunAddrAddition(current, prefix)
		}
		for _, value := range current {
			_, _ = tunAddrPrefix(value)
			_ = tunAddrDescription(value)
		}

		adapter := &memoryTunAddrNetlink{
			addrs: append([]netlink.Addr(nil), current...),
		}
		if len(raw) > 4 && raw[4]&1 != 0 {
			adapter.replaceErr = errors.New("fuzz replace failure")
		}
		if changes, err := planTunAddrReconciliation(
			current,
			desired,
		); err == nil {
			_ = applyTunAddrChanges(adapter, nil, changes)
			_ = verifyTunAddrPrefixes(adapter, nil, desired)
		}
		_ = setTunAddrPrefixes(adapter, nil, desired)
		for _, prefix := range desired {
			_ = addTunAddrPrefix(adapter, nil, prefix)
		}
	})
}
