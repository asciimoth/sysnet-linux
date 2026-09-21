//go:build linux

package tun

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const unusableIPv6AddrFlags = unix.IFA_F_TENTATIVE | unix.IFA_F_DADFAILED

type tunAddrNetlink interface {
	List(netlink.Link) ([]netlink.Addr, error)
	Replace(netlink.Link, *netlink.Addr) error
	Delete(netlink.Link, *netlink.Addr) error
}

type realTunAddrNetlink struct{}

func (realTunAddrNetlink) List(link netlink.Link) ([]netlink.Addr, error) {
	return netlink.AddrList(link, netlink.FAMILY_ALL)
}

func (realTunAddrNetlink) Replace(
	link netlink.Link,
	addr *netlink.Addr,
) error {
	return netlink.AddrReplace(link, addr)
}

func (realTunAddrNetlink) Delete(
	link netlink.Link,
	addr *netlink.Addr,
) error {
	return netlink.AddrDel(link, addr)
}

type tunAddrChangeKind uint8

const (
	tunAddrReplace tunAddrChangeKind = iota
	tunAddrDelete
)

type tunAddrChange struct {
	kind   tunAddrChangeKind
	addr   netlink.Addr
	prefix netip.Prefix
}

func setTunAddrPrefixes(
	adapter tunAddrNetlink,
	link netlink.Link,
	prefixes []netip.Prefix,
) error {
	desired, err := normalizeTunAddrPrefixSet(prefixes)
	if err != nil {
		return err
	}
	current, err := adapter.List(link)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	changes, err := planTunAddrReconciliation(current, desired)
	if err != nil {
		return err
	}
	if err := applyTunAddrChanges(adapter, link, changes); err != nil {
		return err
	}
	return verifyTunAddrPrefixes(adapter, link, desired)
}

func addTunAddrPrefix(
	adapter tunAddrNetlink,
	link netlink.Link,
	prefix netip.Prefix,
) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid address prefix %s", prefix)
	}
	current, err := adapter.List(link)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	changes, err := planTunAddrAddition(current, prefix)
	if err != nil {
		return err
	}
	if err := applyTunAddrChanges(adapter, link, changes); err != nil {
		return err
	}
	return verifyTunAddrPrefixes(adapter, link, []netip.Prefix{prefix})
}

func normalizeTunAddrPrefixSet(
	prefixes []netip.Prefix,
) ([]netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	prefixBits := make(map[netip.Addr]int, len(prefixes))
	normalized := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("invalid address prefix %s", prefix)
		}
		if bits, ok := prefixBits[prefix.Addr()]; ok && bits != prefix.Bits() {
			return nil, fmt.Errorf(
				"address %s has conflicting prefix lengths %d and %d",
				prefix.Addr(),
				bits,
				prefix.Bits(),
			)
		}
		prefixBits[prefix.Addr()] = prefix.Bits()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	return normalized, nil
}

func planTunAddrReconciliation(
	current []netlink.Addr,
	desired []netip.Prefix,
) ([]tunAddrChange, error) {
	desired, err := normalizeTunAddrPrefixSet(desired)
	if err != nil {
		return nil, err
	}
	desiredSet := make(map[netip.Prefix]struct{}, len(desired))
	for _, prefix := range desired {
		desiredSet[prefix] = struct{}{}
	}

	currentPrefixes := make([]netip.Prefix, len(current))
	currentValid := make([]bool, len(current))
	currentByPrefix := make(map[netip.Prefix]int, len(current))
	currentByIP := make(map[netip.Addr][]int, len(current))
	retained := make([]bool, len(current))
	deleted := make([]bool, len(current))
	for i := range current {
		prefix, ok := tunAddrPrefix(current[i])
		if !ok {
			continue
		}
		currentPrefixes[i] = prefix
		currentValid[i] = true
		if _, exists := currentByPrefix[prefix]; !exists {
			currentByPrefix[prefix] = i
		}
		currentByIP[prefix.Addr()] = append(
			currentByIP[prefix.Addr()],
			i,
		)
		if _, ok := desiredSet[prefix]; ok {
			retained[i] = true
		}
	}

	changes := make([]tunAddrChange, 0, len(current)+len(desired))
	for _, prefix := range desired {
		i, ok := currentByPrefix[prefix]
		if !ok || !prefix.Addr().Is6() {
			continue
		}
		flags := current[i].Flags
		if flags&unusableIPv6AddrFlags != 0 || flags&unix.IFA_F_NODAD != 0 {
			continue
		}
		change, err := replaceTunAddrChange(prefix)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}

	for _, prefix := range desired {
		if _, ok := currentByPrefix[prefix]; ok {
			continue
		}
		if len(currentByIP[prefix.Addr()]) != 0 {
			continue
		}
		change, err := replaceTunAddrChange(prefix)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}

	for _, prefix := range desired {
		i, ok := currentByPrefix[prefix]
		if !ok || !prefix.Addr().Is6() ||
			current[i].Flags&unusableIPv6AddrFlags == 0 {
			continue
		}
		changes = append(changes, deleteTunAddrChange(current[i]))
		deleted[i] = true
		change, err := replaceTunAddrChange(prefix)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}

	for _, prefix := range desired {
		if _, ok := currentByPrefix[prefix]; ok {
			continue
		}
		conflicts := currentByIP[prefix.Addr()]
		if len(conflicts) == 0 {
			continue
		}
		for _, i := range conflicts {
			if deleted[i] {
				continue
			}
			changes = append(changes, deleteTunAddrChange(current[i]))
			deleted[i] = true
		}
		change, err := replaceTunAddrChange(prefix)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}

	for i := range current {
		if retained[i] || deleted[i] {
			continue
		}
		if currentValid[i] {
			if _, ok := desiredSet[currentPrefixes[i]]; ok {
				continue
			}
		}
		changes = append(changes, deleteTunAddrChange(current[i]))
	}
	return changes, nil
}

func planTunAddrAddition(
	current []netlink.Addr,
	prefix netip.Prefix,
) ([]tunAddrChange, error) {
	if !prefix.IsValid() {
		return nil, fmt.Errorf("invalid address prefix %s", prefix)
	}
	if !prefix.Addr().Is6() {
		change, err := replaceTunAddrChange(prefix)
		if err != nil {
			return nil, err
		}
		return []tunAddrChange{change}, nil
	}

	var conflicts []int
	for i := range current {
		currentPrefix, ok := tunAddrPrefix(current[i])
		if !ok || currentPrefix.Addr() != prefix.Addr() {
			continue
		}
		if currentPrefix != prefix {
			conflicts = append(conflicts, i)
			continue
		}
		return planExistingIPv6AddrAddition(current[i], prefix)
	}

	changes := make([]tunAddrChange, 0, len(conflicts)+1)
	for _, i := range conflicts {
		changes = append(changes, deleteTunAddrChange(current[i]))
	}
	change, err := replaceTunAddrChange(prefix)
	if err != nil {
		return nil, err
	}
	return append(changes, change), nil
}

func planExistingIPv6AddrAddition(
	current netlink.Addr,
	prefix netip.Prefix,
) ([]tunAddrChange, error) {
	if current.Flags&unix.IFA_F_NODAD != 0 &&
		current.Flags&unusableIPv6AddrFlags == 0 {
		return nil, nil
	}
	change, err := replaceTunAddrChange(prefix)
	if err != nil {
		return nil, err
	}
	if current.Flags&unusableIPv6AddrFlags == 0 {
		return []tunAddrChange{change}, nil
	}
	return []tunAddrChange{
		deleteTunAddrChange(current),
		change,
	}, nil
}

func replaceTunAddrChange(prefix netip.Prefix) (tunAddrChange, error) {
	addr, err := netlinkAddrFromPrefix(prefix)
	if err != nil {
		return tunAddrChange{}, err
	}
	return tunAddrChange{
		kind:   tunAddrReplace,
		addr:   *addr,
		prefix: prefix,
	}, nil
}

func deleteTunAddrChange(addr netlink.Addr) tunAddrChange {
	prefix, _ := tunAddrPrefix(addr)
	return tunAddrChange{
		kind:   tunAddrDelete,
		addr:   addr,
		prefix: prefix,
	}
}

func applyTunAddrChanges(
	adapter tunAddrNetlink,
	link netlink.Link,
	changes []tunAddrChange,
) error {
	for i := range changes {
		change := &changes[i]
		switch change.kind {
		case tunAddrReplace:
			if err := adapter.Replace(link, &change.addr); err != nil {
				return fmt.Errorf(
					"replace address %s: %w",
					change.prefix,
					err,
				)
			}
		case tunAddrDelete:
			if err := adapter.Delete(link, &change.addr); err != nil {
				return fmt.Errorf(
					"delete address %s: %w",
					tunAddrDescription(change.addr),
					err,
				)
			}
		default:
			return fmt.Errorf("unknown address change kind %d", change.kind)
		}
	}
	return nil
}

func verifyTunAddrPrefixes(
	adapter tunAddrNetlink,
	link netlink.Link,
	desired []netip.Prefix,
) error {
	current, err := adapter.List(link)
	if err != nil {
		return fmt.Errorf("verify addresses: %w", err)
	}
	currentByPrefix := make(map[netip.Prefix]netlink.Addr, len(current))
	for _, addr := range current {
		prefix, ok := tunAddrPrefix(addr)
		if ok {
			currentByPrefix[prefix] = addr
		}
	}
	for _, prefix := range desired {
		addr, ok := currentByPrefix[prefix]
		if !ok {
			return fmt.Errorf("verify address %s: address is absent", prefix)
		}
		if !prefix.Addr().Is6() {
			continue
		}
		if addr.Flags&unix.IFA_F_NODAD == 0 {
			return fmt.Errorf(
				"verify address %s: IFA_F_NODAD is not set",
				prefix,
			)
		}
		if addr.Flags&unusableIPv6AddrFlags != 0 {
			return fmt.Errorf(
				"verify address %s: unusable flags %#x",
				prefix,
				addr.Flags&unusableIPv6AddrFlags,
			)
		}
	}
	return nil
}

func tunAddrPrefix(addr netlink.Addr) (netip.Prefix, bool) {
	if addr.IPNet == nil {
		return netip.Prefix{}, false
	}
	ones, bits := addr.Mask.Size()
	if ones < 0 {
		return netip.Prefix{}, false
	}
	ip, ok := addrFromIP(addr.IP)
	if !ok || ip.BitLen() != bits {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip, ones), true
}

func tunAddrDescription(addr netlink.Addr) string {
	if prefix, ok := tunAddrPrefix(addr); ok {
		return prefix.String()
	}
	return addr.String()
}
