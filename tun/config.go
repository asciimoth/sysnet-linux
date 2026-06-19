//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"unsafe"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	"golang.org/x/sys/unix"
)

const (
	defaultTunMTU            = 1420
	minTunMTU                = 576
	netlinkReceiveBufferSize = 1 << 20
)

var nativeEndian binary.ByteOrder = binary.NativeEndian

// SetTunMTU updates MTU of provided Tun.
//
// The Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is
// returned. Values lower than the IPv4 minimum MTU are replaced with a sensible
// default of 1420 bytes.
func SetTunMTU(tun gtun.Tun, mtu int) error {
	if mtu < minTunMTU {
		mtu = defaultTunMTU
	}

	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open control socket: %w", err)
	}
	defer func() {
		_ = unix.Close(fd)
	}()

	ifr, err := unix.NewIfreq(info.name)
	if err != nil {
		return fmt.Errorf("create MTU ifreq: %w", err)
	}
	mtuValue, err := uint32FromInt(mtu, "MTU")
	if err != nil {
		return err
	}
	ifr.SetUint32(mtuValue)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFMTU, ifr); err != nil {
		return fmt.Errorf("set MTU of %s: %w", info.name, err)
	}
	return nil
}

// SetTunAddrs updates list off addrs of provided Tun.
//
// Existing interface addresses are removed before the new CIDR addresses are
// added. The Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is
// returned.
func SetTunAddrs(tun gtun.Tun, addrs []string) error {
	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	prefixes, err := parseTunAddrPrefixes(addrs)
	if err != nil {
		return err
	}

	current, err := getTunAddrs(info.index)
	if err != nil {
		return err
	}
	for _, addr := range current {
		if err := updateTunAddr(
			info.index,
			unix.RTM_DELADDR,
			addr,
		); err != nil {
			return err
		}
	}
	for i, prefix := range prefixes {
		if err := updateTunAddrPrefix(
			info.index,
			unix.RTM_NEWADDR,
			prefix,
			addrs[i],
		); err != nil {
			return err
		}
	}
	return nil
}

// AddTunAddr updates list off addrs of provided Tun.
//
// The address must be a CIDR prefix such as "10.0.0.1/32" or "fd00::1/128".
// The Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is
// returned.
func AddTunAddr(tun gtun.Tun, addr string) error {
	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	return addTunAddrByIndex(info.index, addr)
}

// GetTunAddrs returns list off addrs of provided Tun.
//
// Returned entries are CIDR prefixes assigned to the interface. The Tun must
// expose a non-nil File; otherwise sysnet.ErrUnknownTun is returned.
func GetTunAddrs(tun gtun.Tun) ([]string, error) {
	info, err := tunFileInfo(tun)
	if err != nil {
		return nil, err
	}
	return getTunAddrs(info.index)
}

// SetTunRoutes updates list off routes of provided Tun.
//
// Existing main-table routes whose output interface is the Tun are removed
// before the provided CIDR routes are added. The Tun must expose a non-nil
// File; otherwise sysnet.ErrUnknownTun is returned.
func SetTunRoutes(tun gtun.Tun, routes []string) error {
	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	prefixes, err := parseTunRoutePrefixes(routes)
	if err != nil {
		return err
	}

	current, err := getTunRoutes(info.index)
	if err != nil {
		return err
	}
	for _, route := range current {
		if err := updateTunRoute(
			info.index,
			unix.RTM_DELROUTE,
			route,
		); err != nil {
			return err
		}
	}
	for i, prefix := range prefixes {
		if err := updateTunRoutePrefix(
			info.index,
			unix.RTM_NEWROUTE,
			prefix,
			routes[i],
		); err != nil {
			return err
		}
	}
	return nil
}

// AddTunRoute updates list off routes of provided Tun.
//
// The route must be a CIDR prefix such as "10.0.0.0/24" or "fd00::/64". The
// Tun must expose a non-nil File; otherwise sysnet.ErrUnknownTun is returned.
func AddTunRoute(tun gtun.Tun, route string) error {
	info, err := tunFileInfo(tun)
	if err != nil {
		return err
	}
	return addTunRouteByIndex(info.index, route)
}

// GetTunRotue returns list off routes of provided Tun.
//
// The misspelling is kept to match the gonnect sysnet.System interface. The Tun
// must expose a non-nil File; otherwise sysnet.ErrUnknownTun is returned.
func GetTunRotue(tun gtun.Tun) ([]string, error) {
	info, err := tunFileInfo(tun)
	if err != nil {
		return nil, err
	}
	return getTunRoutes(info.index)
}

// SetTunName updates name of provided Tun.
//
// The current gonnect sysnet.System interface does not provide a replacement
// name argument, so this function validates that the Tun is known through its
// File and returns the current kernel interface name. If File is nil,
// sysnet.ErrUnknownTun is returned.
func SetTunName(tun gtun.Tun) ([]string, error) {
	info, err := tunFileInfo(tun)
	if err != nil {
		return nil, err
	}
	return []string{info.name}, nil
}

type tunInfo struct {
	name  string
	index int
}

func tunFileInfo(tun gtun.Tun) (tunInfo, error) {
	if tun == nil {
		return tunInfo{}, sysnet.ErrUnknownTun
	}
	file := tun.File()
	if file == nil {
		return tunInfo{}, sysnet.ErrUnknownTun
	}

	ifr, err := unix.NewIfreq("")
	if err != nil {
		return tunInfo{}, fmt.Errorf("create TUNGETIFF ifreq: %w", err)
	}
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNGETIFF, ifr); err != nil {
		return tunInfo{}, fmt.Errorf("TUNGETIFF: %w", err)
	}

	iface, err := net.InterfaceByName(ifr.Name())
	if err != nil {
		return tunInfo{}, fmt.Errorf("lookup interface %s: %w", ifr.Name(), err)
	}
	return tunInfo{name: ifr.Name(), index: iface.Index}, nil
}

func addTunAddrByIndex(index int, addr string) error {
	prefix, err := parseTunAddrPrefix(addr)
	if err != nil {
		return err
	}
	return updateTunAddrPrefix(index, unix.RTM_NEWADDR, prefix, addr)
}

func updateTunAddr(index int, msgType uint16, addr string) error {
	prefix, err := parseTunAddrPrefix(addr)
	if err != nil {
		return err
	}
	return updateTunAddrPrefix(index, msgType, prefix, addr)
}

func updateTunAddrPrefix(
	index int,
	msgType uint16,
	prefix netip.Prefix,
	display string,
) error {
	ifindex, err := uint32FromInt(index, "interface index")
	if err != nil {
		return err
	}
	prefixLen, err := uint8FromInt(prefix.Bits(), "prefix length")
	if err != nil {
		return err
	}

	msg := unix.IfAddrmsg{
		Family:    addrFamily(prefix.Addr()),
		Prefixlen: prefixLen,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Index:     ifindex,
	}
	attrs := appendNetlinkAttr(nil, unix.IFA_LOCAL, addrBytes(prefix.Addr()))
	attrs = appendNetlinkAttr(attrs, unix.IFA_ADDRESS, addrBytes(prefix.Addr()))

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	if msgType == unix.RTM_NEWADDR {
		flags |= unix.NLM_F_CREATE | unix.NLM_F_REPLACE
	}
	if err := netlinkRequest(
		msgType,
		flags,
		structBytes(msg),
		attrs,
	); err != nil {
		return fmt.Errorf("update address %s: %w", display, err)
	}
	return nil
}

func getTunAddrs(index int) ([]string, error) {
	ifindex, err := uint32FromInt(index, "interface index")
	if err != nil {
		return nil, err
	}
	msg := unix.IfAddrmsg{Family: unix.AF_UNSPEC, Index: ifindex}
	replies, err := netlinkDump(unix.RTM_GETADDR, structBytes(msg))
	if err != nil {
		return nil, fmt.Errorf("get addresses: %w", err)
	}

	var out []string
	for _, reply := range replies {
		if reply.header.Type != unix.RTM_NEWADDR {
			continue
		}
		if len(reply.data) < int(unsafe.Sizeof(unix.IfAddrmsg{})) {
			continue
		}
		// #nosec G103 -- reply.data length is checked before this kernel struct view.
		addrMsg := *(*unix.IfAddrmsg)(unsafe.Pointer(&reply.data[0]))
		if addrMsg.Index != ifindex {
			continue
		}
		attrStart := int(unsafe.Sizeof(unix.IfAddrmsg{}))
		attrs := parseNetlinkAttrs(reply.data[attrStart:])
		raw := attrs[unix.IFA_LOCAL]
		if len(raw) == 0 {
			raw = attrs[unix.IFA_ADDRESS]
		}
		addr, ok := addrFromBytes(addrMsg.Family, raw)
		if !ok {
			continue
		}
		out = append(
			out,
			netip.PrefixFrom(addr, int(addrMsg.Prefixlen)).String(),
		)
	}
	return out, nil
}

func addTunRouteByIndex(index int, route string) error {
	prefix, err := parseTunRoutePrefix(route)
	if err != nil {
		return err
	}
	return updateTunRoutePrefix(index, unix.RTM_NEWROUTE, prefix, route)
}

func updateTunRoute(index int, msgType uint16, route string) error {
	prefix, err := parseTunRoutePrefix(route)
	if err != nil {
		return err
	}
	return updateTunRoutePrefix(index, msgType, prefix, route)
}

func updateTunRoutePrefix(
	index int,
	msgType uint16,
	prefix netip.Prefix,
	display string,
) error {
	ifindex, err := int32FromInt(index, "interface index")
	if err != nil {
		return err
	}
	prefixLen, err := uint8FromInt(prefix.Bits(), "prefix length")
	if err != nil {
		return err
	}

	msg := unix.RtMsg{
		Family:   addrFamily(prefix.Addr()),
		Dst_len:  prefixLen,
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_LINK,
		Type:     unix.RTN_UNICAST,
	}

	var attrs []byte
	if prefix.Bits() > 0 {
		attrs = appendNetlinkAttr(attrs, unix.RTA_DST, routeDstBytes(prefix))
	}
	attrs = appendNetlinkAttr(attrs, unix.RTA_OIF, int32Bytes(ifindex))

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	if msgType == unix.RTM_NEWROUTE {
		flags |= unix.NLM_F_CREATE | unix.NLM_F_REPLACE
	}
	if err := netlinkRequest(
		msgType,
		flags,
		structBytes(msg),
		attrs,
	); err != nil {
		return fmt.Errorf("update route %s: %w", display, err)
	}
	return nil
}

func getTunRoutes(index int) ([]string, error) {
	ifindex, err := uint32FromInt(index, "interface index")
	if err != nil {
		return nil, err
	}
	msg := unix.RtMsg{Family: unix.AF_UNSPEC, Table: unix.RT_TABLE_MAIN}
	replies, err := netlinkDump(unix.RTM_GETROUTE, structBytes(msg))
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	var out []string
	for _, reply := range replies {
		if reply.header.Type != unix.RTM_NEWROUTE {
			continue
		}
		if len(reply.data) < int(unsafe.Sizeof(unix.RtMsg{})) {
			continue
		}
		// #nosec G103 -- reply.data length is checked before this kernel struct view.
		routeMsg := *(*unix.RtMsg)(unsafe.Pointer(&reply.data[0]))
		if routeMsg.Table != unix.RT_TABLE_MAIN ||
			routeMsg.Type != unix.RTN_UNICAST {
			continue
		}

		attrStart := int(unsafe.Sizeof(unix.RtMsg{}))
		attrs := parseNetlinkAttrs(reply.data[attrStart:])
		oif := attrs[unix.RTA_OIF]
		if len(oif) < 4 || nativeEndian.Uint32(oif[:4]) != ifindex {
			continue
		}
		addr, ok := routeAddrFromBytes(routeMsg.Family, attrs[unix.RTA_DST])
		if !ok {
			continue
		}
		out = append(
			out,
			netip.PrefixFrom(addr, int(routeMsg.Dst_len)).String(),
		)
	}
	return out, nil
}

type netlinkMessage struct {
	header unix.NlMsghdr
	data   []byte
}

func netlinkRequest(msgType uint16, flags uint16, payloads ...[]byte) error {
	replies, err := netlinkRoundTrip(msgType, flags, payloads...)
	if err != nil {
		return err
	}
	for _, reply := range replies {
		if reply.header.Type != unix.NLMSG_ERROR {
			continue
		}
		if len(reply.data) < int(unsafe.Sizeof(unix.NlMsgerr{})) {
			return errors.New("short netlink error response")
		}
		// #nosec G103 -- reply.data length is checked before this kernel struct view.
		nlerr := *(*unix.NlMsgerr)(unsafe.Pointer(&reply.data[0]))
		if nlerr.Error != 0 {
			return unix.Errno(-nlerr.Error)
		}
		return nil
	}
	return nil
}

func netlinkDump(msgType uint16, payload []byte) ([]netlinkMessage, error) {
	return netlinkRoundTrip(
		msgType,
		unix.NLM_F_REQUEST|unix.NLM_F_DUMP,
		payload,
	)
}

func netlinkRoundTrip(
	msgType uint16,
	flags uint16,
	payloads ...[]byte,
) ([]netlinkMessage, error) {
	fd, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		return nil, fmt.Errorf("open netlink socket: %w", err)
	}
	defer func() {
		_ = unix.Close(fd)
	}()

	if err := unix.Bind(
		fd,
		&unix.SockaddrNetlink{Family: unix.AF_NETLINK},
	); err != nil {
		return nil, fmt.Errorf("bind netlink socket: %w", err)
	}

	var body []byte
	for _, payload := range payloads {
		body = append(body, payload...)
	}
	msgLen, err := uint32FromInt(
		int(unsafe.Sizeof(unix.NlMsghdr{}))+len(body),
		"netlink message length",
	)
	if err != nil {
		return nil, err
	}
	header := unix.NlMsghdr{
		Len:   msgLen,
		Type:  msgType,
		Flags: flags,
		Seq:   1,
	}
	request := append(structBytes(header), body...)
	if err := unix.Sendto(
		fd,
		request,
		0,
		&unix.SockaddrNetlink{Family: unix.AF_NETLINK},
	); err != nil {
		return nil, fmt.Errorf("send netlink request: %w", err)
	}

	var replies []netlinkMessage
	for {
		buf := make([]byte, netlinkReceiveBufferSize)
		n, _, recvFlags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("receive netlink response: %w", err)
		}
		if recvFlags&unix.MSG_TRUNC != 0 {
			return nil, errors.New("truncated netlink response")
		}
		done, msgs, err := parseNetlinkMessages(buf[:n])
		if err != nil {
			return nil, err
		}
		if err := checkNetlinkErrors(msgs); err != nil {
			return nil, err
		}
		replies = append(replies, msgs...)
		if done || !isNetlinkDumpRequest(flags) {
			return replies, nil
		}
	}
}

func isNetlinkDumpRequest(flags uint16) bool {
	return flags&unix.NLM_F_DUMP == unix.NLM_F_DUMP
}

func parseNetlinkMessages(buf []byte) (bool, []netlinkMessage, error) {
	var replies []netlinkMessage
	for len(buf) >= int(unsafe.Sizeof(unix.NlMsghdr{})) {
		// #nosec G103 -- buf length is checked before this kernel struct view.
		header := *(*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
		if header.Len < uint32(unsafe.Sizeof(unix.NlMsghdr{})) ||
			int(header.Len) > len(buf) {
			return false, nil, errors.New("invalid netlink message length")
		}

		payloadStart := int(unsafe.Sizeof(unix.NlMsghdr{}))
		payloadEnd := int(header.Len)
		data := append([]byte(nil), buf[payloadStart:payloadEnd]...)
		if header.Type == unix.NLMSG_DONE {
			return true, replies, nil
		}
		replies = append(replies, netlinkMessage{header: header, data: data})
		next := netlinkAlign(int(header.Len))
		if next > len(buf) {
			next = len(buf)
		}
		buf = buf[next:]
	}
	return false, replies, nil
}

func checkNetlinkErrors(msgs []netlinkMessage) error {
	for _, msg := range msgs {
		if msg.header.Type != unix.NLMSG_ERROR {
			continue
		}
		if len(msg.data) < int(unsafe.Sizeof(unix.NlMsgerr{})) {
			return errors.New("short netlink error response")
		}
		// #nosec G103 -- msg.data length is checked before this kernel struct view.
		nlerr := *(*unix.NlMsgerr)(unsafe.Pointer(&msg.data[0]))
		if nlerr.Error != 0 {
			return unix.Errno(-nlerr.Error)
		}
	}
	return nil
}

func parseNetlinkAttrs(buf []byte) map[uint16][]byte {
	attrs := make(map[uint16][]byte)
	for len(buf) >= int(unsafe.Sizeof(unix.RtAttr{})) {
		// #nosec G103 -- buf length is checked before this kernel struct view.
		attr := *(*unix.RtAttr)(unsafe.Pointer(&buf[0]))
		if attr.Len < uint16(unsafe.Sizeof(unix.RtAttr{})) ||
			int(attr.Len) > len(buf) {
			break
		}
		start := int(unsafe.Sizeof(unix.RtAttr{}))
		attrs[attr.Type] = append([]byte(nil), buf[start:int(attr.Len)]...)
		next := netlinkAlign(int(attr.Len))
		if next > len(buf) {
			next = len(buf)
		}
		buf = buf[next:]
	}
	return attrs
}

func appendNetlinkAttr(buf []byte, typ uint16, data []byte) []byte {
	attrLen := int(unsafe.Sizeof(unix.RtAttr{})) + len(data)
	attrLenValue, err := uint16FromInt(attrLen, "netlink attribute length")
	if err != nil {
		panic(err)
	}
	attr := unix.RtAttr{Len: attrLenValue, Type: typ}
	buf = append(buf, structBytes(attr)...)
	buf = append(buf, data...)
	for len(buf)%unix.RTA_ALIGNTO != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func netlinkAlign(n int) int {
	return (n + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1)
}

func parseTunAddrPrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := parseTunAddrPrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseTunRoutePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := parseTunRoutePrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseTunAddrPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err == nil {
		return prefix, nil
	}
	addr, addrErr := netip.ParseAddr(value)
	if addrErr != nil {
		return netip.Prefix{}, fmt.Errorf(
			"parse CIDR prefix %q: %w",
			value,
			err,
		)
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func parseTunRoutePrefix(value string) (netip.Prefix, error) {
	prefix, err := parseTunAddrPrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return prefix.Masked(), nil
}

func addrFamily(addr netip.Addr) uint8 {
	if addr.Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

func addrBytes(addr netip.Addr) []byte {
	if addr.Is4() {
		v := addr.As4()
		return v[:]
	}
	v := addr.As16()
	return v[:]
}

func routeDstBytes(prefix netip.Prefix) []byte {
	addr := prefix.Masked().Addr()
	return append([]byte(nil), addrBytes(addr)...)
}

func addrFromBytes(family uint8, raw []byte) (netip.Addr, bool) {
	switch family {
	case unix.AF_INET:
		if len(raw) < net.IPv4len {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(raw[:4])), true
	case unix.AF_INET6:
		if len(raw) < net.IPv6len {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(raw[:16])), true
	default:
		return netip.Addr{}, false
	}
}

func routeAddrFromBytes(family uint8, raw []byte) (netip.Addr, bool) {
	switch family {
	case unix.AF_INET:
		var b [4]byte
		copy(b[:], raw)
		return netip.AddrFrom4(b), true
	case unix.AF_INET6:
		var b [16]byte
		copy(b[:], raw)
		return netip.AddrFrom16(b), true
	default:
		return netip.Addr{}, false
	}
}

func int32Bytes(v int32) []byte {
	var out [4]byte
	//nolint:gosec // Netlink encodes ifindex as a 32-bit field.
	nativeEndian.PutUint32(out[:], uint32(v))
	return out[:]
}

func uint8FromInt(v int, name string) (uint8, error) {
	if v < 0 || v > math.MaxUint8 {
		return 0, fmt.Errorf("%s %d overflows uint8", name, v)
	}
	return uint8(v), nil //nolint:gosec // Bounds are checked above.
}

func uint16FromInt(v int, name string) (uint16, error) {
	if v < 0 || v > math.MaxUint16 {
		return 0, fmt.Errorf("%s %d overflows uint16", name, v)
	}
	return uint16(v), nil //nolint:gosec // Bounds are checked above.
}

func uint32FromInt(v int, name string) (uint32, error) {
	if v < 0 {
		return 0, fmt.Errorf("%s %d overflows uint32", name, v)
	}
	value := uint64(v) //nolint:gosec // Non-negative and checked below.
	if value > math.MaxUint32 {
		return 0, fmt.Errorf("%s %d overflows uint32", name, v)
	}
	return uint32(value), nil //nolint:gosec // Bounds are checked above.
}

func int32FromInt(v int, name string) (int32, error) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, fmt.Errorf("%s %d overflows int32", name, v)
	}
	return int32(v), nil //nolint:gosec // Bounds are checked above.
}

func structBytes[T any](v T) []byte {
	size := int(unsafe.Sizeof(v))
	// #nosec G103 -- syscall payloads need native in-memory struct layout.
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(&v)), size))
}
