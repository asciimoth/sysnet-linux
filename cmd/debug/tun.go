// nolint
package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

type dummyTUN struct {
	fd      int
	name    string
	ifindex int
}

func (t *dummyTUN) Close() error {
	if t.fd < 0 {
		return nil
	}
	err := unix.Close(t.fd)
	t.fd = -1
	return err
}

func createDummyTUN(pattern string) (*dummyTUN, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(pattern)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create tun ifreq: %w", err)
	}
	ifr.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}

	name := ifr.Name()
	if err := setInterfaceUp(name); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("lookup interface %s: %w", name, err)
	}
	return &dummyTUN{fd: fd, name: name, ifindex: iface.Index}, nil
}

func setInterfaceUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open control socket: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("create flags ifreq: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS(%s): %w", name, err)
	}
	ifr.SetUint16(ifr.Uint16() | uint16(unix.IFF_UP))
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS(%s): %w", name, err)
	}
	return nil
}

func debugDNSAddr() netip.Addr {
	pid := os.Getpid()
	return netip.AddrFrom4([4]byte{
		198,
		18,
		byte(pid >> 8),
		byte(pid%254 + 1),
	})
}

func assignInterfaceAddr(name string, addr netip.Addr) error {
	cmd := exec.Command(
		"ip",
		"addr",
		"replace",
		addr.String()+"/32",
		"dev",
		name,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"assign %s/32 to %s with ip(8): %w: %s",
			addr,
			name,
			err,
			strings.TrimSpace(string(out)),
		)
	}
	return nil
}
