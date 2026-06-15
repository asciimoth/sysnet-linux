//go:build linux

package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-linux/dns/resolvconffile"
)

var (
	SysdResolver = netip.MustParseAddr("127.0.0.53")
)

// DNSProvider implementation should track original upstream DNS resolver
// (e.g. static configured one or DHCP sourced) and use it to serve
// Requests queue regardless of SetDNS being called or not.
// Note that upstream may be dynamic and change over time (e.g. when host
// connects to new network and receive config via DHCP).
//
// DNSProvider should NEVER use server set up via SetDNS to serve Requests
// queue to avoid loops.
//
// After UnsetDNS, DNSProvider implementations that actively maintain the
// server installed by SetDNS by watching system configuration changes and
// rewriting it should stop doing so until SetDNS is called again.
//
// If there are multiple original upstreams (e.g. resolved split dns configuration)
// DNSProvider implementation should handle it correctly under the hood routing
// each request from Requests queue to matching upstream.
//
// It is common for DNSProvider implementations to accept fallback dns server
// at construction time to use in case there is no original upstream provided.
type DNSProvider interface {
	// Requests() chan <- Request
	// Close() error
	dns.Interface

	// SetDNS should set server as a default one for whole system.
	// ALL DNS resolving mechanisms controlled by specific DNSProvider
	// implementation should go use this server for all requests in system except
	// ones done via DNSProvider.Requests queue.
	// All changes done by SetDNS should have lifetime bounded to DNSProvider
	// object and rolled back on close.
	SetDNS(server netip.Addr) error

	// UnsetDNS should roll back changes done by SetDNS, if any. It should be
	// valid to call SetDNS and UnsetDNS multiple times in any order.
	UnsetDNS() error
}

// direct | systemd-resolved | debian-resolvconf | openresolv
//
// NOTE: Borrowed from github.com/tailscale/tailscale
func DnsMode(ctx context.Context, env Env) (ret string, err error) {
	env = env.withDefaults()

	// In all cases that we detect systemd-resolved, try asking it what it
	// thinks the current resolv.conf mode is so we can add it to our logs.
	defer func() {
		if ret != "systemd-resolved" {
			return
		}

		// Try to ask systemd-resolved what it thinks the current
		// status of resolv.conf is. This is documented at:
		//    https://www.freedesktop.org/software/systemd/man/org.freedesktop.resolve1.html
		mode, err := env.DbusReadString(
			ctx,
			"org.freedesktop.resolve1",
			"/org/freedesktop/resolve1",
			"org.freedesktop.resolve1.Manager",
			"ResolvConfMode",
		)
		if err != nil {
			env.Logf("dns: ResolvConfMode error: %v", err)
		} else {
			env.Logf("dns: ResolvConfMode: %s", mode)
		}
	}()

	// Before we read /etc/resolv.conf (which might be in a broken
	// or symlink-dangling state), try to ping the D-Bus service
	// for systemd-resolved. If it's active on the machine, this
	// will make it start up and write the /etc/resolv.conf file
	// before it replies to the ping. (see how systemd's
	// src/resolve/resolved.c calls manager_write_resolv_conf
	// before the sd_event_loop starts)
	resolvedUp := env.DbusPing(
		ctx, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
	) == nil
	if resolvedUp {
		env.Logf("resolved-ping yes")
	}

	bs, err := env.ReadFile(resolvconffile.Path)
	if os.IsNotExist(err) {
		env.Logf("resolvconf missing")
		return "direct", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	typ := ResolvOwner(bs)
	env.Logf("resolvconf: %s", typ)

	switch typ {
	case "systemd-resolved":
		// Some systems, for reasons known only to them, have a
		// resolv.conf that has the word "systemd-resolved" in its
		// header, but doesn't actually point to resolved. We mustn't
		// try to program resolved in that case.
		// https://github.com/tailscale/tailscale/issues/2136
		if err := ResolvedIsActuallyResolver(env, bs); err != nil {
			env.Logf("dns: ResolvedIsActuallyResolver error: %v", err)
			return "direct", nil
		}

		// Unlike tailscale we do not try to detect "save" NetworkManager version
		// here baecuse all modern distros shipping NetworkManager > 1.26.5 today.
		return "systemd-resolved", nil
	case "resolvconf":
		style := env.ResolvconfStyle()
		env.Logf("resolvconf style: %s", style)

		switch style {
		case "":
			return "direct", nil
		case "debian":
			return "debian-resolvconf", nil
		case "openresolv":
			return "openresolv", nil
		default:
			// Shouldn't happen, that means we updated flavors of
			// resolvconf without updating here.
			env.Logf(
				"[unexpected] got unknown flavor of resolvconf %q, falling back to direct manager",
				style,
			)
			return "direct", nil
		}
	case "NetworkManager":
		// Sometimes, NetworkManager owns the configuration but points
		// it at systemd-resolved.
		if err := ResolvedIsActuallyResolver(env, bs); err != nil {
			env.Logf("dns: ResolvedIsActuallyResolver error: %v", err)
			// You'd think we would use newNMManager here. However, as
			// explained in
			// https://github.com/tailscale/tailscale/issues/1699 ,
			// using NetworkManager for DNS configuration carries with
			// it the cost of losing IPv6 configuration on the
			// Tailscale network interface. So, when we can avoid it,
			// we bypass NetworkManager by replacing resolv.conf
			// directly.
			//
			// If you ever try to put NMManager back here, keep in mind
			// that versions >=1.26.6 will ignore DNS configuration
			// anyway, so you still need a fallback path that uses
			// directManager.
			return "direct", nil
		}

		// See large comment above for reasons we'd use NM rather than
		// resolved. systemd-resolved is actually in charge of DNS
		// configuration, but in some cases we might need to configure
		// it via NetworkManager. All the logic below is probing for
		// that case: is NetworkManager running? If so, is it one of
		// the versions that requires direct interaction with it?
		if err := env.DbusPing(
			ctx,
			"org.freedesktop.NetworkManager",
			"/org/freedesktop/NetworkManager/DnsManager",
		); err != nil {
			env.Logf("network-manager ping err: %v", err)
			return "systemd-resolved", nil
		}

		// Unlike tailscale we do not try to detect "save" NetworkManager version
		// here baecuse all modern distros shipping NetworkManager > 1.26.5 today.

		if err := env.NmIsUsingResolved(); err != nil {
			// If systemd-resolved is not running at all, then we don't have any
			// other choice: we take direct control of DNS.
			env.Logf("network-manager not using resolved")
			return "direct", nil
		}

		env.Logf("preferring systemd-resolved over network-manager")
		return "systemd-resolved", nil
	}

	return "direct", nil
}

// ResolvOwner returns the apparent owner of the resolv.conf
// configuration in bs - one of "resolvconf", "systemd-resolved" or
// "NetworkManager", or "" if no known owner was found.
//
// NOTE: Borrowed from github.com/tailscale/tailscale
func ResolvOwner(bs []byte) string {
	likely := ""
	b := bytes.NewBuffer(bs)
	for {
		line, err := b.ReadString('\n')
		if err != nil {
			return likely
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line[0] != '#' {
			// First non-empty, non-comment line. Assume the owner
			// isn't hiding further down.
			return likely
		}

		if strings.Contains(line, "systemd-resolved") { //nolint:gocritic
			likely = "systemd-resolved"
		} else if strings.Contains(line, "NetworkManager") {
			likely = "NetworkManager"
		} else if strings.Contains(line, "resolvconf") {
			likely = "resolvconf"
		}
	}
}

// ResolvedIsActuallyResolver reports whether the system is using
// systemd-resolved as the resolver. There are two different ways to
// use systemd-resolved:
//   - libnss_resolve, which requires adding `resolve` to the "hosts:"
//     line in /etc/nsswitch.conf
//   - setting the only nameserver configured in `resolv.conf` to
//     systemd-resolved IP (127.0.0.53)
//
// Returns an error if the configuration is something other than
// exclusively systemd-resolved, or nil if the config is only
// systemd-resolved.
//
// NOTE: Borrowed from github.com/tailscale/tailscale
func ResolvedIsActuallyResolver(env Env, bs []byte) error {
	if err := IsLibnssResolveUsed(env); err == nil {
		env.Logf("resolved use nss")
		return nil
	}

	cfg, err := resolvconffile.Parse(bytes.NewBuffer(bs))
	if err != nil {
		return err
	}
	// We've encountered at least one system where the line
	// "nameserver 127.0.0.53" appears twice, so we look exhaustively
	// through all of them and allow any number of repeated mentions
	// of the systemd-resolved stub IP.
	if len(cfg.Nameservers) == 0 {
		return errors.New("resolv.conf has no nameservers")
	}
	for _, ns := range cfg.Nameservers {
		if ns != SysdResolver {
			return fmt.Errorf(
				"resolv.conf doesn't point to systemd-resolved; points to %v",
				cfg.Nameservers,
			)
		}
	}
	env.Logf("resolved use file")
	return nil
}

// IsLibnssResolveUsed reports whether libnss_resolve is used
// for resolving names. Returns nil if it is, and an error otherwise.
// NOTE: Borrowed from github.com/tailscale/tailscale
func IsLibnssResolveUsed(env Env) error {
	bs, err := env.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return fmt.Errorf("reading /etc/nsswitch.conf: %w", err)
	}
	for line := range strings.SplitSeq(string(bs), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "hosts:" {
			continue
		}
		for _, module := range fields[1:] {
			if module == "dns" {
				return fmt.Errorf(
					"dns with a higher priority than libnss_resolve",
				)
			}
			if module == "resolve" {
				return nil
			}
		}
	}
	return fmt.Errorf("libnss_resolve not used")
}
