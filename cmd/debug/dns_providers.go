// nolint
package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-linux/dns"
)

func runResolvedDebug(ctx context.Context) error {
	tun, err := createDummyTUN("sysnetdbg%d")
	if err != nil {
		return err
	}
	defer tun.Close()
	fmt.Printf("created dummy TUN %s ifindex=%d\n", tun.name, tun.ifindex)

	addr := debugDNSAddr()
	if err := assignInterfaceAddr(tun.name, addr); err != nil {
		return err
	}
	fmt.Printf("assigned debug DNS address %s/32 to %s\n", addr, tun.name)

	resolved, err := dns.NewResolved(dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	}, tun.ifindex)
	if err != nil {
		return err
	}
	defer func() {
		if err := resolved.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "resolved close: %v\n", err)
		}
	}()

	pc, err := listenDNS(addr)
	if err != nil {
		return err
	}
	logger := newLoggingDNS(resolved)
	defer logger.Close()
	server := gdns.NewServer(pc, logger)
	defer server.Close()

	if err := resolved.SetDNS(addr); err != nil {
		return err
	}
	fmt.Printf("proxying DNS on %s:53 until Ctrl+C\n", addr)
	printResolvedState(tun.name)
	printDebugQueries(addr)

	<-ctx.Done()
	fmt.Println("shutting down")
	return nil
}

func runDirectDebug(ctx context.Context) error {
	addr := netip.MustParseAddr("127.0.0.1")
	direct, err := dns.NewDirect(dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := direct.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "direct close: %v\n", err)
		}
	}()

	pc, err := listenDNS(addr)
	if err != nil {
		return err
	}
	logger := newLoggingDNS(direct)
	defer logger.Close()
	server := gdns.NewServer(pc, logger)
	defer server.Close()

	if err := direct.SetDNS(addr); err != nil {
		return err
	}
	fmt.Printf("proxying DNS on %s:53 until Ctrl+C\n", addr)
	printDirectState()
	printDirectDebugQueries(addr)

	<-ctx.Done()
	fmt.Println("shutting down")
	return nil
}

func runDebianResolvconfDebug(ctx context.Context) error {
	const record = "sysnet-linux"
	addr := netip.MustParseAddr("127.0.0.1")
	provider, err := dns.NewDebianResolvconf(dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	}, record)
	if err != nil {
		return err
	}
	defer func() {
		if err := provider.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "debian-resolvconf close: %v\n", err)
		}
	}()

	pc, err := listenDNS(addr)
	if err != nil {
		return err
	}
	logger := newLoggingDNS(provider)
	defer logger.Close()
	server := gdns.NewServer(pc, logger)
	defer server.Close()

	if err := provider.SetDNS(addr); err != nil {
		return err
	}
	fmt.Printf("proxying DNS on %s:53 until Ctrl+C\n", addr)
	printResolvconfState(record)
	printDirectDebugQueries(addr)

	<-ctx.Done()
	fmt.Println("shutting down")
	return nil
}

func runOpenresolvDebug(ctx context.Context) error {
	const record = "sysnet-linux"
	addr := netip.MustParseAddr("127.0.0.1")
	provider, err := dns.NewOpenresolv(dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	}, record)
	if err != nil {
		return err
	}
	defer func() {
		if err := provider.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "openresolv close: %v\n", err)
		}
	}()

	pc, err := listenDNS(addr)
	if err != nil {
		return err
	}
	logger := newLoggingDNS(provider)
	defer logger.Close()
	server := gdns.NewServer(pc, logger)
	defer server.Close()

	if err := provider.SetDNS(addr); err != nil {
		return err
	}
	fmt.Printf("proxying DNS on %s:53 until Ctrl+C\n", addr)
	printOpenresolvState(record)
	printDirectDebugQueries(addr)

	<-ctx.Done()
	fmt.Println("shutting down")
	return nil
}
