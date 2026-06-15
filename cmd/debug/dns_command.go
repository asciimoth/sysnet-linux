// nolint
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/asciimoth/sysnet-linux/dns"
)

func runDNSCommand(args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "dns: unexpected argument %q\n", args[0])
		fmt.Fprintf(os.Stderr, "usage: %s dns\n", os.Args[0])
		return 2
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	mode, err := dns.DnsMode(context.Background(), dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
		ReadFile:          os.ReadFile,
		DbusReadString:    dns.DbusReadString,
		DbusPing:          dns.DbusPing,
		ResolvconfStyle:   dns.ResolvconfStyle,
		NmIsUsingResolved: dns.NmIsUsingResolved,
	})
	fmt.Println(mode, err)
	if err != nil {
		return 1
	}

	switch mode {
	case "systemd-resolved":
		if err := runResolvedDebug(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "debug resolved: %v\n", err)
			return 1
		}
	case "direct":
		if err := runDirectDebug(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "debug direct: %v\n", err)
			return 1
		}
	case "debian-resolvconf":
		if err := runDebianResolvconfDebug(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "debug debian-resolvconf: %v\n", err)
			return 1
		}
	case "openresolv":
		if err := runOpenresolvDebug(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "debug openresolv: %v\n", err)
			return 1
		}
	default:
		fmt.Println("mode not supported")
	}

	return 0
}
