//go:build linux

// nolint
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/asciimoth/sysnet-linux/killswitch"
)

func runKillswitchCommand(args []string) int {
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "killswitch: unexpected argument %q\n", args[1])
		fmt.Fprintf(
			os.Stderr,
			"usage: %s killswitch [admin-socket]\n",
			os.Args[0],
		)
		return 2
	}
	adminSocket := ""
	if len(args) == 1 {
		adminSocket = args[0]
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	client := killswitch.NewClient(
		adminSocket,
		func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	)
	defer client.Close() //nolint:errcheck

	id, err := client.CreateTMPRuleset(killswitch.AllowRules{
		EnableV4:     true,
		EnableV6:     true,
		AllowedPorts: []string{"tcp/443", "udp/53"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create killswitch temporary ruleset: %v\n", err)
		return 1
	}

	fmt.Printf("created temporary killswitch ruleset %d\n", id)
	fmt.Println("waiting for Ctrl+C")
	<-ctx.Done()

	return 0
}
