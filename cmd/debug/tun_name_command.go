//go:build linux

// nolint
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	systun "github.com/asciimoth/sysnet-linux/tun"
)

const tunNameDefaultMTU = 1420

func runTUNNameCommand(args []string) int {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintf(os.Stderr, "usage: %s tun-name <base> [mtu]\n", os.Args[0])
		return 2
	}

	mtu := tunNameDefaultMTU
	if len(args) == 2 {
		parsedMTU, err := strconv.Atoi(args[1])
		if err != nil || parsedMTU <= 0 {
			fmt.Fprintf(os.Stderr, "tun-name: invalid mtu %q\n", args[1])
			return 2
		}
		mtu = parsedMTU
	}

	tun, err := systun.CreateDefaultTUN(args[0], mtu)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create tun: %v\n", err)
		return 1
	}
	defer tun.Close() //nolint:errcheck

	name, err := tun.Name()
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"created tun, but failed to read name: %v\n",
			err,
		)
		return 1
	}

	fmt.Printf("created tun %s with mtu %d\n", name, mtu)
	fmt.Println("press Enter to close it")
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		return 1
	}

	return 0
}
