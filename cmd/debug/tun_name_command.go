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

	"github.com/asciimoth/sysnet-linux/subnet"
	systun "github.com/asciimoth/sysnet-linux/tun"
)

const tunNameDefaultMTU = 1420

func runTUNNameCommand(args []string) int {
	if len(args) < 1 {
		printTUNNameUsage()
		return 2
	}

	base := args[0]
	mtu := tunNameDefaultMTU
	args = args[1:]
	if len(args) > 0 && args[0] != "addr" && args[0] != "route" {
		parsedMTU, err := strconv.Atoi(args[0])
		if err != nil || parsedMTU <= 0 {
			fmt.Fprintf(os.Stderr, "tun-name: invalid mtu %q\n", args[0])
			return 2
		}
		mtu = parsedMTU
		args = args[1:]
	}

	addrs, routes, err := parseTUNNameConfigArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tun-name: %v\n", err)
		printTUNNameUsage()
		return 2
	}

	tun, err := systun.CreateDefaultTUN(base, mtu)
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

	defaultAddr, defaultRoute := "", ""
	if len(addrs) == 0 || len(routes) == 0 {
		defaultAddr, defaultRoute = defaultTUNConfig()
	}

	if len(addrs) > 0 {
		if err := systun.SetTunAddrs(tun, addrs); err != nil {
			fmt.Fprintf(os.Stderr, "set addrs: %v\n", err)
			return 1
		}
	} else {
		if defaultAddr != "" {
			if err := systun.AddTunAddr(tun, defaultAddr); err != nil {
				fmt.Fprintf(os.Stderr, "add default addr: %v\n", err)
				return 1
			}
		}
	}

	if err := setInterfaceUp(name); err != nil {
		fmt.Fprintf(os.Stderr, "set interface up: %v\n", err)
		return 1
	}

	if len(routes) > 0 {
		if err := systun.SetTunRoutes(tun, routes); err != nil {
			fmt.Fprintf(os.Stderr, "set routes: %v\n", err)
			return 1
		}
	} else {
		if defaultRoute != "" {
			if err := systun.AddTunRoute(tun, defaultRoute); err != nil {
				fmt.Fprintf(os.Stderr, "add default route: %v\n", err)
				return 1
			}
		}
	}

	finalAddrs, err := systun.GetTunAddrs(tun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get addrs: %v\n", err)
		return 1
	}
	finalRoutes, err := systun.GetTunRotue(tun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get routes: %v\n", err)
		return 1
	}

	fmt.Printf("created tun %s with mtu %d\n", name, mtu)
	fmt.Println("addrs:")
	for _, addr := range finalAddrs {
		fmt.Printf("  %s\n", addr)
	}
	fmt.Println("routes:")
	for _, route := range finalRoutes {
		fmt.Printf("  %s\n", route)
	}
	fmt.Println("press Enter to close it")
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		return 1
	}

	return 0
}

func printTUNNameUsage() {
	fmt.Fprintf(
		os.Stderr,
		"usage: %s tun-name <base> [mtu] [addr <cidr>...] [route <cidr>...]\n",
		os.Args[0],
	)
}

func parseTUNNameConfigArgs(args []string) ([]string, []string, error) {
	var addrs []string
	var routes []string
	var current *[]string
	for _, arg := range args {
		switch arg {
		case "addr":
			current = &addrs
		case "route":
			current = &routes
		default:
			if current == nil {
				return nil, nil, fmt.Errorf("unexpected argument %q", arg)
			}
			*current = append(*current, arg)
		}
	}
	return addrs, routes, nil
}

func defaultTUNConfig() (string, string) {
	alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{})
	ip, network := alloc.AllocIP4()
	if ip == nil || network == nil {
		return "", ""
	}
	return fmt.Sprintf("%s/32", ip), network.String()
}
