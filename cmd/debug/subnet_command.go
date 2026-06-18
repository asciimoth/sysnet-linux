// nolint
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/asciimoth/sysnet-linux/subnet"
)

const subnetDebugCount = 4

func runSubnetCommand(args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "subnet: unexpected argument %q\n", args[0])
		fmt.Fprintf(os.Stderr, "usage: %s subnet\n", os.Args[0])
		return 2
	}

	alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{})

	fmt.Println("IPv4 subnets:")
	for range subnetDebugCount {
		fmt.Printf("  %v\n", alloc.AllocSubnet4(24))
	}

	fmt.Println("IPv6 subnets:")
	for range subnetDebugCount {
		fmt.Printf("  %v\n", alloc.AllocSubnet6(64))
	}

	fmt.Println("IPv4 addresses:")
	for range subnetDebugCount {
		ip, network := alloc.AllocIP4()
		fmt.Printf("  %v\t%s\n", ip, formatSubnet(network))
	}

	fmt.Println("IPv6 addresses:")
	for range subnetDebugCount {
		ip, network := alloc.AllocIP6()
		fmt.Printf("  %v\t%s\n", ip, formatSubnet(network))
	}

	return 0
}

func formatSubnet(network *net.IPNet) string {
	if network == nil {
		return "<nil>"
	}
	return network.String()
}
