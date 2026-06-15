// nolint
package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

func printDebugQueries(addr netip.Addr) {
	uncachedName := fmt.Sprintf(
		"sysnet-debug-%d.example.com",
		time.Now().UnixNano(),
	)
	fmt.Printf("direct proxy check: dig @%s %s\n", addr, uncachedName)
	fmt.Printf("resolved check: resolvectl query %s\n", uncachedName)
	fmt.Println(
		"plain dig uses /etc/resolv.conf; it tests resolved only when " +
			"resolv.conf points at the resolved stub",
	)
}

func printDirectDebugQueries(addr netip.Addr) {
	uncachedName := fmt.Sprintf(
		"sysnet-debug-%d.example.com",
		time.Now().UnixNano(),
	)
	fmt.Printf("direct proxy check: dig @%s %s\n", addr, uncachedName)
	fmt.Printf("system resolver check: dig %s\n", uncachedName)
}

func printDirectState() {
	out, err := os.ReadFile("/etc/resolv.conf")
	fmt.Printf("/etc/resolv.conf\n%s", out)
	if err != nil {
		fmt.Printf("read /etc/resolv.conf: %v\n", err)
	}
}

func printResolvconfState(record string) {
	for _, args := range [][]string{
		{"-l"},
		{"-u"},
	} {
		cmd := exec.Command("resolvconf", args...)
		out, err := cmd.CombinedOutput()
		fmt.Printf("resolvconf %s\n%s", strings.Join(args, " "), out)
		if err != nil {
			fmt.Printf("resolvconf %s: %v\n", strings.Join(args, " "), err)
		}
	}
	fmt.Printf("owned resolvconf record: %s\n", record)
	printDirectState()
}

func printOpenresolvState(record string) {
	for _, args := range [][]string{
		{"-i"},
		{"-l", record},
		{"-L"},
	} {
		cmd := exec.Command("resolvconf", args...)
		out, err := cmd.CombinedOutput()
		fmt.Printf("resolvconf %s\n%s", strings.Join(args, " "), out)
		if err != nil {
			fmt.Printf("resolvconf %s: %v\n", strings.Join(args, " "), err)
		}
	}
	fmt.Printf("owned openresolv record: %s\n", record)
	printDirectState()
}

func printResolvedState(ifname string) {
	for _, args := range [][]string{
		{"dns", ifname},
		{"domain", ifname},
		{"default-route", ifname},
	} {
		cmd := exec.Command("resolvectl", args...)
		out, err := cmd.CombinedOutput()
		fmt.Printf("resolvectl %s\n%s", strings.Join(args, " "), out)
		if err != nil {
			fmt.Printf("resolvectl %s: %v\n", strings.Join(args, " "), err)
		}
	}
}
