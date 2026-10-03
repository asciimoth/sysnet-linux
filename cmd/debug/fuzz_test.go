//go:build linux

// nolint
package main

import (
	"strings"
	"testing"
)

func FuzzUntrustedInput(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1:53,[::1]:53",
		"addr\x0010.0.0.1/24\x00route\x000.0.0.0/0",
		"route",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			input = input[:64<<10]
		}
		_, _ = parseDebugDNSFallbackAddrs(input)
		args := strings.Split(input, "\x00")
		if len(args) > 64 {
			args = args[:64]
		}
		_, _, _ = parseTUNNameConfigArgs(args)
	})
}
