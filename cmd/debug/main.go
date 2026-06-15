// nolint
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "dns":
		os.Exit(runDNSCommand(os.Args[2:]))
	case "-h", "--help", "help":
		printUsage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(out *os.File) {
	fmt.Fprintf(out, "usage: %s <subcommand>\n\n", os.Args[0])
	fmt.Fprintln(out, "subcommands:")
	fmt.Fprintln(out, "  dns    debug system DNS integration")
}
