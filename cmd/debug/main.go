package main

import (
	"context"
	"fmt"
	"os"

	"github.com/asciimoth/sysnet-linux/dns"
)

func main() {
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
}
