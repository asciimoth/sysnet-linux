// nolint
package resolvconffile

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/asciimoth/sysnet-linux/dns/dnsname"
)

func FuzzUntrustedInput(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("nameserver 1.1.1.1\nsearch example.com\n"),
		[]byte("# generated\nnameserver ::1\n"),
		[]byte("nameserver"),
		[]byte("search ."),
		[]byte("search .\v."),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 128<<10 {
			input = input[:128<<10]
		}
		config, err := Parse(bytes.NewReader(input))
		if err != nil {
			return
		}
		var output bytes.Buffer
		if err := config.Write(&output, "fuzz"); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(&output); err != nil {
			t.Fatalf("serialized configuration cannot be parsed: %v", err)
		}

		addr, _ := netip.AddrFromSlice(input)
		arbitrary := Config{
			Nameservers:   []netip.Addr{addr},
			SearchDomains: []dnsname.FQDN{dnsname.FQDN(string(input))},
		}
		output.Reset()
		_ = arbitrary.Write(&output, string(input))
	})
}
