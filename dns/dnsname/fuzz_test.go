// nolint
package dnsname

import "testing"

func FuzzUntrustedInput(f *testing.F) {
	for _, seed := range []string{"", ".", "example.com", "host_name.local", "a..b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4<<10 {
			input = input[:4<<10]
		}
		arbitrary := FQDN(input)
		_ = arbitrary.WithTrailingDot()
		_ = arbitrary.WithoutTrailingDot()
		_ = arbitrary.NumLabels()
		_ = arbitrary.Parent()
		_ = arbitrary.Contains(arbitrary)

		fqdn, err := ToFQDN(input)
		if err == nil {
			_ = fqdn.WithTrailingDot()
			_ = fqdn.WithoutTrailingDot()
			_ = fqdn.NumLabels()
			_ = fqdn.Parent()
			_ = fqdn.Contains(fqdn)
		}
		_ = ValidLabel(input)
		sanitized := SanitizeLabel(input)
		if sanitized != "" {
			if err := ValidLabel(sanitized); err != nil {
				t.Fatalf(
					"SanitizeLabel returned invalid label %q: %v",
					sanitized,
					err,
				)
			}
		}
		_ = HasSuffix(input, sanitized)
		_ = TrimSuffix(input, sanitized)
		_ = SanitizeHostname(input)
		_ = NumLabels(input)
		_ = FirstLabel(input)
		_ = ValidHostname(input)
	})
}
