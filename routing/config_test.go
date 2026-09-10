// nolint
package routing

import (
	"errors"
	"net/netip"
	"testing"
)

func TestValidateConfigRejectsInvalidValues(t *testing.T) {
	base := configForTest()

	tests := []struct {
		name   string
		update func(*Config)
	}{
		{
			name: "reserved VPN table",
			update: func(cfg *Config) {
				cfg.VPNTable = 254
			},
		},
		{
			name: "duplicate tables",
			update: func(cfg *Config) {
				cfg.SafeTable = cfg.VPNTable
			},
		},
		{
			name: "small priority range",
			update: func(cfg *Config) {
				cfg.PrioritySpan = DefaultPrioritySpan - 1
			},
		},
		{
			name: "zero app mark mask",
			update: func(cfg *Config) {
				cfg.AppBypassMask = 0
			},
		},
		{
			name: "overlapping marks",
			update: func(cfg *Config) {
				cfg.UserMark = cfg.AppBypassMark
			},
		},
		{
			name: "missing tun",
			update: func(cfg *Config) {
				cfg.TUNIndex = 0
			},
		},
		{
			name: "unsupported mode",
			update: func(cfg *Config) {
				cfg.Mode = Mode(99)
			},
		},
		{
			name: "unsupported family",
			update: func(cfg *Config) {
				cfg.Families = FamilySet{}
			},
		},
		{
			name: "invalid preferred source",
			update: func(cfg *Config) {
				cfg.SourceRoutes = []SourceRoute{{
					Destination: netip.MustParsePrefix("0.0.0.0/0"),
				}}
			},
		},
		{
			name: "unmasked source destination",
			update: func(cfg *Config) {
				cfg.SourceRoutes = []SourceRoute{{
					Destination: netip.MustParsePrefix("192.0.2.1/24"),
					Source:      netip.MustParseAddr("10.20.0.2"),
				}}
			},
		},
		{
			name: "mixed source route families",
			update: func(cfg *Config) {
				cfg.SourceRoutes = []SourceRoute{{
					Destination: netip.MustParsePrefix("0.0.0.0/0"),
					Source:      netip.MustParseAddr("2001:db8::2"),
				}}
			},
		},
		{
			name: "IPv4-mapped source",
			update: func(cfg *Config) {
				cfg.Families = BothFamilies
				cfg.SourceRoutes = []SourceRoute{{
					Destination: netip.MustParsePrefix("::/0"),
					Source: netip.MustParseAddr(
						"::ffff:192.0.2.2",
					),
				}}
			},
		},
		{
			name: "IPv4-mapped destination",
			update: func(cfg *Config) {
				cfg.Families = BothFamilies
				cfg.SourceRoutes = []SourceRoute{{
					Destination: netip.MustParsePrefix(
						"::ffff:192.0.2.0/120",
					),
					Source: netip.MustParseAddr("2001:db8::2"),
				}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.update(&cfg)
			err := ValidateConfig(cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf(
					"ValidateConfig() error = %v, want ErrInvalidConfig",
					err,
				)
			}
		})
	}
}

func TestValidateConfigAcceptsSeparateMaskedMarks(t *testing.T) {
	cfg := configForTest()
	cfg.AppBypassMark = 0x100
	cfg.AppBypassMask = 0xf00
	cfg.UserMark = 0x200
	cfg.UserMarkMask = 0xf00

	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
}

func TestValidateConfigRejectsNonNormalizedSourceRoutePolicy(t *testing.T) {
	v4Default := netip.MustParsePrefix("0.0.0.0/0")
	v4Source := netip.MustParseAddr("10.20.0.2")
	tests := []struct {
		name   string
		routes []SourceRoute
	}{
		{
			name: "invalid destination",
			routes: []SourceRoute{{
				Source: v4Source,
			}},
		},
		{
			name: "unspecified source",
			routes: []SourceRoute{{
				Destination: v4Default,
				Source:      netip.IPv4Unspecified(),
			}},
		},
		{
			name: "multicast source",
			routes: []SourceRoute{{
				Destination: v4Default,
				Source:      netip.MustParseAddr("224.0.0.1"),
			}},
		},
		{
			name: "broadcast source",
			routes: []SourceRoute{{
				Destination: v4Default,
				Source:      netip.MustParseAddr("255.255.255.255"),
			}},
		},
		{
			name: "loopback source",
			routes: []SourceRoute{{
				Destination: v4Default,
				Source:      netip.MustParseAddr("127.0.0.2"),
			}},
		},
		{
			name: "zoned source",
			routes: []SourceRoute{{
				Destination: netip.MustParsePrefix("::/0"),
				Source:      netip.MustParseAddr("fe80::2%tun0"),
			}},
		},
		{
			name: "disabled family",
			routes: []SourceRoute{{
				Destination: netip.MustParsePrefix("2001:db8::/32"),
				Source:      netip.MustParseAddr("2001:db8::2"),
			}},
		},
		{
			name: "exact duplicate",
			routes: []SourceRoute{
				{Destination: v4Default, Source: v4Source},
				{Destination: v4Default, Source: v4Source},
			},
		},
		{
			name: "conflicting duplicate",
			routes: []SourceRoute{
				{Destination: v4Default, Source: v4Source},
				{
					Destination: v4Default,
					Source:      netip.MustParseAddr("100.64.0.2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := configForTest()
			config.SourceRoutes = test.routes
			if err := ValidateConfig(
				config,
			); !errors.Is(
				err,
				ErrInvalidConfig,
			) {
				t.Fatalf(
					"ValidateConfig() error = %v, want ErrInvalidConfig",
					err,
				)
			}
		})
	}
}

func TestValidateConfigAcceptsLinkLocalPreferredSources(t *testing.T) {
	config := configForTest()
	config.Families = BothFamilies
	config.SourceRoutes = []SourceRoute{
		{
			Destination: netip.MustParsePrefix("198.51.100.0/24"),
			Source:      netip.MustParseAddr("169.254.10.2"),
		},
		{
			Destination: netip.MustParsePrefix("2001:db8::/32"),
			Source:      netip.MustParseAddr("fe80::2"),
		},
	}
	if err := ValidateConfig(config); err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
}

func configForTest() Config {
	cfg := DefaultConfig()
	cfg.TUNIndex = 7
	cfg.VPNTable = 300
	cfg.SafeTable = 301
	cfg.PriorityBase = 100
	cfg.PrioritySpan = DefaultPrioritySpan
	cfg.AppBypassMark = 0x100
	cfg.AppBypassMask = 0xff00
	cfg.UserMark = 0x200
	cfg.UserMarkMask = 0xff00
	cfg.Families = FamilySet{IPv4: true}
	return cfg
}
