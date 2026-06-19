// nolint
package routing

import (
	"errors"
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
