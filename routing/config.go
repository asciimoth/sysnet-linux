//go:build linux

package routing

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

const (
	// DefaultAppBypassMark is the suggested mark for VPN transport sockets
	// that must route directly through main and never loop back into the VPN.
	DefaultAppBypassMark uint32 = 0xeb9f0001

	// DefaultMarkMask matches all 32 bits of a packet mark.
	DefaultMarkMask uint32 = 0xffffffff

	// DefaultPrioritySpan is the minimum practical size of a package-owned
	// priority block. The compiler currently uses fewer slots, but keeping a
	// larger span leaves room for future selectors without changing callers.
	DefaultPrioritySpan = 32

	// DefaultPriorityBase is intentionally well after kernel priority 0 and
	// before the normal main/default rule priorities.
	DefaultPriorityBase = 10000

	// Suggested table IDs for callers that do not have their own allocation.
	DefaultVPNTable  = 51820
	DefaultSafeTable = 51821

	firstKernelBuiltinPriority = 32766
)

const (
	ruleOffsetAppMain = iota
	ruleOffsetAppUnreachable
	ruleOffsetTransitionGuard
	ruleOffsetUserFirst
)

// Mode selects whether the user mark means exclude-from-VPN or include-in-VPN.
type Mode int

const (
	ModeExclude Mode = iota
	ModeInclude
)

func (m Mode) String() string {
	switch m {
	case ModeExclude:
		return "exclude"
	case ModeInclude:
		return "include"
	default:
		return fmt.Sprintf("Mode(%d)", int(m))
	}
}

// Strictness controls whether destination-based safe direct routes are allowed.
type Strictness int

const (
	Strict Strictness = iota
	NonStrict
)

func (s Strictness) String() string {
	switch s {
	case Strict:
		return "strict"
	case NonStrict:
		return "non-strict"
	default:
		return fmt.Sprintf("Strictness(%d)", int(s))
	}
}

// FamilySet selects which IP families the manager owns.
type FamilySet struct {
	IPv4 bool
	IPv6 bool
}

// BothFamilies enables IPv4 and IPv6.
var BothFamilies = FamilySet{IPv4: true, IPv6: true}

// Config describes the routing state a Manager should enforce.
type Config struct {
	TUNIndex int

	VPNTable  int
	SafeTable int

	PriorityBase int
	PrioritySpan int

	AppBypassMark uint32
	AppBypassMask uint32
	UserMark      uint32
	UserMarkMask  uint32

	Mode       Mode
	Strictness Strictness
	Families   FamilySet
}

// DefaultConfig returns a conservative starting point. Callers must still set
// TUNIndex and should set UserMark to the value used by their packet marker.
func DefaultConfig() Config {
	return Config{
		VPNTable:      DefaultVPNTable,
		SafeTable:     DefaultSafeTable,
		PriorityBase:  DefaultPriorityBase,
		PrioritySpan:  DefaultPrioritySpan,
		AppBypassMark: DefaultAppBypassMark,
		AppBypassMask: DefaultMarkMask,
		UserMarkMask:  DefaultMarkMask,
		Mode:          ModeExclude,
		Strictness:    Strict,
		Families:      BothFamilies,
	}
}

var (
	ErrInvalidConfig   = errors.New("routing: invalid config")
	ErrTUNLinkNotFound = errors.New("routing: TUN link not found")
)

func (c Config) validate() error {
	if c.TUNIndex <= 0 {
		return fmt.Errorf(
			"%w: TUN interface index must be positive",
			ErrInvalidConfig,
		)
	}
	if reservedRouteTable(c.VPNTable) {
		return fmt.Errorf(
			"%w: VPN table %d is reserved",
			ErrInvalidConfig,
			c.VPNTable,
		)
	}
	if reservedRouteTable(c.SafeTable) {
		return fmt.Errorf(
			"%w: safe table %d is reserved",
			ErrInvalidConfig,
			c.SafeTable,
		)
	}
	if c.VPNTable == c.SafeTable {
		return fmt.Errorf(
			"%w: VPN and safe tables must differ",
			ErrInvalidConfig,
		)
	}
	if c.PriorityBase <= 0 {
		return fmt.Errorf(
			"%w: priority base must be above kernel priority 0",
			ErrInvalidConfig,
		)
	}
	if c.PrioritySpan < DefaultPrioritySpan {
		return fmt.Errorf(
			"%w: priority span %d is smaller than %d",
			ErrInvalidConfig,
			c.PrioritySpan,
			DefaultPrioritySpan,
		)
	}
	if c.PriorityBase+c.PrioritySpan > firstKernelBuiltinPriority {
		return fmt.Errorf(
			"%w: priority range overlaps kernel built-in rules",
			ErrInvalidConfig,
		)
	}
	if c.AppBypassMask == 0 {
		return fmt.Errorf(
			"%w: app bypass mark mask must be non-zero",
			ErrInvalidConfig,
		)
	}
	if c.UserMarkMask == 0 {
		return fmt.Errorf(
			"%w: user mark mask must be non-zero",
			ErrInvalidConfig,
		)
	}
	if marksOverlap(
		c.AppBypassMark,
		c.AppBypassMask,
		c.UserMark,
		c.UserMarkMask,
	) {
		return fmt.Errorf(
			"%w: app bypass and user mark selectors overlap",
			ErrInvalidConfig,
		)
	}
	if c.Mode != ModeExclude && c.Mode != ModeInclude {
		return fmt.Errorf("%w: unsupported mode %s", ErrInvalidConfig, c.Mode)
	}
	if c.Strictness != Strict && c.Strictness != NonStrict {
		return fmt.Errorf(
			"%w: unsupported strictness %s",
			ErrInvalidConfig,
			c.Strictness,
		)
	}
	if !c.Families.IPv4 && !c.Families.IPv6 {
		return fmt.Errorf(
			"%w: at least one IP family must be enabled",
			ErrInvalidConfig,
		)
	}
	return nil
}

// ValidateConfig checks whether config can be compiled or applied.
func ValidateConfig(config Config) error {
	return config.validate()
}

func reservedRouteTable(table int) bool {
	switch table {
	case 0, unix.RT_TABLE_MAIN, unix.RT_TABLE_LOCAL, unix.RT_TABLE_DEFAULT:
		return true
	default:
		return table < 0
	}
}

func marksOverlap(aValue, aMask, bValue, bMask uint32) bool {
	common := aMask & bMask
	return (aValue & common) == (bValue & common)
}

func familyConstants(f FamilySet) []int {
	var out []int
	if f.IPv4 {
		out = append(out, unix.AF_INET)
	}
	if f.IPv6 {
		out = append(out, unix.AF_INET6)
	}
	return out
}

func familyDefaultPrefix(family int) netip.Prefix {
	if family == unix.AF_INET6 {
		return netip.MustParsePrefix("::/0")
	}
	return netip.MustParsePrefix("0.0.0.0/0")
}

func netIPFromAddr(addr netip.Addr) net.IP {
	if !addr.IsValid() {
		return nil
	}
	if addr.Is4() {
		a := addr.As4()
		return net.IPv4(a[0], a[1], a[2], a[3]).To4()
	}
	a := addr.As16()
	return net.IP(a[:])
}
