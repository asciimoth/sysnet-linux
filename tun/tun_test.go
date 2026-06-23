// nolint
package tun

import (
	"errors"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
)

func TestCreateDefaultTUNRetriesOccupiedNames(t *testing.T) {
	replaceCreateTUNTestHooks(t)

	suffixes := []string{"first111111", "second22222"}
	randomString = func(length int) (string, error) {
		if length != 11 {
			t.Fatalf("random length = %d, want 11", length)
		}
		suffix := suffixes[0]
		suffixes = suffixes[1:]
		return suffix, nil
	}

	var names []string
	wantTun := fakeTun{name: "vpn-second22222"}
	createTUN = func(name string, mtu int) (gtun.Tun, error) {
		names = append(names, name)
		if mtu != 1400 {
			t.Fatalf("mtu = %d, want 1400", mtu)
		}
		if len(names) == 1 {
			return nil, syscall.EBUSY
		}
		return wantTun, nil
	}

	got, err := CreateDefaultTUN("vpn", 1400)
	if err != nil {
		t.Fatalf("CreateDefaultTUN error = %v", err)
	}
	if got != wantTun {
		t.Fatalf("CreateDefaultTUN returned %#v, want %#v", got, wantTun)
	}
	if !slices.Equal(names, []string{"vpn-first111111", "vpn-second22222"}) {
		t.Fatalf("created names = %#v", names)
	}

}

func TestCreateDefaultTUNTruncatesFinalNameAfterConcatenation(t *testing.T) {
	replaceCreateTUNTestHooks(t)

	randomString = func(length int) (string, error) {
		if length != 1 {
			t.Fatalf("random length = %d, want 1", length)
		}
		return "Z", nil
	}

	var gotName string
	wantTun := fakeTun{name: "abcdefghijklmno"}
	createTUN = func(name string, mtu int) (gtun.Tun, error) {
		gotName = name
		return wantTun, nil
	}

	got, err := CreateDefaultTUN("abcdefghijklmnopqrst", 1400)
	if err != nil {
		t.Fatalf("CreateDefaultTUN error = %v", err)
	}
	if got != wantTun {
		t.Fatalf("CreateDefaultTUN returned %#v, want %#v", got, wantTun)
	}
	if gotName != "abcdefghijklmno" {
		t.Fatalf("created name = %q, want %q", gotName, "abcdefghijklmno")
	}
	if len(gotName) != 15 {
		t.Fatalf("created name length = %d, want 15", len(gotName))
	}
}

func TestCreateDefaultTUNStopsAfterRetryLimit(t *testing.T) {
	replaceCreateTUNTestHooks(t)

	var randomCalls int
	randomString = func(length int) (string, error) {
		randomCalls++
		if length != 1 {
			t.Fatalf("random length = %d, want 1", length)
		}
		return "Z", nil
	}

	var createCalls int
	createTUN = func(name string, mtu int) (gtun.Tun, error) {
		createCalls++
		if name != "abcdefghijklmno" {
			t.Fatalf("created name = %q, want %q", name, "abcdefghijklmno")
		}
		return nil, syscall.EBUSY
	}

	_, err := CreateDefaultTUN("abcdefghijklmnopqrst", 1400)
	if !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("CreateDefaultTUN error = %v, want EBUSY", err)
	}
	if randomCalls != maxCreateTUNNameAttempts {
		t.Fatalf(
			"random calls = %d, want %d",
			randomCalls,
			maxCreateTUNNameAttempts,
		)
	}
	if createCalls != maxCreateTUNNameAttempts {
		t.Fatalf(
			"create calls = %d, want %d",
			createCalls,
			maxCreateTUNNameAttempts,
		)
	}
}

func TestCreateDefaultTUNReturnsNonOccupiedError(t *testing.T) {
	replaceCreateTUNTestHooks(t)

	randomString = func(int) (string, error) {
		return "suffix0000", nil
	}
	createTUN = func(string, int) (gtun.Tun, error) {
		return nil, os.ErrPermission
	}

	_, err := CreateDefaultTUN("vpn", 1400)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("CreateDefaultTUN error = %v, want permission error", err)
	}

}

func TestCreateDefaultTUNReturnsRandomError(t *testing.T) {
	replaceCreateTUNTestHooks(t)

	wantErr := errors.New("entropy unavailable")
	randomString = func(int) (string, error) {
		return "", wantErr
	}
	createTUN = func(string, int) (gtun.Tun, error) {
		t.Fatal("createTUN should not be called")
		return nil, nil
	}

	_, err := CreateDefaultTUN("vpn", 1400)
	if !errors.Is(err, wantErr) {
		t.Fatalf("CreateDefaultTUN error = %v, want random error", err)
	}

}

func TestTunConfigFunctionsReturnUnknownTunForNilFile(t *testing.T) {
	tun := fakeTun{name: "vpn-test"}

	errChecks := []struct {
		name string
		fn   func() error
	}{
		{
			name: "SetTunMTU",
			fn: func() error {
				return SetTunMTU(tun, 1400)
			},
		},
		{
			name: "SetTunAddrs",
			fn: func() error {
				return SetTunAddrs(tun, []string{"10.0.0.1/32"})
			},
		},
		{
			name: "AddTunAddr",
			fn: func() error {
				return AddTunAddr(tun, "10.0.0.1/32")
			},
		},
		{
			name: "SetTunRoutes",
			fn: func() error {
				return SetTunRoutes(tun, []string{"10.0.0.0/24"})
			},
		},
		{
			name: "AddTunRoute",
			fn: func() error {
				return AddTunRoute(tun, "10.0.0.0/24")
			},
		},
	}
	for _, check := range errChecks {
		if err := check.fn(); !errors.Is(err, sysnet.ErrUnknownTun) {
			t.Fatalf("%s error = %v, want ErrUnknownTun", check.name, err)
		}
	}

	if _, err := GetTunAddrs(tun); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("GetTunAddrs error = %v, want ErrUnknownTun", err)
	}
	if _, err := GetTunRotue(tun); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("GetTunRotue error = %v, want ErrUnknownTun", err)
	}
	if _, err := SetTunName(
		tun,
		"renamed0",
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunName error = %v, want ErrUnknownTun", err)
	}
}

func TestParseTunAddrPrefixPreservesHostAddress(t *testing.T) {
	got, err := parseTunAddrPrefix("10.0.0.1/24")
	if err != nil {
		t.Fatalf("parseTunAddrPrefix error = %v", err)
	}
	want := netip.MustParsePrefix("10.0.0.1/24")
	if got != want {
		t.Fatalf("parseTunAddrPrefix = %v, want %v", got, want)
	}
}

func TestParseTunRoutePrefixMasksHostAddress(t *testing.T) {
	got, err := parseTunRoutePrefix("10.0.0.1/24")
	if err != nil {
		t.Fatalf("parseTunRoutePrefix error = %v", err)
	}
	want := netip.MustParsePrefix("10.0.0.0/24")
	if got != want {
		t.Fatalf("parseTunRoutePrefix = %v, want %v", got, want)
	}
}

func TestNetlinkAddrFromStringPreservesHostAddress(t *testing.T) {
	got, err := netlinkAddrFromString("10.0.0.1/24")
	if err != nil {
		t.Fatalf("netlinkAddrFromString error = %v", err)
	}
	if got.IP.String() != "10.0.0.1" {
		t.Fatalf("netlinkAddrFromString IP = %v, want 10.0.0.1", got.IP)
	}
	ones, bits := got.Mask.Size()
	if ones != 24 || bits != 32 {
		t.Fatalf("netlinkAddrFromString mask = %d/%d, want 24/32", ones, bits)
	}
}

func TestNetlinkRouteFromPrefixMasksHostAddress(t *testing.T) {
	got, err := netlinkRouteFromPrefix(3, netip.MustParsePrefix("10.0.0.1/24"))
	if err != nil {
		t.Fatalf("netlinkRouteFromPrefix error = %v", err)
	}
	if got.LinkIndex != 3 {
		t.Fatalf("netlinkRouteFromPrefix LinkIndex = %d, want 3", got.LinkIndex)
	}
	if got.Dst.String() != "10.0.0.0/24" {
		t.Fatalf("netlinkRouteFromPrefix Dst = %v, want 10.0.0.0/24", got.Dst)
	}
}

func TestNetlinkRouteFromDefaultPrefixUsesNilDst(t *testing.T) {
	got, err := netlinkRouteFromPrefix(3, netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil {
		t.Fatalf("netlinkRouteFromPrefix error = %v", err)
	}
	if got.Dst != nil {
		t.Fatalf("netlinkRouteFromPrefix Dst = %v, want nil", got.Dst)
	}
}

func TestParseTunAddrPrefixesRejectsInvalidReplacementSet(t *testing.T) {
	_, err := parseTunAddrPrefixes([]string{"10.0.0.1/24", "not-a-cidr"})
	if err == nil {
		t.Fatal("parseTunAddrPrefixes accepted invalid address")
	}
}

func TestParseTunRoutePrefixesRejectsInvalidReplacementSet(t *testing.T) {
	_, err := parseTunRoutePrefixes([]string{"10.0.0.0/24", "not-a-cidr"})
	if err == nil {
		t.Fatal("parseTunRoutePrefixes accepted invalid route")
	}
}

func replaceCreateTUNTestHooks(t *testing.T) {
	t.Helper()

	oldCreateTUN := createTUN
	oldRandomString := randomString
	t.Cleanup(func() {
		createTUN = oldCreateTUN
		randomString = oldRandomString
	})
}

type fakeTun struct {
	name string
}

func (f fakeTun) File() *os.File { return nil }

func (f fakeTun) IsNative() bool { return false }

func (f fakeTun) Read(
	[][]byte,
	[]int,
	int,
) (int, error) {
	return 0, os.ErrClosed
}

func (f fakeTun) Write([][]byte, int) (int, error) { return 0, os.ErrClosed }

func (f fakeTun) MWO() int { return 0 }

func (f fakeTun) MRO() int { return 0 }

func (f fakeTun) MTU() (int, error) { return 0, nil }

func (f fakeTun) Name() (string, error) { return f.name, nil }

func (f fakeTun) Events() <-chan gtun.Event { return nil }

func (f fakeTun) Close() error { return nil }

func (f fakeTun) BatchSize() int { return 1 }
