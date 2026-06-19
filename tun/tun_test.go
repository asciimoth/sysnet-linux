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
	"golang.org/x/sys/unix"
)

func TestCreateDefaultTUNRetriesOccupiedNames(t *testing.T) {
	replaceCreateTUNTestHooks(t)

	suffixes := []string{"first11111", "second2222"}
	randomString = func(length int) (string, error) {
		if length != randomNameLength {
			t.Fatalf("random length = %d, want %d", length, randomNameLength)
		}
		suffix := suffixes[0]
		suffixes = suffixes[1:]
		return suffix, nil
	}

	var names []string
	wantTun := fakeTun{name: "vpn-second2222"}
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
	if !slices.Equal(names, []string{"vpn-first11111", "vpn-second2222"}) {
		t.Fatalf("created names = %#v", names)
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
	if _, err := SetTunName(tun); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("SetTunName error = %v, want ErrUnknownTun", err)
	}
}

func TestIsNetlinkDumpRequestRequiresFullDumpMask(t *testing.T) {
	if !isNetlinkDumpRequest(unix.NLM_F_REQUEST | unix.NLM_F_DUMP) {
		t.Fatal("NLM_F_DUMP request was not detected as dump")
	}

	flags := uint16(
		unix.NLM_F_REQUEST |
			unix.NLM_F_ACK |
			unix.NLM_F_REPLACE |
			unix.NLM_F_CREATE,
	)
	if isNetlinkDumpRequest(flags) {
		t.Fatal("replace/create request was detected as dump")
	}
}

func TestNetlinkReceiveBufferAllowsLargeDumpDatagrams(t *testing.T) {
	if netlinkReceiveBufferSize < 1<<20 {
		t.Fatalf(
			"netlinkReceiveBufferSize = %d, want at least 1 MiB",
			netlinkReceiveBufferSize,
		)
	}
}

func TestRouteDstBytesUsesFullAddressLength(t *testing.T) {
	prefix := netip.MustParsePrefix("10.112.0.0/24")
	got := routeDstBytes(prefix)
	want := []byte{10, 112, 0, 0}
	if !slices.Equal(got, want) {
		t.Fatalf("routeDstBytes(%v) = %#v, want %#v", prefix, got, want)
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
