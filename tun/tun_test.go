// nolint
package tun

import (
	"errors"
	"os"
	"slices"
	"syscall"
	"testing"

	gtun "github.com/asciimoth/gonnect/tun"
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
