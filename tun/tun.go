//go:build linux

package tun

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"syscall"

	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/tuntap"
)

const (
	maxLinuxInterfaceNameLength = 15
	maxCreateTUNNameAttempts    = 10000
	minRandomNameLength         = 1
	nameSeparator               = "-"
	randomAlphabet              = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var (
	createTUN    = tuntap.CreateTUN
	randomString = cryptoRandomString
)

// CreateDefaultTUN creates a TUN device whose name is generated from base.
//
// Unlike tuntap.CreateTUN, base is not used as the exact interface name.
// Instead, each attempt uses the template "<base>-<rand>", where rand is a
// freshly generated alpha-numeric string sized to consume the space left by the
// base name and Linux's 15-character interface name limit. The final name is
// truncated to Linux's limit after base and rand are concatenated.
//
// If the generated name is already occupied, CreateDefaultTUN generates another
// random suffix and tries again, up to a fixed attempt limit. Only name-occupied
// errors are retryable; random generation failures, invalid names, permission
// errors, missing /dev/net/tun, unsupported MTU values, and all other
// tuntap.CreateTUN errors are returned immediately.
func CreateDefaultTUN(base string, mtu int) (gtun.Tun, error) {
	var lastName string
	var lastErr error
	for range maxCreateTUNNameAttempts {
		nameSuffix, err := randomString(randomTUNNameSuffixLength(base))
		if err != nil {
			return nil, fmt.Errorf("generate TUN name suffix: %w", err)
		}

		name := defaultTUNName(base, nameSuffix)
		lastName = name
		tun, err := createTUN(name, mtu)
		if err == nil {
			return tun, nil
		}
		lastErr = err
		if !isTUNNameOccupied(err) {
			return nil, fmt.Errorf("create TUN %q: %w", name, err)
		}
	}

	return nil, fmt.Errorf(
		"create TUN %q after %d attempts: %w",
		lastName,
		maxCreateTUNNameAttempts,
		lastErr,
	)
}

func randomTUNNameSuffixLength(base string) int {
	length := maxLinuxInterfaceNameLength - len(base) - len(nameSeparator)
	if length < minRandomNameLength {
		return minRandomNameLength
	}
	return length
}

func defaultTUNName(base, suffix string) string {
	name := base + nameSeparator + suffix
	if len(name) > maxLinuxInterfaceNameLength {
		name = name[:maxLinuxInterfaceNameLength]
	}
	return name
}

func cryptoRandomString(length int) (string, error) {
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(randomAlphabet))))
		if err != nil {
			return "", err
		}
		out[i] = randomAlphabet[n.Int64()]
	}
	return string(out), nil
}

func isTUNNameOccupied(err error) bool {
	return errors.Is(err, syscall.EBUSY)
}
