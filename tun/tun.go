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
	randomNameLength = 5
	randomAlphabet   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var (
	createTUN    = tuntap.CreateTUN
	randomString = cryptoRandomString
)

// CreateDefaultTUN creates a TUN device whose name is generated from base.
//
// Unlike tuntap.CreateTUN, base is not used as the exact interface name.
// Instead, each attempt uses the template "<base>-<rand>", where rand is a
// freshly generated 5-character alpha-numeric string. For example, base
// "vpn" can produce "vpn-aZ38fK02Lm".
//
// If the generated name is already occupied, CreateDefaultTUN generates another
// random suffix and tries again. Only name-occupied errors are retryable; random
// generation failures, invalid names, permission errors, missing /dev/net/tun,
// unsupported MTU values, and all other tuntap.CreateTUN errors are returned
// immediately.
func CreateDefaultTUN(base string, mtu int) (gtun.Tun, error) {
	for {
		nameSuffix, err := randomString(randomNameLength)
		if err != nil {
			return nil, fmt.Errorf("generate TUN name suffix: %w", err)
		}

		name := fmt.Sprintf("%s-%s", base, nameSuffix)
		tun, err := createTUN(name, mtu)
		if err == nil {
			return tun, nil
		}
		if !isTUNNameOccupied(err) {
			return nil, fmt.Errorf("create TUN %q: %w", name, err)
		}
	}
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
