//go:build linux

package dns

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	DbusTimeout = time.Second
)

type Env struct {
	Logf func(format string, args ...any)

	ReadFile func(path string) ([]byte, error)

	DbusReadString func(ctx context.Context, name, objectPath, iface, member string) (string, error)
	DbusPing       func(ctx context.Context, name, objectPath string) error

	ResolvconfStyle func() string

	NmIsUsingResolved func() error
}

// DbusReadString reads a string property from the provided name and object
// path. property must be in "interface.member" notation.
//
// NOTE: Borrowed from github.com/tailscale/tailscale
func DbusReadString(
	ctx context.Context,
	name, objectPath, iface, member string,
) (string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, DbusTimeout)
	defer cancel()

	obj := conn.Object(name, dbus.ObjectPath(objectPath))

	var result dbus.Variant
	err = obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, member).
		Store(&result)
	if err != nil {
		return "", err
	}

	if s, ok := result.Value().(string); ok {
		return s, nil
	}
	return result.String(), nil
}

// NOTE: Borrowed from github.com/tailscale/tailscale
func DbusPing(ctx context.Context, name, objectPath string) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, DbusTimeout)
	defer cancel()

	obj := conn.Object(name, dbus.ObjectPath(objectPath))
	call := obj.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0)
	return call.Err
}
