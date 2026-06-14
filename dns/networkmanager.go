//go:build linux

package dns

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

// NOTE: Borrowed from github.com/tailscale/tailscale
func NmIsUsingResolved() error {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return err
	}

	nm := conn.Object(
		"org.freedesktop.NetworkManager",
		dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager"),
	)
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.DnsManager.Mode")
	if err != nil {
		return fmt.Errorf("getting NM mode: %w", err)
	}
	mode, ok := v.Value().(string)
	if !ok {
		return fmt.Errorf("unexpected type %T for NM DNS mode", v.Value())
	}
	if mode != "systemd-resolved" {
		return errors.New(
			"NetworkManager is not using systemd-resolved for DNS",
		)
	}
	return nil
}
