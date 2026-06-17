//go:build linux

package dns

import (
	"context"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	DbusTimeout = time.Second
)

type Env struct {
	Logf func(format string, args ...any)

	ReadFile       func(path string) ([]byte, error)
	WriteFile      func(path string, data []byte, perm os.FileMode) error
	Remove         func(path string) error
	CommandContext func(
		ctx context.Context,
		name string,
		args ...string,
	) Cmd

	DbusReadString func(ctx context.Context, name, objectPath, iface, member string) (string, error)
	DbusPing       func(ctx context.Context, name, objectPath string) error
	SystemBus      func() (*dbus.Conn, error)
	ResolvedBus    func() (DBusConn, error)

	ResolvconfStyle func() string

	NmIsUsingResolved func() error
}

// Cmd is the subset of exec.Cmd used by DNS providers that configure the host
// through external commands.
type Cmd interface {
	SetStdin(reader io.Reader)
	Run() error
}

type execCmd struct {
	cmd *exec.Cmd
}

func (c execCmd) SetStdin(r io.Reader) {
	c.cmd.Stdin = r
}

func (c execCmd) Run() error {
	return c.cmd.Run()
}

// DBusConn is the subset of a D-Bus connection used by resolved integration.
type DBusConn interface {
	Object(dest string, path dbus.ObjectPath) dbus.BusObject
	AddMatchSignal(options ...dbus.MatchOption) error
	Signal(ch chan<- *dbus.Signal)
	Close() error
}

func (env Env) withDefaults() Env {
	if env.Logf == nil {
		env.Logf = func(string, ...any) {}
	}
	if env.ReadFile == nil {
		env.ReadFile = os.ReadFile
	}
	if env.WriteFile == nil {
		env.WriteFile = os.WriteFile
	}
	if env.Remove == nil {
		env.Remove = os.Remove
	}
	if env.CommandContext == nil {
		env.CommandContext = func(
			ctx context.Context,
			name string,
			args ...string,
		) Cmd {
			return execCmd{cmd: exec.CommandContext(ctx, name, args...)}
		}
	}
	if env.DbusReadString == nil {
		env.DbusReadString = DbusReadString
	}
	if env.DbusPing == nil {
		env.DbusPing = DbusPing
	}
	if env.SystemBus == nil {
		env.SystemBus = dbus.SystemBus
	}
	if env.ResolvedBus == nil {
		env.ResolvedBus = func() (DBusConn, error) {
			return env.SystemBus()
		}
	}
	if env.ResolvconfStyle == nil {
		env.ResolvconfStyle = ResolvconfStyle
	}
	if env.NmIsUsingResolved == nil {
		env.NmIsUsingResolved = NmIsUsingResolved
	}
	return env
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
