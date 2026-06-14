//go:build linux

package dns

import (
	"bytes"
	"errors"
	"os/exec"
)

// NOTE: Borrowed from github.com/tailscale/tailscale
func ResolvconfStyle() string {
	if _, err := exec.LookPath("resolvconf"); err != nil {
		return ""
	}
	output, err := exec.Command("resolvconf", "--version"). //nolint
								CombinedOutput()
	if err != nil {
		// Debian resolvconf doesn't understand --version, and
		// exits with a specific error code.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 99 {
			return "debian"
		}
	}
	if bytes.HasPrefix(output, []byte("Debian resolvconf")) {
		return "debian"
	}
	// Treat everything else as openresolv, by far the more popular implementation.
	return "openresolv"
}
