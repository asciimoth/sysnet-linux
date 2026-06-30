//go:build linux

package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-linux/dns/resolvconffile"
)

const (
	debianResolvconfBackendName    = "default"
	debianResolvconfOwner          = "sysnet-linux Debian resolvconf DNS provider"
	debianResolvconfCommandTimeout = 5 * time.Second
	debianResolvconfCommand        = "resolvconf"
)

// DebianResolvconf is a DNSProvider backed by Debian's resolvconf package.
//
// The provider owns one resolvconf record, named by iface. SetDNS writes that
// record with `resolvconf -a <iface>` and Close or UnsetDNS removes it with
// `resolvconf -d <iface>`. It does not try to reconstruct global resolver state;
// resolvconf is responsible for regenerating /etc/resolv.conf after the
// provider-owned record is added or removed.
//
// Requests are forwarded directly to the nameservers present in /etc/resolv.conf
// at construction time, excluding the server installed by SetDNS. This avoids
// forwarding loops after resolvconf points the host at this provider. Fallback
// servers are used only when no original upstream remains. Debian resolvconf
// does not expose an event stream here, so dynamic upstream changes are not
// tracked by this provider.
type DebianResolvconf struct {
	env Env

	mu              sync.Mutex
	closed          bool
	base            *gdns.Router
	listenNetwork   gonnect.Network
	dialNetwork     gonnect.Network
	client          gdns.Interface
	iface           string
	fallback        []netip.AddrPort
	originalServers []netip.AddrPort
	setDNS          netip.Addr
	setDNSActive    bool
	upstreamSig     []string
}

var _ DNSProvider = (*DebianResolvconf)(nil)

// NewDebianResolvconf returns a DNSProvider backed by Debian resolvconf.
//
// env provides access to the host environment. Any nil callbacks are replaced
// with production defaults. listenNetwork is used for listening operations and
// dialNetwork is used for all outgoing upstream DNS requests. iface is the
// resolvconf record name to own, for example "sysnet-linux". fallback is used
// only when /etc/resolv.conf has no original nameserver after excluding the
// managed server installed by SetDNS.
func NewDebianResolvconf(
	env Env,
	listenNetwork gonnect.Network,
	dialNetwork gonnect.Network,
	iface string,
	fallback ...netip.AddrPort,
) (*DebianResolvconf, error) {
	env = env.withDefaults()
	if err := requireDNSNetworks(
		"debian-resolvconf",
		listenNetwork,
		dialNetwork,
	); err != nil {
		return nil, err
	}
	if iface == "" {
		return nil, errors.New("debian-resolvconf: empty interface name")
	}

	r := &DebianResolvconf{
		env:           env,
		base:          gdns.NewRouter(nil),
		listenNetwork: listenNetwork,
		dialNetwork:   dialNetwork,
		iface:         iface,
		fallback:      append([]netip.AddrPort(nil), fallback...),
	}

	bs, err := env.ReadFile(resolvconffile.Path)
	if err == nil { //nolint
		servers, err := resolvconfNameservers(bs)
		if err != nil {
			_ = r.base.Close()
			return nil, fmt.Errorf(
				"debian-resolvconf: parse %s: %w",
				resolvconffile.Path,
				err,
			)
		}
		r.originalServers = servers
	} else if !os.IsNotExist(err) {
		_ = r.base.Close()
		return nil, fmt.Errorf(
			"debian-resolvconf: read %s: %w",
			resolvconffile.Path,
			err,
		)
	}

	if err := r.refreshUpstreams(nil); err != nil {
		_ = r.base.Close()
		return nil, err
	}
	return r, nil
}

// Requests returns the queue consumed by the internal forwarding client.
//
// Requests are forwarded to the original resolv.conf nameservers or fallbacks,
// not to the server most recently installed with SetDNS.
func (r *DebianResolvconf) Requests() chan<- gdns.Request {
	return r.base.Requests()
}

// SetDNS installs server as this provider's Debian resolvconf nameserver.
//
// The change is bounded by this DebianResolvconf object's lifetime. Repeated
// calls replace the provider-owned resolvconf record and rebuild the forwarding
// client so Requests never forward to the managed server.
func (r *DebianResolvconf) SetDNS(server netip.Addr) error {
	if !server.IsValid() {
		return errors.New("debian-resolvconf: invalid DNS server")
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return gdns.ErrClosed
	}
	oldServer := r.setDNS
	oldActive := r.setDNSActive
	r.mu.Unlock()

	exclude := []netip.Addr{server}
	if oldActive {
		exclude = append(exclude, oldServer)
	}
	if err := r.refreshUpstreams(exclude); err != nil {
		return err
	}

	data, err := debianResolvconfForServer(server)
	if err != nil {
		return err
	}
	if err := r.runResolvconf([]string{"-a", r.iface}, data); err != nil {
		return err
	}

	r.mu.Lock()
	r.setDNS = server
	r.setDNSActive = true
	r.mu.Unlock()
	return nil
}

// UnsetDNS removes the Debian resolvconf record previously applied by SetDNS.
// It is valid to call multiple times and in any order with SetDNS.
func (r *DebianResolvconf) UnsetDNS() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return gdns.ErrClosed
	}
	active := r.setDNSActive
	server := r.setDNS
	r.setDNS = netip.Addr{}
	r.setDNSActive = false
	r.mu.Unlock()

	if !active {
		return nil
	}

	err := r.runResolvconf([]string{"-d", r.iface}, nil)
	if refreshErr := r.refreshUpstreams(
		[]netip.Addr{server},
	); refreshErr != nil {
		err = errors.Join(err, refreshErr)
	}
	return err
}

// Close rolls back active Debian resolvconf configuration and releases
// forwarding resources. Close is idempotent.
func (r *DebianResolvconf) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	active := r.setDNSActive
	r.setDNSActive = false
	client := r.client
	r.client = nil
	r.mu.Unlock()

	var err error
	if active {
		err = errors.Join(err, r.runResolvconf([]string{"-d", r.iface}, nil))
	}
	if r.base != nil {
		err = errors.Join(err, r.base.Close())
	}
	if client != nil {
		err = errors.Join(err, client.Close())
	}
	return err
}

func (r *DebianResolvconf) refreshUpstreams(exclude []netip.Addr) error {
	r.mu.Lock()
	servers := append([]netip.AddrPort(nil), r.originalServers...)
	fallback := append([]netip.AddrPort(nil), r.fallback...)
	upstreamSig := append([]string(nil), r.upstreamSig...)
	r.mu.Unlock()

	servers = filterAddr(servers, exclude)
	if len(servers) == 0 {
		servers = filterAddr(fallback, exclude)
	}
	urls := serverURLs(servers)
	if len(urls) == 0 {
		return errors.New("debian-resolvconf: no upstream DNS servers")
	}
	if sameStrings(urls, upstreamSig) {
		return nil
	}

	r.mu.Lock()
	dialNetwork := r.dialNetwork
	r.mu.Unlock()

	client := gdns.NewClient(upstreamDNSDial(dialNetwork), nil, urls...)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = client.Close()
		return gdns.ErrClosed
	}
	oldClient := r.client
	if err := r.base.Attach(debianResolvconfBackendName, client); err != nil {
		r.mu.Unlock()
		_ = client.Close()
		return err
	}
	if err := r.base.SetRouter(
		func(*gdns.Message) string { return debianResolvconfBackendName },
	); err != nil {
		r.mu.Unlock()
		_ = client.Close()
		return err
	}
	r.client = client
	r.upstreamSig = append([]string(nil), urls...)
	r.mu.Unlock()

	if oldClient != nil {
		_ = oldClient.Close()
	}
	return nil
}

func (r *DebianResolvconf) runResolvconf(args []string, stdin []byte) error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		debianResolvconfCommandTimeout,
	)
	defer cancel()

	cmd := r.env.CommandContext(ctx, debianResolvconfCommand, args...)
	if stdin != nil {
		cmd.SetStdin(bytes.NewReader(stdin))
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf(
			"debian-resolvconf: %s %v: %w",
			debianResolvconfCommand,
			args,
			err,
		)
	}
	return nil
}

func debianResolvconfForServer(server netip.Addr) ([]byte, error) {
	var buf bytes.Buffer
	err := (&resolvconffile.Config{
		Nameservers: []netip.Addr{server},
	}).Write(&buf, debianResolvconfOwner)
	return buf.Bytes(), err
}
