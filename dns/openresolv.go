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
	openresolvBackendName    = "default"
	openresolvOwner          = "sysnet-linux openresolv DNS provider"
	openresolvCommandTimeout = 5 * time.Second
	openresolvCommand        = "resolvconf"
)

// Openresolv is a DNSProvider backed by the openresolv resolvconf program.
//
// The provider owns one openresolv record, named by iface. SetDNS writes that
// record with `resolvconf -m 0 -x -a <iface>` so the managed DNS server becomes
// the exclusive, highest-priority resolver configuration. Close or UnsetDNS
// removes the record with `resolvconf -f -d <iface>`. It does not reconstruct
// global resolver state; openresolv regenerates /etc/resolv.conf after records
// are added or removed.
//
// Requests are forwarded directly to the nameservers present in /etc/resolv.conf
// at construction time, excluding the server installed by SetDNS. This avoids
// forwarding loops after openresolv points the host at this provider. Fallback
// servers are used only when no original upstream remains. Openresolv is not
// watched for dynamic upstream changes by this provider.
type Openresolv struct {
	env Env

	mu              sync.Mutex
	closed          bool
	base            *gdns.Router
	dial            gonnect.Dial
	client          gdns.Interface
	iface           string
	fallback        []netip.AddrPort
	originalServers []netip.AddrPort
	setDNS          netip.Addr
	setDNSActive    bool
	upstreamSig     []string
}

var _ DNSProvider = (*Openresolv)(nil)

// NewOpenresolv returns a DNSProvider backed by openresolv.
//
// env provides access to the host environment. Any nil callbacks are replaced
// with production defaults. iface is the openresolv record key to own, for
// example "sysnet-linux". fallback is used only when /etc/resolv.conf has no
// original nameserver after excluding the managed server installed by SetDNS.
func NewOpenresolv(
	env Env,
	iface string,
	fallback ...netip.AddrPort,
) (*Openresolv, error) {
	env = env.withDefaults()
	if iface == "" {
		return nil, errors.New("openresolv: empty interface name")
	}

	r := &Openresolv{
		env:      env,
		base:     gdns.NewRouter(),
		dial:     env.Dial,
		iface:    iface,
		fallback: append([]netip.AddrPort(nil), fallback...),
	}

	bs, err := env.ReadFile(resolvconffile.Path)
	if err == nil { //nolint
		servers, err := resolvconfNameservers(bs)
		if err != nil {
			_ = r.base.Close()
			return nil, fmt.Errorf(
				"openresolv: parse %s: %w",
				resolvconffile.Path,
				err,
			)
		}
		r.originalServers = servers
	} else if !os.IsNotExist(err) {
		_ = r.base.Close()
		return nil, fmt.Errorf(
			"openresolv: read %s: %w",
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
func (r *Openresolv) Requests() chan<- gdns.Request {
	return r.base.Requests()
}

// SetDNS installs server as this provider's openresolv nameserver.
//
// The change is bounded by this Openresolv object's lifetime. Repeated calls
// replace the provider-owned openresolv record and rebuild the forwarding client
// so Requests never forward to the managed server.
func (r *Openresolv) SetDNS(server netip.Addr) error {
	if !server.IsValid() {
		return errors.New("openresolv: invalid DNS server")
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

	data, err := openresolvForServer(server)
	if err != nil {
		return err
	}
	if err := r.runResolvconf(
		[]string{"-m", "0", "-x", "-a", r.iface},
		data,
	); err != nil {
		return err
	}

	r.mu.Lock()
	r.setDNS = server
	r.setDNSActive = true
	r.mu.Unlock()
	return nil
}

// UnsetDNS removes the openresolv record previously applied by SetDNS. It is
// valid to call multiple times and in any order with SetDNS.
func (r *Openresolv) UnsetDNS() error {
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

	err := r.runResolvconf([]string{"-f", "-d", r.iface}, nil)
	if refreshErr := r.refreshUpstreams(
		[]netip.Addr{server},
	); refreshErr != nil {
		err = errors.Join(err, refreshErr)
	}
	return err
}

// Close rolls back active openresolv configuration and releases forwarding
// resources. Close is idempotent.
func (r *Openresolv) Close() error {
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
		err = errors.Join(
			err,
			r.runResolvconf([]string{"-f", "-d", r.iface}, nil),
		)
	}
	if r.base != nil {
		err = errors.Join(err, r.base.Close())
	}
	if client != nil {
		err = errors.Join(err, client.Close())
	}
	return err
}

func (r *Openresolv) refreshUpstreams(exclude []netip.Addr) error {
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
		return errors.New("openresolv: no upstream DNS servers")
	}
	if sameStrings(urls, upstreamSig) {
		return nil
	}

	r.mu.Lock()
	dial := r.dial
	r.mu.Unlock()

	client := gdns.NewClient(dial, urls...)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = client.Close()
		return gdns.ErrClosed
	}
	oldClient := r.client
	if err := r.base.Attach(openresolvBackendName, client); err != nil {
		r.mu.Unlock()
		_ = client.Close()
		return err
	}
	if err := r.base.SetRouter(
		func(*gdns.Message) string { return openresolvBackendName },
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

func (r *Openresolv) runResolvconf(args []string, stdin []byte) error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		openresolvCommandTimeout,
	)
	defer cancel()

	cmd := r.env.CommandContext(ctx, openresolvCommand, args...)
	if stdin != nil {
		cmd.SetStdin(bytes.NewReader(stdin))
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf(
			"openresolv: %s %v: %w",
			openresolvCommand,
			args,
			err,
		)
	}
	return nil
}

func openresolvForServer(server netip.Addr) ([]byte, error) {
	var buf bytes.Buffer
	err := (&resolvconffile.Config{
		Nameservers: []netip.Addr{server},
	}).Write(&buf, openresolvOwner)
	return buf.Bytes(), err
}
