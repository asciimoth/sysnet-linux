//go:build linux

package dns

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-linux/dns/resolvconffile"
)

const (
	directBackendName = "default"
	directOwner       = "sysnet-linux direct DNS provider"
)

// Direct is a DNSProvider that directly owns /etc/resolv.conf.
//
// NewDirect reads the original resolv.conf nameservers once and Requests
// forwards directly to those upstreams, excluding the DNS server most recently
// installed by SetDNS. If no usable original upstream remains, constructor
// fallbacks are used instead. Direct does not watch resolv.conf for dynamic
// upstream changes because plain resolv.conf provides no ownership-safe update
// notification mechanism.
//
// SetDNS writes a provider-owned /etc/resolv.conf containing only the managed
// server. UnsetDNS and Close restore the saved original contents, or remove the
// file when it was absent originally, but only while the current file still
// looks provider-owned to avoid clobbering unrelated host changes.
type Direct struct {
	env Env

	mu              sync.Mutex
	closed          bool
	base            *gdns.Router
	dial            gonnect.Dial
	client          gdns.Interface
	fallback        []netip.AddrPort
	original        []byte
	originalExists  bool
	originalServers []netip.AddrPort
	setDNS          netip.Addr
	setDNSActive    bool
	upstreamSig     []string
}

var _ DNSProvider = (*Direct)(nil)

// NewDirect returns a DNSProvider backed by direct /etc/resolv.conf writes.
//
// env provides access to the host environment. Any nil callbacks are replaced
// with production defaults. fallback is used only when /etc/resolv.conf has no
// original nameserver after excluding the managed server installed by SetDNS.
func NewDirect(env Env, fallback ...netip.AddrPort) (*Direct, error) {
	env = env.withDefaults()
	d := &Direct{
		env:      env,
		base:     gdns.NewRouter(),
		dial:     env.Dial,
		fallback: append([]netip.AddrPort(nil), fallback...),
	}

	bs, err := env.ReadFile(resolvconffile.Path)
	if err == nil { //nolint
		d.original = append([]byte(nil), bs...)
		d.originalExists = true
		servers, err := resolvconfNameservers(bs)
		if err != nil {
			_ = d.base.Close()
			return nil, fmt.Errorf(
				"direct: parse %s: %w",
				resolvconffile.Path,
				err,
			)
		}
		d.originalServers = servers
	} else if os.IsNotExist(err) {
		d.originalExists = false
	} else {
		_ = d.base.Close()
		return nil, fmt.Errorf("direct: read %s: %w", resolvconffile.Path, err)
	}

	if err := d.refreshUpstreams(nil); err != nil {
		_ = d.base.Close()
		return nil, err
	}
	return d, nil
}

// Requests returns the queue consumed by the internal forwarding client.
//
// Requests are forwarded to the original resolv.conf nameservers or fallbacks,
// not to the server most recently installed with SetDNS.
func (d *Direct) Requests() chan<- gdns.Request {
	return d.base.Requests()
}

// SetDNS writes /etc/resolv.conf with server as the system nameserver.
//
// The change is bounded by this Direct object's lifetime. Repeated calls update
// the managed file and rebuild the forwarding client so Requests never forward
// to the managed server.
func (d *Direct) SetDNS(server netip.Addr) error {
	if !server.IsValid() {
		return errors.New("direct: invalid DNS server")
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return gdns.ErrClosed
	}
	oldServer := d.setDNS
	oldActive := d.setDNSActive
	d.mu.Unlock()

	exclude := []netip.Addr{server}
	if oldActive {
		exclude = append(exclude, oldServer)
	}
	if err := d.refreshUpstreams(exclude); err != nil {
		return err
	}

	data, err := resolvconfForServer(server)
	if err != nil {
		return err
	}
	if err := d.env.WriteFile(resolvconffile.Path, data, 0o644); err != nil {
		return fmt.Errorf("direct: write %s: %w", resolvconffile.Path, err)
	}

	d.mu.Lock()
	d.setDNS = server
	d.setDNSActive = true
	d.mu.Unlock()
	return nil
}

// UnsetDNS rolls back the /etc/resolv.conf change previously applied by
// SetDNS. It is valid to call multiple times and in any order with SetDNS.
func (d *Direct) UnsetDNS() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return gdns.ErrClosed
	}
	active := d.setDNSActive
	server := d.setDNS
	d.setDNS = netip.Addr{}
	d.setDNSActive = false
	d.mu.Unlock()

	if !active {
		return nil
	}

	err := d.restoreResolvConfIfOwned()
	if refreshErr := d.refreshUpstreams(
		[]netip.Addr{server},
	); refreshErr != nil {
		err = errors.Join(err, refreshErr)
	}
	return err
}

// Close rolls back active Direct configuration and releases forwarding
// resources. Close is idempotent.
func (d *Direct) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	active := d.setDNSActive
	d.setDNSActive = false
	client := d.client
	d.client = nil
	d.mu.Unlock()

	var err error
	if active {
		err = errors.Join(err, d.restoreResolvConfIfOwned())
	}
	if d.base != nil {
		err = errors.Join(err, d.base.Close())
	}
	if client != nil {
		err = errors.Join(err, client.Close())
	}
	return err
}

func (d *Direct) refreshUpstreams(exclude []netip.Addr) error {
	d.mu.Lock()
	servers := append([]netip.AddrPort(nil), d.originalServers...)
	fallback := append([]netip.AddrPort(nil), d.fallback...)
	upstreamSig := append([]string(nil), d.upstreamSig...)
	d.mu.Unlock()

	servers = filterAddr(servers, exclude)
	if len(servers) == 0 {
		servers = filterAddr(fallback, exclude)
	}
	urls := serverURLs(servers)
	if len(urls) == 0 {
		return errors.New("direct: no upstream DNS servers")
	}
	if sameStrings(urls, upstreamSig) {
		return nil
	}

	d.mu.Lock()
	dial := d.dial
	d.mu.Unlock()

	client := gdns.NewClient(dial, urls...)
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = client.Close()
		return gdns.ErrClosed
	}
	oldClient := d.client
	if err := d.base.Attach(directBackendName, client); err != nil {
		d.mu.Unlock()
		_ = client.Close()
		return err
	}
	if err := d.base.SetRouter(
		func(*gdns.Message) string { return directBackendName },
	); err != nil {
		d.mu.Unlock()
		_ = client.Close()
		return err
	}
	d.client = client
	d.upstreamSig = append([]string(nil), urls...)
	d.mu.Unlock()

	if oldClient != nil {
		_ = oldClient.Close()
	}
	return nil
}

func (d *Direct) restoreResolvConfIfOwned() error {
	bs, err := d.env.ReadFile(resolvconffile.Path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf(
			"direct: read current %s: %w",
			resolvconffile.Path,
			err,
		)
	}
	if err == nil && !directResolvconfOwned(bs) {
		d.env.Logf(
			"direct: skipping rollback of externally changed %s",
			resolvconffile.Path,
		)
		return nil
	}

	d.mu.Lock()
	original := append([]byte(nil), d.original...)
	originalExists := d.originalExists
	d.mu.Unlock()

	if originalExists {
		if err := d.env.WriteFile(
			resolvconffile.Path,
			original,
			0o644,
		); err != nil {
			return fmt.Errorf(
				"direct: restore %s: %w",
				resolvconffile.Path,
				err,
			)
		}
		return nil
	}
	if err := d.env.Remove(
		resolvconffile.Path,
	); err != nil &&
		!os.IsNotExist(err) {
		return fmt.Errorf("direct: remove %s: %w", resolvconffile.Path, err)
	}
	return nil
}

func resolvconfNameservers(bs []byte) ([]netip.AddrPort, error) {
	cfg, err := resolvconffile.Parse(bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}
	servers := make([]netip.AddrPort, 0, len(cfg.Nameservers))
	for _, ns := range cfg.Nameservers {
		servers = append(servers, netip.AddrPortFrom(ns, 53))
	}
	return dedupeServers(servers), nil
}

func resolvconfForServer(server netip.Addr) ([]byte, error) {
	var buf bytes.Buffer
	err := (&resolvconffile.Config{
		Nameservers: []netip.Addr{server},
	}).Write(&buf, directOwner)
	return buf.Bytes(), err
}

func directResolvconfOwned(bs []byte) bool {
	return bytes.Contains(bs, []byte("generated by "+directOwner))
}
