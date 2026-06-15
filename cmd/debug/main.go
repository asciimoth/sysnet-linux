// nolint
package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-linux/dns"
	"golang.org/x/sys/unix"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	mode, err := dns.DnsMode(context.Background(), dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
		ReadFile:          os.ReadFile,
		DbusReadString:    dns.DbusReadString,
		DbusPing:          dns.DbusPing,
		ResolvconfStyle:   dns.ResolvconfStyle,
		NmIsUsingResolved: dns.NmIsUsingResolved,
	})
	fmt.Println(mode, err)
	if err != nil {
		os.Exit(1)
	}

	switch mode {
	case "systemd-resolved":
		if err := runResolvedDebug(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "debug resolved: %v\n", err)
			os.Exit(1)
		}
		return
	case "direct":
		if err := runDirectDebug(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "debug direct: %v\n", err)
			os.Exit(1)
		}
		return
	case "debian-resolvconf":
		if err := runDebianResolvconfDebug(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "debug debian-resolvconf: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("mode not supported")
}

func runResolvedDebug(ctx context.Context) error {
	tun, err := createDummyTUN("sysnetdbg%d")
	if err != nil {
		return err
	}
	defer tun.Close()
	fmt.Printf("created dummy TUN %s ifindex=%d\n", tun.name, tun.ifindex)

	addr := debugDNSAddr()
	if err := assignInterfaceAddr(tun.name, addr); err != nil {
		return err
	}
	fmt.Printf("assigned debug DNS address %s/32 to %s\n", addr, tun.name)

	resolved, err := dns.NewResolved(dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	}, tun.ifindex)
	if err != nil {
		return err
	}
	defer func() {
		if err := resolved.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "resolved close: %v\n", err)
		}
	}()

	pc, err := listenDNS(addr)
	if err != nil {
		return err
	}
	logger := newLoggingDNS(resolved)
	defer logger.Close()
	server := gdns.NewServer(pc, logger)
	defer server.Close()

	if err := resolved.SetDNS(addr); err != nil {
		return err
	}
	fmt.Printf("proxying DNS on %s:53 until Ctrl+C\n", addr)
	printResolvedState(tun.name)
	printDebugQueries(addr)

	<-ctx.Done()
	fmt.Println("shutting down")
	return nil
}

func runDirectDebug(ctx context.Context) error {
	addr := netip.MustParseAddr("127.0.0.1")
	direct, err := dns.NewDirect(dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := direct.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "direct close: %v\n", err)
		}
	}()

	pc, err := listenDNS(addr)
	if err != nil {
		return err
	}
	logger := newLoggingDNS(direct)
	defer logger.Close()
	server := gdns.NewServer(pc, logger)
	defer server.Close()

	if err := direct.SetDNS(addr); err != nil {
		return err
	}
	fmt.Printf("proxying DNS on %s:53 until Ctrl+C\n", addr)
	printDirectState()
	printDirectDebugQueries(addr)

	<-ctx.Done()
	fmt.Println("shutting down")
	return nil
}

func runDebianResolvconfDebug(ctx context.Context) error {
	const record = "sysnet-linux"
	addr := netip.MustParseAddr("127.0.0.1")
	provider, err := dns.NewDebianResolvconf(dns.Env{
		Logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	}, record)
	if err != nil {
		return err
	}
	defer func() {
		if err := provider.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "debian-resolvconf close: %v\n", err)
		}
	}()

	pc, err := listenDNS(addr)
	if err != nil {
		return err
	}
	logger := newLoggingDNS(provider)
	defer logger.Close()
	server := gdns.NewServer(pc, logger)
	defer server.Close()

	if err := provider.SetDNS(addr); err != nil {
		return err
	}
	fmt.Printf("proxying DNS on %s:53 until Ctrl+C\n", addr)
	printResolvconfState(record)
	printDirectDebugQueries(addr)

	<-ctx.Done()
	fmt.Println("shutting down")
	return nil
}

func printDebugQueries(addr netip.Addr) {
	uncachedName := fmt.Sprintf(
		"sysnet-debug-%d.example.com",
		time.Now().UnixNano(),
	)
	fmt.Printf("direct proxy check: dig @%s %s\n", addr, uncachedName)
	fmt.Printf("resolved check: resolvectl query %s\n", uncachedName)
	fmt.Println(
		"plain dig uses /etc/resolv.conf; it tests resolved only when " +
			"resolv.conf points at the resolved stub",
	)
}

func printDirectDebugQueries(addr netip.Addr) {
	uncachedName := fmt.Sprintf(
		"sysnet-debug-%d.example.com",
		time.Now().UnixNano(),
	)
	fmt.Printf("direct proxy check: dig @%s %s\n", addr, uncachedName)
	fmt.Printf("system resolver check: dig %s\n", uncachedName)
}

func printDirectState() {
	out, err := os.ReadFile("/etc/resolv.conf")
	fmt.Printf("/etc/resolv.conf\n%s", out)
	if err != nil {
		fmt.Printf("read /etc/resolv.conf: %v\n", err)
	}
}

func printResolvconfState(record string) {
	for _, args := range [][]string{
		{"-l"},
		{"-u"},
	} {
		cmd := exec.Command("resolvconf", args...)
		out, err := cmd.CombinedOutput()
		fmt.Printf("resolvconf %s\n%s", strings.Join(args, " "), out)
		if err != nil {
			fmt.Printf("resolvconf %s: %v\n", strings.Join(args, " "), err)
		}
	}
	fmt.Printf("owned resolvconf record: %s\n", record)
	printDirectState()
}

func printResolvedState(ifname string) {
	for _, args := range [][]string{
		{"dns", ifname},
		{"domain", ifname},
		{"default-route", ifname},
	} {
		cmd := exec.Command("resolvectl", args...)
		out, err := cmd.CombinedOutput()
		fmt.Printf("resolvectl %s\n%s", strings.Join(args, " "), out)
		if err != nil {
			fmt.Printf("resolvectl %s: %v\n", strings.Join(args, " "), err)
		}
	}
}

type dummyTUN struct {
	fd      int
	name    string
	ifindex int
}

func (t *dummyTUN) Close() error {
	if t.fd < 0 {
		return nil
	}
	err := unix.Close(t.fd)
	t.fd = -1
	return err
}

func createDummyTUN(pattern string) (*dummyTUN, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(pattern)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create tun ifreq: %w", err)
	}
	ifr.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}

	name := ifr.Name()
	if err := setInterfaceUp(name); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("lookup interface %s: %w", name, err)
	}
	return &dummyTUN{fd: fd, name: name, ifindex: iface.Index}, nil
}

func setInterfaceUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open control socket: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("create flags ifreq: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS(%s): %w", name, err)
	}
	ifr.SetUint16(ifr.Uint16() | uint16(unix.IFF_UP))
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS(%s): %w", name, err)
	}
	return nil
}

func debugDNSAddr() netip.Addr {
	pid := os.Getpid()
	return netip.AddrFrom4([4]byte{
		198,
		18,
		byte(pid >> 8),
		byte(pid%254 + 1),
	})
}

func assignInterfaceAddr(name string, addr netip.Addr) error {
	cmd := exec.Command(
		"ip",
		"addr",
		"replace",
		addr.String()+"/32",
		"dev",
		name,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"assign %s/32 to %s with ip(8): %w: %s",
			addr,
			name,
			err,
			strings.TrimSpace(string(out)),
		)
	}
	return nil
}

func listenDNS(ip netip.Addr) (net.PacketConn, error) {
	addr := net.JoinHostPort(ip.String(), "53")
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp DNS on %s: %w", addr, err)
	}

	tcp, err := net.Listen("tcp4", addr)
	if err == nil {
		_ = tcp.Close()
		return pc, nil
	}
	_ = pc.Close()
	return nil, fmt.Errorf("listen tcp DNS check on %s: %w", addr, err)
}

type loggingDNS struct {
	upstream gdns.Interface
	ch       chan gdns.Request
	done     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
}

func newLoggingDNS(upstream gdns.Interface) *loggingDNS {
	l := &loggingDNS{
		upstream: upstream,
		ch:       make(chan gdns.Request),
		done:     make(chan struct{}),
	}
	l.wg.Add(1)
	go l.run()
	return l
}

func (l *loggingDNS) Requests() chan<- gdns.Request { return l.ch }

func (l *loggingDNS) Close() error {
	l.once.Do(func() { close(l.done) })
	l.wg.Wait()
	return nil
}

func (l *loggingDNS) run() {
	defer l.wg.Done()
	for {
		select {
		case <-l.done:
			return
		case req := <-l.ch:
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				l.proxy(req)
			}()
		}
	}
}

func (l *loggingDNS) proxy(req gdns.Request) {
	fmt.Printf(
		"dns request id=%d questions=%s\n",
		req.Message.ID,
		questions(req.Message),
	)

	reply := make(chan gdns.Response, 1)
	select {
	case l.upstream.Requests() <- gdns.Request{
		Context: req.Context,
		Message: req.Message,
		Reply:   reply,
	}:
	case <-req.Context.Done():
		l.reply(req, gdns.Response{Err: req.Context.Err()})
		return
	case <-l.done:
		l.reply(req, gdns.Response{Err: gdns.ErrClosed})
		return
	}

	select {
	case resp := <-reply:
		if resp.Err != nil {
			fmt.Printf("dns response id=%d err=%v\n", req.Message.ID, resp.Err)
		} else if resp.Message != nil {
			fmt.Printf(
				"dns response id=%d rcode=%d answers=%d\n",
				req.Message.ID,
				resp.Message.RCode,
				len(resp.Message.Answers),
			)
		}
		l.reply(req, resp)
	case <-req.Context.Done():
		l.reply(req, gdns.Response{Err: req.Context.Err()})
	case <-l.done:
		l.reply(req, gdns.Response{Err: gdns.ErrClosed})
	}
}

func (l *loggingDNS) reply(req gdns.Request, resp gdns.Response) {
	select {
	case req.Reply <- resp:
	case <-req.Context.Done():
	case <-l.done:
	}
}

func questions(msg *gdns.Message) string {
	if msg == nil || len(msg.Questions) == 0 {
		return "<none>"
	}
	out := make([]string, 0, len(msg.Questions))
	for _, q := range msg.Questions {
		out = append(out, fmt.Sprintf("%s/%d/%d", q.Name, q.Type, q.Class))
	}
	return strings.Join(out, ",")
}
