//go:build linux

// nolint
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect-netstack/vtun"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/fwmark"
	"github.com/asciimoth/p-mark/multirule"
	linux "github.com/asciimoth/sysnet-linux"
	"github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/routing"
	"golang.org/x/sys/unix"
)

const (
	physLinkName = "snrt-phys0"
	peerLinkName = "snrt-peer0"
	safeLinkName = "snrt-safe0"

	dnsIP         = "10.66.0.1"
	vtunServiceIP = "10.66.0.2"
	vtunHTTPPort  = 18080

	userMark = 0x4d000001

	socketProbeMode = "socket-probe"
	socketProbeComm = "system-e2e"
	curlComm        = "^curl$"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == socketProbeMode {
		if err := runSocketProbe(); err != nil {
			log.Fatalf("socket probe failed: %v", err)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatalf("system e2e failed: %v", err)
	}
	log.Print("system e2e passed")
}

func run() error {
	if err := setupLinksAndMainRoutes(); err != nil {
		return err
	}
	defer cleanupLinks()

	pmarkCtl := &recordingPmark{}
	system, err := newSystem(pmarkCtl)
	if err != nil {
		return err
	}
	defer func() {
		if err := system.Close(); err != nil {
			log.Printf("system cleanup failed: %v", err)
		}
	}()

	if err := checkFeaturesAndRules(system); err != nil {
		return err
	}
	if err := checkRegularTun(system); err != nil {
		return err
	}
	if err := checkDefaultTunLifecycle(system, pmarkCtl); err != nil {
		return err
	}
	if err := checkDefaultTunRuleContexts(system, pmarkCtl); err != nil {
		return err
	}
	if err := checkMatchers(system, pmarkCtl); err != nil {
		return err
	}
	if err := checkFullPmarkEBPFSetup(); err != nil {
		return err
	}

	return nil
}

func newSystem(pmarkCtl linux.PmarkController) (*linux.System, error) {
	plainNet := gonnect.NativeConfig{}.Build()
	dnsProvider, err := dns.NewDirect(
		dns.Env{Logf: log.Printf},
		plainNet,
		plainNet,
		netip.MustParseAddrPort("1.1.1.1:53"),
	)
	if err != nil {
		return nil, fmt.Errorf("create direct DNS provider: %w", err)
	}

	routingManager, err := routing.NewManager()
	if err != nil {
		_ = dnsProvider.Close()
		return nil, fmt.Errorf("create routing manager: %w", err)
	}

	system, err := linux.NewSystem(linux.Config{
		Features: linux.FeatureConfig{
			Tun:           true,
			DefaultTun:    true,
			DynTun:        true,
			DynDefaultTun: true,
			StrictMode:    true,
			TunRules:      true,
			MatcherRules:  true,
			DNSControl:    true,
			Routing:       true,
			Pmark:         true,
		},
		DNSProvider:    dnsProvider,
		RoutingManager: routingManager,
		Pmark:          pmarkCtl,
		RuleTracker:    multirule.New(),
		OwnerLookup:    sockowner.GetSockOwner,
		UserMark:       userMark,
	})
	if err != nil {
		_ = routingManager.Close()
		_ = dnsProvider.Close()
		return nil, fmt.Errorf("create System: %w", err)
	}
	return system, nil
}

func checkFeaturesAndRules(system *linux.System) error {
	features := system.Features()
	if !features.Tun || !features.DefaultTun || !features.StrictMode {
		return fmt.Errorf(
			"features = %+v, want TUN, DefaultTun, StrictMode",
			features,
		)
	}
	rules := system.ListRules()
	if len(rules.TunRules) != 8 {
		return fmt.Errorf("TunRules len = %d, want 8", len(rules.TunRules))
	}
	if len(rules.MatcherRules) != 8 {
		return fmt.Errorf(
			"MatcherRules len = %d, want 8",
			len(rules.MatcherRules),
		)
	}
	if !system.RuleVerify(
		sysnet.Rule{Type: "pid", Rule: strconv.Itoa(os.Getpid())},
	) {
		return fmt.Errorf("pid rule did not verify")
	}
	return nil
}

func checkRegularTun(system *linux.System) error {
	t, err := system.BuildTun(sysnet.TunOpts{
		TunAddrs: []string{"127.0.0.1/8", "10.67.0.1/32"},
		MTU:      1300,
	})
	if err != nil {
		return fmt.Errorf("build regular TUN: %w", err)
	}
	defer func() { _ = t.Close() }()

	addrs, err := system.GetTunAddrs(t)
	if err != nil {
		return fmt.Errorf("get regular TUN addrs: %w", err)
	}
	if !contains(addrs, "10.67.0.1/32") || contains(addrs, "127.0.0.1/8") {
		return fmt.Errorf(
			"regular TUN addrs = %v, want normalized 10.67.0.1/32",
			addrs,
		)
	}
	if err := system.SetTunMTU(
		nil,
		1400,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		return fmt.Errorf("SetTunMTU(nil) = %v, want ErrUnknownTun", err)
	}
	return nil
}

func checkDefaultTunLifecycle(
	system *linux.System,
	pmarkCtl *recordingPmark,
) error {
	pid := strconv.Itoa(os.Getpid())
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Exclude:  []sysnet.Rule{{Type: "pid", Rule: pid}},
	})
	if err != nil {
		return fmt.Errorf("build exclude DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("default TUN name: %w", err)
	}
	if err := waitForResolvconf(dnsIP); err != nil {
		return err
	}
	if err := expectDNSRCode(
		"detached DefaultTun DNS",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	answerA := netip.MustParseAddr("203.0.113.77")
	answerB := netip.MustParseAddr("203.0.113.88")
	dt.SetDns(newStaticDNS(answerA))
	if err := expectDNSA("attached DefaultTun DNS", answerA); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude unmarked public route",
		"9.9.9.9",
		0,
		"dev "+tunName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude user-mark public route",
		"9.9.9.9",
		userMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"exclude app-bypass public route",
		"9.9.9.9",
		routing.DefaultAppBypassMark,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectPmark(pmarkCtl, true); err != nil {
		return err
	}

	rebuilt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Include:  []sysnet.Rule{{Type: "pid", Rule: pid}},
	})
	if err != nil {
		return fmt.Errorf("rebuild include DefaultTun: %w", err)
	}
	defer func() { _ = rebuilt.Close() }()
	rebuiltName, err := rebuilt.Name()
	if err != nil {
		return fmt.Errorf("rebuilt default TUN name: %w", err)
	}
	if rebuiltName != tunName {
		return fmt.Errorf(
			"rebuild created %s, want existing TUN %s",
			rebuiltName,
			tunName,
		)
	}

	dt.SetDns(newStaticDNS(answerB))
	if err := expectDNSRCode(
		"old DefaultTun wrapper after rebuild",
		gdns.RCodeServerFailure,
	); err != nil {
		return err
	}
	rebuilt.SetDns(newStaticDNS(answerB))
	if err := expectDNSA("rebuilt DefaultTun DNS", answerB); err != nil {
		return err
	}
	if err := expectRoute(
		"include unmarked public route",
		"9.9.9.9",
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"include user-mark public route",
		"9.9.9.9",
		userMark,
		"dev "+tunName,
	); err != nil {
		return err
	}
	if err := rebuilt.Close(); err != nil {
		return fmt.Errorf("close rebuilt DefaultTun: %w", err)
	}
	if err := waitForResolvconfNot(dnsIP); err != nil {
		return err
	}
	if err := expectRoute(
		"closed DefaultTun public route",
		"9.9.9.9",
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	return nil
}

type ruleCase struct {
	name string
	rule sysnet.Rule
}

func checkDefaultTunRuleContexts(
	system *linux.System,
	pmarkCtl *recordingPmark,
) error {
	info, cases, err := currentProcessRuleCases()
	if err != nil {
		return err
	}
	for _, contextName := range []string{"exclude", "include"} {
		for _, tc := range cases {
			opts := sysnet.DefaultTunOpts{
				TunAddrs: []string{dnsIP + "/32"},
				DnsIP:    dnsIP,
				MTU:      1400,
			}
			switch contextName {
			case "exclude":
				opts.Exclude = []sysnet.Rule{tc.rule}
			case "include":
				opts.Include = []sysnet.Rule{tc.rule}
			}
			dt, err := system.BuildDefaultTun(opts)
			if err != nil {
				return fmt.Errorf(
					"build %s DefaultTun for %s rule: %w",
					contextName,
					tc.name,
					err,
				)
			}
			if err := expectPmarkInfo(
				pmarkCtl,
				info,
				true,
				fmt.Sprintf("%s DefaultTun %s rule", contextName, tc.name),
			); err != nil {
				_ = dt.Close()
				return err
			}
			if err := dt.Close(); err != nil {
				return fmt.Errorf(
					"close %s DefaultTun for %s rule: %w",
					contextName,
					tc.name,
					err,
				)
			}
		}
	}
	return nil
}

func checkMatchers(system *linux.System, pmarkCtl *recordingPmark) error {
	info, cases, err := currentProcessRuleCases()
	if err != nil {
		return err
	}
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Exclude:  []sysnet.Rule{{Type: "pid", Rule: strconv.Itoa(os.Getpid())}},
	})
	if err != nil {
		return fmt.Errorf("build matcher DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()
	if err := expectPmarkInfo(
		pmarkCtl,
		info,
		true,
		"matcher seed pid rule",
	); err != nil {
		return err
	}

	flow, closeFlow, err := outgoingTunFlow(dt, "9.9.9.9:53")
	if err != nil {
		return err
	}
	defer closeFlow()
	if err := expectAllMatchers(
		system,
		cases,
		flow,
		"outgoing TUN packet",
	); err != nil {
		return err
	}

	localNetSystem, err := newLocalNetOnlySystem()
	if err != nil {
		return err
	}
	defer func() { _ = localNetSystem.Close() }()
	localFlow, closeLocalFlow, err := acceptedLocalNetFlow(localNetSystem)
	if err != nil {
		return err
	}
	defer closeLocalFlow()
	if err := expectAllMatchers(
		system,
		cases,
		localFlow,
		"LocalNet accepted connection",
	); err != nil {
		return err
	}
	return nil
}

func newLocalNetOnlySystem() (*linux.System, error) {
	system, err := linux.NewSystem(linux.Config{
		Features: linux.FeatureConfig{
			MatcherRules: true,
		},
		RuleTracker: multirule.New(),
		OwnerLookup: sockowner.GetSockOwner,
		UserMark:    userMark,
	})
	if err != nil {
		return nil, fmt.Errorf("create LocalNet-only System: %w", err)
	}
	return system, nil
}

func checkFullPmarkEBPFSetup() error {
	harness, err := newPmarkEBPFHarness()
	if err != nil {
		return err
	}
	defer harness.Close()

	if err := checkPmarkEBPFSocketProbe(harness.system); err != nil {
		return err
	}
	if err := checkPmarkEBPFVTunCurl(harness.system); err != nil {
		return err
	}
	return nil
}

type pmarkEBPFHarness struct {
	system  *linux.System
	cleanup func()
}

func (h *pmarkEBPFHarness) Close() {
	if h.cleanup != nil {
		h.cleanup()
	}
}

func newPmarkEBPFHarness() (*pmarkEBPFHarness, error) {
	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	cleanupBPFFS, err := prepareBPFFS()
	if err != nil {
		return nil, err
	}
	cleanups = append(cleanups, cleanupBPFFS)

	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "sysnet-e2e-pmark-")
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create pmark pin path: %w", err)
	}
	cleanups = append(cleanups, func() { _ = os.RemoveAll(pinPath) })

	daemon, err := pmark.NewDaemon(
		pinPath,
		pmark.Callbacks{Logf: log.Printf},
		0,
		0,
	)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create pmark daemon: %w", err)
	}
	cleanups = append(cleanups, func() { _ = daemon.Close() })

	fwmarks, err := fwmark.NewManager(pinPath, log.Printf)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create fwmark eBPF manager: %w", err)
	}
	cleanups = append(cleanups, func() { _ = fwmarks.Close() })

	fwmarkUpdate := fwmarks.ProcessUpdateCallback()
	daemon.UpdateHooks(pmark.Callbacks{
		ProcessUpdate: fwmarkUpdate,
		Logf:          log.Printf,
	})
	if err := daemon.Run(); err != nil {
		cleanup()
		return nil, fmt.Errorf("run pmark daemon: %w", err)
	}

	system, err := newSystem(daemon)
	if err != nil {
		cleanup()
		return nil, err
	}
	cleanups = append(cleanups, func() { _ = system.Close() })

	return &pmarkEBPFHarness{system: system, cleanup: cleanup}, nil
}

func checkPmarkEBPFSocketProbe(system *linux.System) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Include: []sysnet.Rule{{
			Type: "comm",
			Rule: socketProbeComm,
		}},
	})
	if err != nil {
		return fmt.Errorf("build pmark eBPF DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("pmark eBPF default TUN name: %w", err)
	}
	if err := expectRoute(
		"pmark eBPF unmarked public route",
		"9.9.9.9",
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"pmark eBPF user-mark public route",
		"9.9.9.9",
		userMark,
		"dev "+tunName,
	); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	output, err := commandOutputContext(
		ctx,
		os.Args[0],
		socketProbeMode,
		"9.9.9.9:53",
		dnsIP,
		fmt.Sprintf("%#x", userMark),
	)
	if err != nil {
		return fmt.Errorf(
			"run pmark eBPF socket probe with output %q: %w",
			output,
			err,
		)
	}
	return nil
}

func checkPmarkEBPFVTunCurl(system *linux.System) error {
	dt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{dnsIP + "/32"},
		DnsIP:    dnsIP,
		MTU:      1400,
		Include: []sysnet.Rule{{
			Type: "comm",
			Rule: curlComm,
		}},
	})
	if err != nil {
		return fmt.Errorf("build curl pmark eBPF DefaultTun: %w", err)
	}
	defer func() { _ = dt.Close() }()

	tunName, err := dt.Name()
	if err != nil {
		return fmt.Errorf("curl pmark eBPF default TUN name: %w", err)
	}
	if err := expectRoute(
		"curl eBPF unmarked service route",
		vtunServiceIP,
		0,
		"dev "+physLinkName,
	); err != nil {
		return err
	}
	if err := expectRoute(
		"curl eBPF marked service route",
		vtunServiceIP,
		userMark,
		"dev "+tunName,
	); err != nil {
		return err
	}

	serviceURL, stopService, err := startVTunHTTPService(dt)
	if err != nil {
		return err
	}
	defer stopService()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := commandOutputContext(
		ctx,
		"curl",
		"--fail",
		"--silent",
		"--show-error",
		"--max-time",
		"5",
		serviceURL,
	)
	if err != nil {
		return fmt.Errorf(
			"curl vtun service %s output %q: %w",
			serviceURL,
			output,
			err,
		)
	}
	if strings.TrimSpace(output) != "sysnet vtun ok" {
		return fmt.Errorf(
			"curl vtun service response = %q, want %q",
			output,
			"sysnet vtun ok",
		)
	}
	return nil
}

func startVTunHTTPService(dt sysnet.DefaultTun) (string, func(), error) {
	serviceAddr := netip.MustParseAddr(vtunServiceIP)
	serverTun, err := (&vtun.Opts{
		LocalAddrs: []netip.Addr{serviceAddr},
		Name:       "sysnet-e2e-vtun",
	}).Build()
	if err != nil {
		return "", func() {}, fmt.Errorf("build vtun service stack: %w", err)
	}
	bridgeTuns(dt, serverTun)

	listenAddr := netip.AddrPortFrom(serviceAddr, vtunHTTPPort)
	listener, err := serverTun.ListenTCPAddrPort(listenAddr)
	if err != nil {
		_ = serverTun.Close()
		return "", func() {}, fmt.Errorf("listen vtun HTTP service: %w", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "sysnet vtun ok")
		}),
	}
	serveDone := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveDone <- err
			return
		}
		serveDone <- nil
	}()

	stop := func() {
		_ = server.Close()
		_ = listener.Close()
		_ = serverTun.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				log.Printf("vtun HTTP service stopped with error: %v", err)
			}
		case <-time.After(time.Second):
			log.Printf("vtun HTTP service did not stop within timeout")
		}
	}
	return "http://" + listenAddr.String() + "/", stop, nil
}

func bridgeTuns(a, b gtun.Tun) {
	done := make(chan struct{})
	go forwardTunPackets(a, b, done)
	go forwardTunPackets(b, a, done)
	go func() {
		for range b.Events() {
		}
		close(done)
	}()
}

func forwardTunPackets(src, dst gtun.Tun, done <-chan struct{}) {
	readBatch := src.BatchSize()
	if readBatch < 1 {
		readBatch = 1
	}
	mtu, err := src.MTU()
	if err != nil {
		mtu = 1500
	}
	if dstMTU, err := dst.MTU(); err == nil && dstMTU > mtu {
		mtu = dstMTU
	}
	offset := max(src.MRO(), dst.MWO())
	bufs := make([][]byte, readBatch)
	sizes := make([]int, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, mtu+offset)
	}

	for {
		select {
		case <-done:
			return
		default:
		}

		n, err := src.Read(bufs, sizes, offset)
		if err != nil {
			if gtun.IsTunTermError(err) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}
		writeBufs := make([][]byte, n)
		for i := range n {
			writeBufs[i] = bufs[i][:offset+sizes[i]]
		}
		if _, err := dst.Write(
			writeBufs,
			offset,
		); err != nil &&
			gtun.IsTunTermError(err) {
			return
		}
	}
}

func prepareBPFFS() (func(), error) {
	const root = "/sys/fs/bpf"
	if err := os.MkdirAll(root, 0o755); err != nil {
		return func() {}, fmt.Errorf("create bpffs mountpoint: %w", err)
	}
	mounted, err := isBPFFS(root)
	if err != nil {
		return func() {}, err
	}
	if mounted {
		return func() {}, nil
	}
	if err := unix.Mount(
		"bpffs",
		root,
		"bpf",
		0,
		"",
	); err != nil &&
		!errors.Is(err, unix.EBUSY) {
		return func() {}, fmt.Errorf("mount bpffs at %s: %w", root, err)
	}
	mounted, err = isBPFFS(root)
	if err != nil {
		return func() {}, err
	}
	if !mounted {
		return func() {}, fmt.Errorf("%s is not bpffs after mount", root)
	}
	return func() { _ = unix.Unmount(root, 0) }, nil
}

func isBPFFS(path string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false, fmt.Errorf("statfs %s: %w", path, err)
	}
	return stat.Type == unix.BPF_FS_MAGIC, nil
}

func runSocketProbe() error {
	if len(os.Args) != 5 {
		return fmt.Errorf(
			"usage: %s %s <dst> <want-local-ip> <want-mark>",
			os.Args[0],
			socketProbeMode,
		)
	}
	dst := os.Args[2]
	wantLocal, err := netip.ParseAddr(os.Args[3])
	if err != nil {
		return fmt.Errorf("parse wanted local IP: %w", err)
	}
	rawMark, err := strconv.ParseUint(os.Args[4], 0, 32)
	if err != nil {
		return fmt.Errorf("parse wanted mark: %w", err)
	}
	wantMark := uint32(rawMark)

	var gotMark uint32
	var gotLocal netip.Addr
	if err := waitForTimeout(5*time.Second, func() error {
		mark, local, err := udpSocketMarkAndLocal(dst)
		if err != nil {
			return err
		}
		gotMark = mark
		gotLocal = local
		if mark != wantMark {
			return fmt.Errorf("SO_MARK = %#x, want %#x", mark, wantMark)
		}
		if local != wantLocal {
			return fmt.Errorf("local IP = %s, want %s", local, wantLocal)
		}
		return nil
	}); err != nil {
		return err
	}

	fmt.Printf("socket probe mark=%#x local=%s\n", gotMark, gotLocal)
	return nil
}

func udpSocketMarkAndLocal(dst string) (uint32, netip.Addr, error) {
	conn, err := net.Dial("udp4", dst)
	if err != nil {
		return 0, netip.Addr{}, fmt.Errorf("dial UDP probe socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return 0, netip.Addr{}, fmt.Errorf(
			"probe connection is %T, want *net.UDPConn",
			conn,
		)
	}
	localUDP, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, netip.Addr{}, fmt.Errorf(
			"probe local addr is %T, want *net.UDPAddr",
			udpConn.LocalAddr(),
		)
	}
	local, ok := netip.AddrFromSlice(localUDP.IP)
	if !ok {
		return 0, netip.Addr{}, fmt.Errorf(
			"parse probe local IP %v",
			localUDP.IP,
		)
	}

	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return 0, netip.Addr{}, fmt.Errorf("probe syscall conn: %w", err)
	}
	var mark int
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		mark, sockErr = unix.GetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_MARK,
		)
	}); err != nil {
		return 0, netip.Addr{}, fmt.Errorf("probe control socket: %w", err)
	}
	if sockErr != nil {
		return 0, netip.Addr{}, fmt.Errorf("get probe SO_MARK: %w", sockErr)
	}
	return uint32(mark), local.Unmap(), nil
}

func setupLinksAndMainRoutes() error {
	cleanupLinks()
	for ip("route", "del", "default") == nil {
	}
	if err := ip(
		"link",
		"add",
		physLinkName,
		"type",
		"veth",
		"peer",
		"name",
		peerLinkName,
	); err != nil {
		return err
	}
	if err := ip("link", "add", safeLinkName, "type", "dummy"); err != nil {
		return err
	}
	for _, name := range []string{physLinkName, peerLinkName, safeLinkName} {
		if err := ip("link", "set", name, "up"); err != nil {
			return err
		}
	}
	commands := [][]string{
		{"addr", "add", "198.51.100.2/24", "dev", physLinkName},
		{"addr", "add", "198.51.100.1/24", "dev", peerLinkName},
		{"addr", "add", "172.28.0.1/16", "dev", safeLinkName},
		{"route", "add", "default", "via", "198.51.100.1", "dev", physLinkName},
		{
			"route",
			"add",
			"172.29.0.0/16",
			"via",
			"172.28.0.254",
			"dev",
			safeLinkName,
		},
	}
	for _, args := range commands {
		if err := ip(args...); err != nil {
			return err
		}
	}
	return nil
}

func cleanupLinks() {
	_ = ip("link", "del", physLinkName)
	_ = ip("link", "del", safeLinkName)
}

func expectDNSRCode(name string, code uint8) error {
	resp, err := queryDefaultTunDNS()
	if err != nil {
		return fmt.Errorf("%s: query failed: %w", name, err)
	}
	if resp.RCode != code {
		return fmt.Errorf("%s: RCode = %d, want %d", name, resp.RCode, code)
	}
	return nil
}

func expectDNSA(name string, want netip.Addr) error {
	resp, err := queryDefaultTunDNS()
	if err != nil {
		return fmt.Errorf("%s: query failed: %w", name, err)
	}
	if resp.RCode != gdns.RCodeSuccess {
		return fmt.Errorf("%s: RCode = %d, want success", name, resp.RCode)
	}
	for _, rr := range resp.Answers {
		if rr.Type != gdns.TypeA || len(rr.Data) != net.IPv4len {
			continue
		}
		got := netip.AddrFrom4([4]byte(rr.Data))
		if got == want {
			return nil
		}
	}
	return fmt.Errorf("%s: answers = %+v, want A %s", name, resp.Answers, want)
}

func queryDefaultTunDNS() (*gdns.Message, error) {
	client := gdns.NewClient(nil, "udp://"+net.JoinHostPort(dnsIP, "53"))
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return gdns.Query(ctx, client, &gdns.Message{
		ID:               gdns.NextID(),
		Opcode:           gdns.OpcodeQuery,
		RecursionDesired: true,
		Questions: []gdns.Question{{
			Name:  "sysnet-e2e.test.",
			Type:  gdns.TypeA,
			Class: gdns.ClassIN,
		}},
	})
}

func expectRoute(name, dst string, mark uint32, contains string) error {
	output, err := routeGet("-4", dst, mark)
	if err != nil {
		return fmt.Errorf(
			"%s: route get failed with output %q: %w",
			name,
			output,
			err,
		)
	}
	if !strings.Contains(output, contains) {
		return fmt.Errorf(
			"%s: route %q does not contain %q",
			name,
			output,
			contains,
		)
	}
	return nil
}

func routeGet(family, dst string, mark uint32) (string, error) {
	args := []string{family, "route", "get", dst}
	if mark != 0 {
		args = append(args, "mark", fmt.Sprintf("%#x", mark))
	}
	return commandOutput("ip", args...)
}

func waitForResolvconf(server string) error {
	return waitFor(func() error {
		bs, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		if !strings.Contains(string(bs), "nameserver "+server) {
			return fmt.Errorf(
				"/etc/resolv.conf = %q",
				strings.TrimSpace(string(bs)),
			)
		}
		return nil
	})
}

func waitForResolvconfNot(server string) error {
	return waitFor(func() error {
		bs, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		if strings.Contains(string(bs), "nameserver "+server) {
			return fmt.Errorf("/etc/resolv.conf still contains %s", server)
		}
		return nil
	})
}

func waitFor(check func() error) error {
	return waitForTimeout(3*time.Second, check)
}

func waitForTimeout(timeout time.Duration, check func() error) error {
	var last error
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := check(); err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return nil
	}
	return last
}

func expectPmark(pmarkCtl *recordingPmark, wantOK bool) error {
	info := pmark.ProcessInfo{Key: pmark.ProcessKey{Tgid: uint32(os.Getpid())}}
	return expectPmarkInfo(pmarkCtl, info, wantOK, "pmark")
}

func expectPmarkInfo(
	pmarkCtl *recordingPmark,
	info pmark.ProcessInfo,
	wantOK bool,
	name string,
) error {
	pmarkCtl.mu.Lock()
	check := pmarkCtl.check
	setCheckerCalls := pmarkCtl.setCheckerCalls
	forceCalls := pmarkCtl.forceCalls
	pmarkCtl.mu.Unlock()
	if setCheckerCalls == 0 || forceCalls == 0 || check == nil {
		return fmt.Errorf(
			"%s: pmark calls set=%d force=%d check nil=%v",
			name,
			setCheckerCalls,
			forceCalls,
			check == nil,
		)
	}
	priority, mark, ok := check(info)
	if ok != wantOK {
		return fmt.Errorf("%s: pmark check ok = %v, want %v", name, ok, wantOK)
	}
	if ok && (priority != 0 || mark != fwmark.ToMark(userMark)) {
		return fmt.Errorf(
			"%s: pmark check = (%d, %#x, true), want (0, %#x, true)",
			name,
			priority,
			mark,
			fwmark.ToMark(userMark),
		)
	}
	return nil
}

func currentProcessRuleCases() (pmark.ProcessInfo, []ruleCase, error) {
	info, err := currentProcessInfo()
	if err != nil {
		return pmark.ProcessInfo{}, nil, err
	}
	currentUser, err := osuser.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return pmark.ProcessInfo{}, nil, fmt.Errorf(
			"lookup current user: %w",
			err,
		)
	}
	currentGroup, err := osuser.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		return pmark.ProcessInfo{}, nil, fmt.Errorf(
			"lookup current group: %w",
			err,
		)
	}
	if info.Comm == "" || info.Cmdline == "" || info.Exe == "" {
		return pmark.ProcessInfo{}, nil, fmt.Errorf(
			"current process info is incomplete: %+v",
			info,
		)
	}
	cases := []ruleCase{
		{
			name: "comm",
			rule: sysnet.Rule{
				Type: "comm",
				Rule: "^" + regexp.QuoteMeta(info.Comm) + "$",
			},
		},
		{
			name: "exec",
			rule: sysnet.Rule{Type: "exec", Rule: filepath.Base(info.Exe)},
		},
		{
			name: "cmd",
			rule: sysnet.Rule{
				Type: "cmd",
				Rule: regexp.QuoteMeta(info.Cmdline),
			},
		},
		{
			name: "pid",
			rule: sysnet.Rule{Type: "pid", Rule: strconv.Itoa(os.Getpid())},
		},
		{
			name: "user",
			rule: sysnet.Rule{Type: "user", Rule: currentUser.Username},
		},
		{
			name: "uid",
			rule: sysnet.Rule{Type: "uid", Rule: strconv.Itoa(os.Getuid())},
		},
		{
			name: "group",
			rule: sysnet.Rule{Type: "group", Rule: currentGroup.Name},
		},
		{
			name: "gid",
			rule: sysnet.Rule{Type: "gid", Rule: strconv.Itoa(os.Getgid())},
		},
	}
	return info, cases, nil
}

func currentProcessInfo() (pmark.ProcessInfo, error) {
	pid := os.Getpid()
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return pmark.ProcessInfo{}, fmt.Errorf("read /proc/self/exe: %w", err)
	}
	cmdline, err := readProcCmdline(pid)
	if err != nil {
		return pmark.ProcessInfo{}, err
	}
	return pmark.ProcessInfo{
		Key:     pmark.ProcessKey{Tgid: uint32(pid)},
		PPID:    uint32(os.Getppid()),
		Comm:    readProcText(pid, "comm"),
		Cmdline: cmdline,
		Exe:     exe,
	}, nil
}

func readProcText(pid int, name string) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcCmdline(pid int) (string, error) {
	data, err := os.ReadFile(
		filepath.Join("/proc", strconv.Itoa(pid), "cmdline"),
	)
	if err != nil {
		return "", fmt.Errorf("read proc cmdline: %w", err)
	}
	parts := bytes.Split(bytes.Trim(data, "\x00"), []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) != 0 {
			out = append(out, string(part))
		}
	}
	return strings.Join(out, " "), nil
}

func outgoingTunFlow(
	dt sysnet.DefaultTun,
	dst string,
) (sockowner.FlowTuple, func(), error) {
	dstAddr, err := net.ResolveUDPAddr("udp4", dst)
	if err != nil {
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"resolve UDP flow destination: %w",
			err,
		)
	}
	conn, err := net.Dial("udp4", dst)
	if err != nil {
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"dial UDP flow for TUN matcher: %w",
			err,
		)
	}
	flowCh := make(chan sockowner.FlowTuple, 1)
	errCh := make(chan error, 1)
	go func() {
		for {
			packet, err := readOutgoingIPPacket(dt)
			if err != nil {
				errCh <- err
				return
			}
			flow, err := sockowner.FlowTupleFromOutgoingIPPacket(packet)
			if err != nil {
				continue
			}
			if flow.Proto != "udp" || flow.RemotePort != uint16(dstAddr.Port) ||
				!flow.RemoteIP.Equal(dstAddr.IP) {
				continue
			}
			flowCh <- flow
			return
		}
	}()
	send := func() error {
		_, err := conn.Write([]byte("sysnet matcher e2e"))
		return err
	}
	if err := send(); err != nil {
		_ = conn.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"write UDP flow for TUN matcher: %w",
			err,
		)
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case flow := <-flowCh:
			return flow, func() { _ = conn.Close() }, nil
		case err := <-errCh:
			_ = conn.Close()
			return sockowner.FlowTuple{}, func() {}, err
		case <-ticker.C:
			if err := send(); err != nil {
				_ = conn.Close()
				return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
					"write UDP flow for TUN matcher: %w",
					err,
				)
			}
		case <-timeout:
			_ = conn.Close()
			return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
				"timed out reading UDP packet from DefaultTun",
			)
		}
	}
}

func readOutgoingIPPacket(dt sysnet.DefaultTun) ([]byte, error) {
	batchSize := dt.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	offset := dt.MRO()
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, offset+2048)
	}
	n, err := dt.Read(bufs, sizes, offset)
	if err != nil {
		return nil, fmt.Errorf("read DefaultTun packet: %w", err)
	}
	if n < 1 || sizes[0] <= 0 {
		return nil, fmt.Errorf(
			"read DefaultTun packet count=%d size=%d",
			n,
			sizes[0],
		)
	}
	packet := append([]byte(nil), bufs[0][offset:offset+sizes[0]]...)
	return packet, nil
}

func acceptedLocalNetFlow(
	system *linux.System,
) (sockowner.FlowTuple, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	listener, err := system.LocalNet().Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"listen with LocalNet: %w",
			err,
		)
	}
	acceptCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conn
	}()
	client, err := system.LocalNet().Dial(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"dial LocalNet listener: %w",
			err,
		)
	}
	var accepted net.Conn
	select {
	case accepted = <-acceptCh:
	case err := <-errCh:
		_ = client.Close()
		_ = listener.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"accept LocalNet connection: %w",
			err,
		)
	case <-ctx.Done():
		_ = client.Close()
		_ = listener.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"accept LocalNet connection: %w",
			ctx.Err(),
		)
	}
	flow, err := sockowner.IncomingConnPeerFlow(accepted)
	if err != nil {
		_ = accepted.Close()
		_ = client.Close()
		_ = listener.Close()
		return sockowner.FlowTuple{}, func() {}, fmt.Errorf(
			"extract LocalNet accepted flow tuple: %w",
			err,
		)
	}
	cleanup := func() {
		_ = accepted.Close()
		_ = client.Close()
		_ = listener.Close()
	}
	return *flow, cleanup, nil
}

func expectAllMatchers(
	system *linux.System,
	cases []ruleCase,
	flow sockowner.FlowTuple,
	label string,
) error {
	for _, tc := range cases {
		matcher, err := system.BuildMatcher(tc.rule)
		if err != nil {
			return fmt.Errorf("%s %s matcher build: %w", label, tc.name, err)
		}
		matched, matchErr := matcher.Match(flow)
		closeErr := matcher.Close()
		if matchErr != nil {
			return fmt.Errorf("%s %s matcher: %w", label, tc.name, matchErr)
		}
		if closeErr != nil {
			return fmt.Errorf(
				"%s %s matcher close: %w",
				label,
				tc.name,
				closeErr,
			)
		}
		if !matched {
			return fmt.Errorf(
				"%s %s matcher did not match flow %+v",
				label,
				tc.name,
				flow,
			)
		}
	}
	return nil
}

func ip(args ...string) error {
	_, err := commandOutput("ip", args...)
	return err
}

func commandOutput(name string, args ...string) (string, error) {
	return commandOutputContext(context.Background(), name, args...)
}

func commandOutputContext(
	ctx context.Context,
	name string,
	args ...string,
) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	output := strings.TrimSpace(stdout.String() + stderr.String())
	if err != nil {
		if output == "" {
			return output, fmt.Errorf(
				"%s %s: %w",
				name,
				strings.Join(args, " "),
				err,
			)
		}
		return output, fmt.Errorf(
			"%s %s: %w",
			name,
			strings.Join(args, " "),
			errors.Join(err, errors.New(output)),
		)
	}
	return output, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

type recordingPmark struct {
	mu              sync.Mutex
	check           pmark.CheckFunc
	setCheckerCalls int
	forceCalls      int
}

func (r *recordingPmark) SetChecker(check pmark.CheckFunc) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setCheckerCalls++
	r.check = check
	return uint64(r.setCheckerCalls), nil
}

func (r *recordingPmark) ForceProcessTraversal() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forceCalls++
	return nil
}

type staticDNS struct {
	ch     chan gdns.Request
	closed chan struct{}
	answer netip.Addr
}

func newStaticDNS(answer netip.Addr) *staticDNS {
	s := &staticDNS{
		ch:     make(chan gdns.Request),
		closed: make(chan struct{}),
		answer: answer,
	}
	go s.run()
	return s
}

func (s *staticDNS) Requests() chan<- gdns.Request { return s.ch }

func (s *staticDNS) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

func (s *staticDNS) run() {
	for {
		select {
		case req := <-s.ch:
			resp := &gdns.Message{
				ID:                 req.Message.ID,
				Response:           true,
				Opcode:             req.Message.Opcode,
				RCode:              gdns.RCodeSuccess,
				RecursionDesired:   req.Message.RecursionDesired,
				RecursionAvailable: true,
				Questions: append(
					[]gdns.Question(nil),
					req.Message.Questions...),
			}
			for _, q := range req.Message.Questions {
				if q.Type == gdns.TypeA && q.Class == gdns.ClassIN {
					a4 := s.answer.As4()
					resp.Answers = append(resp.Answers, gdns.Resource{
						Name:  q.Name,
						Type:  gdns.TypeA,
						Class: gdns.ClassIN,
						TTL:   60,
						Data:  a4[:],
					})
				}
			}
			req.Reply <- gdns.Response{Message: resp}
		case <-s.closed:
			return
		}
	}
}
