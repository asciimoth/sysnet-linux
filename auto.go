//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sockopt"
	pmark "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/fwmark"
	"github.com/asciimoth/p-mark/multirule"
	"github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/killswitch"
	"github.com/asciimoth/sysnet-linux/routing"
	linuxsubnet "github.com/asciimoth/sysnet-linux/subnet"
	linuxtun "github.com/asciimoth/sysnet-linux/tun"
	"golang.org/x/sys/unix"
)

const (
	defaultDNSResolvconfInterface = "sysnet-linux"
	defaultPmarkPriority          = 0
)

// DNSMode selects the host DNS integration used by New.
//
// DNSModeAuto uses dns.DnsMode to detect the host DNS integration.
type DNSMode string

const (
	DNSModeAuto             DNSMode = ""
	DNSModeDisabled         DNSMode = "disabled"
	DNSModeDirect           DNSMode = "direct"
	DNSModeOpenresolv       DNSMode = "openresolv"
	DNSModeDebianResolvconf DNSMode = "debian-resolvconf"
	DNSModeResolved         DNSMode = "systemd-resolved"
)

// DNSConfig configures the DNSProvider built by New.
//
// FallbackServers are used by DNS providers only when no usable original
// upstream resolver is available. ResolvconfInterface is the provider-owned
// resolvconf record name; when empty, "sysnet-linux" is used.
type DNSConfig struct {
	Mode DNSMode

	ResolvconfInterface    string
	ResolvedInterfaceIndex int
	FallbackServers        []netip.AddrPort
}

// PmarkConfig configures the optional p-mark integration built by New.
//
// P-mark is attempted only when PinPath is non-empty. This avoids creating a
// global bpffs directory implicitly. When enabled, New also starts the fwmark
// eBPF manager, because DefaultTun include/exclude rules need p-mark values to
// become socket fwmarks before routing can see them.
type PmarkConfig struct {
	PinPath string

	Callbacks            pmark.Callbacks
	TombCollectionEvents uint64
	TombTTL              time.Duration
	Priority             int
}

// SystemConfig is the high-level, best-effort constructor configuration used by
// New.
//
// The zero value requests all System-level features and lets New auto-detect
// which ones are actually available in the current process environment. Missing
// privileges, absent /dev/net/tun, unavailable routing/DNS/killswitch/p-mark
// integrations, and unsupported optional daemons disable the affected features
// while leaving allocation, OutNet, LocalNet, rule verification, and any other
// available features usable.
//
// For exact dependency injection, deterministic tests, or integrations that
// need a DNS provider tied to a TUN created elsewhere, use NewSystem.
type SystemConfig struct {
	Features FeatureConfig

	Allocator      linuxsubnet.DefaultAllocatorConfig
	DNS            DNSConfig
	KillswitchPath string
	Pmark          PmarkConfig

	AppBypassMark uint32
	AppBypassMask uint32
	UserMark      uint32
	UserMarkMask  uint32

	DefaultTunBaseName string

	KillswitchAllowExclude bool
	Logf                   func(format string, args ...any)
	Callbacks              Callbacks
}

type systemAutoEnvironment struct {
	hasCapability     func(int) bool
	probeTUN          func(TUNFactory) error
	newRoutingManager func() (RoutingManager, error)
	newDNSProvider    func(SystemConfig, gonnect.Network, gonnect.Network) (dns.DNSProvider, error)
	newPmark          func(SystemConfig, func(format string, args ...any)) (PmarkController, []io.Closer, error)
	newKillswitch     func(string, killswitch.Logf) KillswitchClient
}

var autoSystemEnv = systemAutoEnvironment{
	hasCapability:     hasEffectiveCapability,
	probeTUN:          probeTUNCreation,
	newRoutingManager: newNativeRoutingManager,
	newDNSProvider:    newAutoDNSProvider,
	newPmark:          newAutoPmark,
	newKillswitch: func(path string, logf killswitch.Logf) KillswitchClient {
		return killswitch.NewClient(path, logf)
	},
}

// New creates a Linux System by constructing native components under the hood.
//
// New probes the current process environment and enables features on a
// best-effort basis. In particular, TUN and routing are enabled only when
// CAP_NET_ADMIN is effective and a throwaway TUN can be created; DNS control is
// enabled only when a configured provider can be built; killswitch is enabled
// only when requested and a daemon path is usable; TunRules are enabled only
// when p-mark starts successfully. A missing optional integration is logged and
// degrades Features(), rather than making construction fail.
//
// Errors are reserved for invalid static configuration or failures in the
// underlying System constructor after feature degradation.
func New(config SystemConfig) (*System, error) {
	logf := config.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	features := config.Features
	if features == (FeatureConfig{}) {
		features = defaultSystemFeatures()
	}

	allocator := linuxsubnet.NewDefaultAllocator(config.Allocator)
	factory := tunFactoryFunc(linuxtun.CreateDefaultTUN)
	var tunConfig TunConfigurator = systemTunConfigurator{}
	if features.Tun {
		if !autoSystemEnv.hasCapability(unix.CAP_NET_ADMIN) {
			logf("system auto-detect: disabling TUN: missing CAP_NET_ADMIN")
			disableTUNFeatures(&features)
			factory = nil
			tunConfig = nil
		} else if err := autoSystemEnv.probeTUN(factory); err != nil {
			logf("system auto-detect: disabling TUN: %v", err)
			disableTUNFeatures(&features)
			factory = nil
			tunConfig = nil
		}
	}

	var routingManager RoutingManager
	if features.Routing {
		routingManager = setupRoutingManager(&features, logf)
	}

	appMark := config.AppBypassMark
	if appMark == 0 {
		appMark = routing.DefaultAppBypassMark
	}
	dnsNet := buildMarkedNetwork(appMark, logf)
	var dnsProvider dns.DNSProvider
	if features.DNSControl {
		provider, err := autoSystemEnv.newDNSProvider(config, dnsNet, dnsNet)
		if err != nil {
			logf("system auto-detect: disabling DNS control: %v", err)
			features.DNSControl = false
			features.DefaultTun = false
			features.DynDefaultTun = false
		} else {
			dnsProvider = provider
		}
	}

	var extraClosers []io.Closer
	var pmarkController PmarkController
	if features.Pmark {
		controller, closers, err := autoSystemEnv.newPmark(config, logf)
		if err != nil {
			logf("system auto-detect: disabling p-mark: %v", err)
			features.Pmark = false
			features.TunRules = false
			closeAll(closers)
		} else {
			pmarkController = controller
			extraClosers = append(extraClosers, closers...)
			if pmarkController == nil {
				features.Pmark = false
				features.TunRules = false
			}
		}
	}

	var killswitchClient KillswitchClient
	if features.Killswitch {
		killswitchClient = autoSystemEnv.newKillswitch(
			config.KillswitchPath,
			logf,
		)
	} else {
		features.Killswitch = false
	}

	tracker := multirule.New()
	if !features.MatcherRules && !features.TunRules {
		tracker = nil
	}

	system, err := NewSystem(Config{
		Features:               features,
		Allocator:              allocator,
		DNSProvider:            dnsProvider,
		RoutingManager:         routingManager,
		Pmark:                  pmarkController,
		Killswitch:             killswitchClient,
		TUNFactory:             factory,
		TunConfig:              tunConfig,
		RuleTracker:            tracker,
		AppBypassMark:          config.AppBypassMark,
		AppBypassMask:          config.AppBypassMask,
		UserMark:               config.UserMark,
		UserMarkMask:           config.UserMarkMask,
		PmarkPriority:          pmarkPriority(config),
		KillswitchAllowExclude: config.KillswitchAllowExclude,
		Logf:                   logf,
		Callbacks:              config.Callbacks,
		ExtraClosers:           extraClosers,
		DefaultTunBaseName:     config.DefaultTunBaseName,
	})
	if err != nil {
		closeAll(extraClosers)
		if killswitchClient != nil {
			_ = killswitchClient.Close()
		}
		if routingManager != nil {
			_ = routingManager.Close()
		}
		if dnsProvider != nil {
			_ = dnsProvider.Close()
		}
		return nil, err
	}
	return system, nil
}

func defaultSystemFeatures() FeatureConfig {
	return FeatureConfig{
		Tun:           true,
		DefaultTun:    true,
		DynTun:        true,
		DynDefaultTun: true,
		TunNames:      true,
		StrictMode:    true,
		TunRules:      true,
		MatcherRules:  true,
		DNSControl:    true,
		Routing:       true,
		Pmark:         true,
		Killswitch:    true,
	}
}

func disableTUNFeatures(features *FeatureConfig) {
	features.Tun = false
	features.DefaultTun = false
	features.DynTun = false
	features.DynDefaultTun = false
	features.TunNames = false
	features.DefaultTunNames = false
	features.TunRules = false
}

func disableRoutingFeatures(features *FeatureConfig) {
	features.Routing = false
	features.DefaultTun = false
	features.DynDefaultTun = false
	features.StrictMode = false
}

func pmarkPriority(config SystemConfig) int {
	if config.Pmark.Priority != 0 {
		return config.Pmark.Priority
	}
	return defaultPmarkPriority
}

func buildMarkedNetwork(
	mark uint32,
	logf func(format string, args ...any),
) gonnect.Network {
	setRoutingMark := func(network, address string, c syscall.RawConn) {
		if err := sockopt.SetRoutingMark(c, mark); err != nil {
			logf("set SO_MARK on %s %s: %v", network, address, err)
		}
	}
	return gonnect.NativeConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			setRoutingMark(network, address, c)
			return nil
		},
		ControlContext: func(_ context.Context, network, address string, c syscall.RawConn) error {
			setRoutingMark(network, address, c)
			return nil
		},
		ListenCfg: &net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				setRoutingMark(network, address, c)
				return nil
			},
		},
	}.Build()
}

func newNativeRoutingManager() (RoutingManager, error) {
	return routing.NewManager()
}

func setupRoutingManager(
	features *FeatureConfig,
	logf func(format string, args ...any),
) RoutingManager {
	if !autoSystemEnv.hasCapability(unix.CAP_NET_ADMIN) {
		logf("system auto-detect: disabling routing: missing CAP_NET_ADMIN")
		disableRoutingFeatures(features)
		return nil
	}
	manager, err := autoSystemEnv.newRoutingManager()
	if err != nil {
		logf("system auto-detect: disabling routing: %v", err)
		disableRoutingFeatures(features)
		return nil
	}
	return manager
}

func probeTUNCreation(factory TUNFactory) error {
	t, err := factory.CreateTUN("snprobe", 1420)
	if err != nil {
		return err
	}
	return t.Close()
}

func newAutoDNSProvider(
	config SystemConfig,
	listenNetwork gonnect.Network,
	dialNetwork gonnect.Network,
) (dns.DNSProvider, error) {
	dnsConfig := config.DNS
	env := dns.Env{Logf: config.Logf}
	if dnsConfig.Mode == DNSModeDisabled {
		return nil, errors.New("DNS disabled by config")
	}
	if dnsConfig.ResolvconfInterface == "" {
		dnsConfig.ResolvconfInterface = defaultDNSResolvconfInterface
	}
	mode := dnsConfig.Mode
	if mode == DNSModeAuto {
		detected, err := dns.DnsMode(context.Background(), env)
		if err != nil {
			return nil, err
		}
		mode = DNSMode(detected)
	}
	switch mode {
	case DNSModeAuto:
		return nil, errors.New("DNS auto mode was not resolved")
	case DNSModeDisabled:
		return nil, errors.New("DNS disabled by config")
	case DNSModeDirect:
		if !canWriteResolvConf() {
			return nil, errors.New("/etc/resolv.conf is not writable")
		}
		return dns.NewDirect(
			env,
			listenNetwork,
			dialNetwork,
			dnsConfig.FallbackServers...,
		)
	case DNSModeOpenresolv:
		return dns.NewOpenresolv(
			env,
			listenNetwork,
			dialNetwork,
			dnsConfig.ResolvconfInterface,
			dnsConfig.FallbackServers...,
		)
	case DNSModeDebianResolvconf:
		return dns.NewDebianResolvconf(
			env,
			listenNetwork,
			dialNetwork,
			dnsConfig.ResolvconfInterface,
			dnsConfig.FallbackServers...,
		)
	case DNSModeResolved, "resolved":
		return dns.NewResolved(
			env,
			listenNetwork,
			dialNetwork,
			dnsConfig.ResolvedInterfaceIndex,
			dnsConfig.FallbackServers...,
		)
	default:
		return nil, fmt.Errorf("unknown DNS mode %q", mode)
	}
}

func newAutoPmark(
	config SystemConfig,
	logf func(format string, args ...any),
) (PmarkController, []io.Closer, error) {
	if config.Pmark.PinPath == "" {
		return nil, nil, nil
	}
	if err := os.MkdirAll(config.Pmark.PinPath, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create p-mark pin path: %w", err)
	}
	callbacks := config.Pmark.Callbacks
	if callbacks.Logf == nil {
		callbacks.Logf = logf
	}
	var closers []io.Closer
	daemon, err := pmark.NewDaemon(
		config.Pmark.PinPath,
		callbacks,
		config.Pmark.TombCollectionEvents,
		config.Pmark.TombTTL,
	)
	if err != nil {
		return nil, closers, fmt.Errorf("create p-mark daemon: %w", err)
	}
	closers = append(closers, daemon)
	manager, err := fwmark.NewManager(config.Pmark.PinPath, logf)
	if err != nil {
		return nil, closers, fmt.Errorf("create fwmark manager: %w", err)
	}
	closers = append(closers, manager)
	daemon.UpdateHooks(pmarkCallbacksWithFwmark(
		callbacks,
		manager.ProcessUpdateCallback(),
	))
	if err := daemon.Run(); err != nil {
		return nil, closers, fmt.Errorf("run p-mark daemon: %w", err)
	}
	return daemon, closers, nil
}

func pmarkCallbacksWithFwmark(
	callbacks pmark.Callbacks,
	fwmarkUpdate func(pmark.ProcessUpdate),
) pmark.Callbacks {
	previousUpdate := callbacks.ProcessUpdate
	callbacks.ProcessUpdate = func(update pmark.ProcessUpdate) {
		if fwmarkUpdate != nil {
			fwmarkUpdate(update)
		}
		if previousUpdate != nil {
			previousUpdate(update)
		}
	}
	return callbacks
}

func closeAll(closers []io.Closer) {
	for i := len(closers) - 1; i >= 0; i-- {
		if closers[i] != nil {
			_ = closers[i].Close()
		}
	}
}

func canWriteResolvConf() bool {
	if err := unix.Access("/etc/resolv.conf", unix.W_OK); err == nil {
		return true
	}
	if unix.Geteuid() == 0 || hasEffectiveCapability(unix.CAP_DAC_OVERRIDE) {
		dir := filepath.Dir("/etc/resolv.conf")
		return unix.Access(dir, unix.W_OK) == nil
	}
	return false
}

func hasEffectiveCapability(capability int) bool {
	if capability < 0 {
		return false
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := make([]unix.CapUserData, 2)
	if len(data) == 0 {
		return false
	}
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return unix.Geteuid() == 0
	}
	idx := capability / 32
	if idx >= len(data) {
		return false
	}
	return data[idx].Effective&(uint32(1)<<(capability%32)) != 0
}
