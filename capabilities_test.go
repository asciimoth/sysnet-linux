//go:build linux

//nolint:testpackage // These tests use the package's injected fake components.
package linux

import (
	"errors"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/p-mark/multirule"
)

// newCapabilityTestSystem supplies every optional dependency. Individual tests
// can therefore control capability state only through FeatureConfig.
func newCapabilityTestSystem(
	t *testing.T,
	features FeatureConfig,
) (*System, *fakeTUNFactory, *fakeTunConfig) {
	t.Helper()
	factory := &fakeTUNFactory{}
	configurator := &fakeTunConfig{}
	listener := &fakePacketListen{}
	system, err := NewSystem(Config{
		Features:       features,
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: &fakeRouting{},
		Connmark:       &fakeConnmark{},
		Pmark:          &fakePmark{},
		Killswitch:     &fakeKillswitch{},
		TUNFactory:     factory,
		TunConfig:      configurator,
		RuleTracker:    multirule.New(),
		OwnerLookup: func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
			return &sockowner.SocketOwner{}, nil
		},
		PacketListen: listener.listen,
		TUNIndex:     func(gtun.Tun) (int, error) { return 9, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Error(err)
		}
	})
	return system, factory, configurator
}

func allCapabilityTestFeatures() FeatureConfig {
	return FeatureConfig{
		Tun:             true,
		DefaultTun:      true,
		DynTun:          true,
		DynDefaultTun:   true,
		TunNames:        true,
		DefaultTunNames: true,
		StrictMode:      true,
		TunRules:        true,
		MatcherRules:    true,
		DNSControl:      true,
		Routing:         true,
		Pmark:           true,
		Killswitch:      true,
	}
}

func TestCapabilitiesPublishCompleteExactCatalog(t *testing.T) {
	system, _, _ := newCapabilityTestSystem(t, allCapabilityTestFeatures())

	report := system.Capabilities()
	if err := report.Validate(); err != nil {
		t.Fatalf("Capabilities validation error = %v", err)
	}
	if report.SchemaVersion != sysnet.CapabilitySchemaVersion ||
		report.Revision == 0 {
		t.Fatalf(
			"report identity = schema %d revision %d",
			report.SchemaVersion,
			report.Revision,
		)
	}
	if got, want := len(report.Operations), 108; got != want {
		t.Fatalf("operation count = %d, want %d", got, want)
	}
	if got, want := len(report.DefaultTunProfiles), 18; got != want {
		t.Fatalf("default TUN profile count = %d, want %d", got, want)
	}
	if got, want := len(report.Rules), len(supportedRules); got != want {
		t.Fatalf("rule count = %d, want %d", got, want)
	}
	if got, want := len(report.Ownership), 4; got != want {
		t.Fatalf("ownership profile count = %d, want %d", got, want)
	}

	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
		sysnet.FamilyDual,
	} {
		for _, mode := range []sysnet.RoutingMode{
			sysnet.RoutingFull,
			sysnet.RoutingExclude,
			sysnet.RoutingInclude,
		} {
			for _, strict := range []bool{false, true} {
				profile := report.DefaultTunProfile(sysnet.RoutingProfileKey{
					Family: family,
					Mode:   mode,
					Strict: strict,
				})
				if profile.State != sysnet.CapabilityAvailable {
					t.Fatalf(
						"profile %+v = %+v, want available",
						profile.Key,
						profile.Capability,
					)
				}
				if mode == sysnet.RoutingFull && len(profile.Rules) != 0 {
					t.Fatalf("full profile %+v has rules", profile.Key)
				}
				if mode != sysnet.RoutingFull &&
					len(profile.Rules) != len(supportedRules) {
					t.Fatalf(
						"selective profile %+v has %d rules",
						profile.Key,
						len(profile.Rules),
					)
				}
			}
		}
	}

	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
		for _, operation := range []sysnet.Operation{
			sysnet.OpDNSPort53Exclusive,
			sysnet.OpDNSSystemExclusive,
		} {
			capability := report.Operation(sysnet.OperationKey{
				Target: sysnet.TargetDefaultTun, Operation: operation, Family: family,
			})
			unsupported := capability.State == sysnet.CapabilityUnsupported
			notImplemented := slices.Contains(
				capability.Reasons,
				sysnet.ReasonNotImplemented,
			)
			if !unsupported || !notImplemented {
				t.Fatalf(
					"DNS exclusivity capability = %+v, want unsupported",
					capability,
				)
			}
		}
	}
}

func TestCapabilitiesAreDeepCopiesWithStableRevision(t *testing.T) {
	system, _, _ := newCapabilityTestSystem(t, allCapabilityTestFeatures())

	first := system.Capabilities()
	originalRevision := first.Revision
	first.Operations[0].Key.Target = "modified"
	first.Operations[0].Reasons = append(
		first.Operations[0].Reasons,
		"modified",
	)
	first.DefaultTunProfiles[2].Rules[0].Type = "modified"
	first.DefaultTunProfiles[2].Rules[0].Reasons = append(
		first.DefaultTunProfiles[2].Rules[0].Reasons,
		"modified",
	)
	first.Rules[0].Matchers[0].Key.Transport = "modified"
	first.Ownership[0].Fields[0].Field = "modified"

	second := system.Capabilities()
	if second.Revision != originalRevision {
		t.Fatalf(
			"unchanged revision = %d, want %d",
			second.Revision,
			originalRevision,
		)
	}
	if err := second.Validate(); err != nil {
		t.Fatalf("mutation changed backend report: %v", err)
	}
	if second.Operations[0].Key.Target == "modified" ||
		second.DefaultTunProfiles[2].Rules[0].Type == "modified" ||
		second.Rules[0].Matchers[0].Key.Transport == "modified" ||
		second.Ownership[0].Fields[0].Field == "modified" {
		t.Fatal("returned nested data aliases backend capability state")
	}

	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 20 {
				snapshot := system.Capabilities()
				if snapshot.Revision != originalRevision {
					t.Errorf(
						"concurrent revision = %d, want %d",
						snapshot.Revision,
						originalRevision,
					)
				}
				if err := snapshot.Validate(); err != nil {
					t.Errorf("concurrent report validation error = %v", err)
				}
			}
		}()
	}
	wait.Wait()
}

func TestCapabilitiesAfterCloseKeepUnsupportedRows(t *testing.T) {
	features := allCapabilityTestFeatures()
	features.DynTun = false
	system, _, _ := newCapabilityTestSystem(t, features)
	open := system.Capabilities()
	if err := system.Close(); err != nil {
		t.Fatal(err)
	}
	closed := system.Capabilities()
	if closed.Revision <= open.Revision {
		t.Fatalf(
			"closed revision = %d, want greater than %d",
			closed.Revision,
			open.Revision,
		)
	}
	allocate := closed.Operation(sysnet.OperationKey{
		Target: sysnet.TargetSystem, Operation: sysnet.OpAllocateIP, Family: sysnet.FamilyIPv4,
	})
	if allocate.State != sysnet.CapabilityUnavailable ||
		!slices.Equal(
			allocate.Reasons,
			[]sysnet.CapabilityReason{sysnet.ReasonSystemClosed},
		) {
		t.Fatalf("closed allocate capability = %+v", allocate)
	}
	exclusive := closed.Operation(sysnet.OperationKey{
		Target:    sysnet.TargetDefaultTun,
		Operation: sysnet.OpDNSSystemExclusive,
		Family:    sysnet.FamilyIPv4,
	})
	if exclusive.State != sysnet.CapabilityUnsupported ||
		!slices.Equal(
			exclusive.Reasons,
			[]sysnet.CapabilityReason{sysnet.ReasonNotImplemented},
		) {
		t.Fatalf("closed unsupported capability = %+v", exclusive)
	}
	dynamic := closed.Operation(sysnet.OperationKey{
		Target:    sysnet.TargetTun,
		Operation: sysnet.OpSetMTU,
		Family:    sysnet.FamilyNone,
	})
	if dynamic.State != sysnet.CapabilityUnavailable ||
		!slices.Equal(
			dynamic.Reasons,
			[]sysnet.CapabilityReason{sysnet.ReasonDisabledByConfig},
		) {
		t.Fatalf("closed disabled capability = %+v", dynamic)
	}
	if err := system.CheckTunOpts(sysnet.TunOpts{}).
		Err(); !errors.Is(
		err,
		sysnet.ErrUnavailable,
	) {
		t.Fatalf("closed CheckTunOpts error = %v, want ErrUnavailable", err)
	}
}

func TestCapabilitiesForTunRejectForeignAndClosedObjects(t *testing.T) {
	features := FeatureConfig{Tun: true, DynTun: true, TunNames: true}
	system, _, _ := newCapabilityTestSystem(t, features)
	foreignSystem, _, _ := newCapabilityTestSystem(t, features)

	tunDevice, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := system.CapabilitiesForTun(tunDevice)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("per-TUN report validation error = %v", err)
	}
	if report.SystemRevision != system.Capabilities().Revision ||
		report.InstanceRevision == 0 {
		t.Fatalf(
			"per-TUN revisions = system %d instance %d",
			report.SystemRevision,
			report.InstanceRevision,
		)
	}
	if capability := report.Operation(sysnet.OperationKey{
		Target: sysnet.TargetTun, Operation: sysnet.OpSetMTU, Family: sysnet.FamilyNone,
	}); capability.State != sysnet.CapabilityAvailable {
		t.Fatalf("per-TUN SetMTU capability = %+v", capability)
	}
	if capability := report.Operation(sysnet.OperationKey{
		Target: sysnet.TargetTun, Operation: sysnet.OpCreate, Family: sysnet.FamilyNone,
	}); capability.State != sysnet.CapabilityUnknown {
		t.Fatalf("per-TUN create capability = %+v, want unknown", capability)
	}
	if _, err := foreignSystem.CapabilitiesForTun(
		tunDevice,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("foreign TUN error = %v, want ErrUnknownTun", err)
	}
	if err := tunDevice.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := system.CapabilitiesForTun(
		tunDevice,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("closed TUN error = %v, want ErrUnknownTun", err)
	}
}

func TestRegularTunCreationNameAndRenameAreIndependent(t *testing.T) {
	system, factory, configurator := newCapabilityTestSystem(t, FeatureConfig{
		Tun: true, TunNames: true,
	})

	const name = "sn-cap-name"
	tunDevice, err := system.BuildTun(sysnet.TunOpts{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	native := factory.created[0]
	if native.name != name || configurator.names[native] != name {
		t.Fatalf(
			"created name = native %q configured %q, want %q",
			native.name,
			configurator.names[native],
			name,
		)
	}
	if err := system.SetTunName(
		tunDevice,
		"sn-cap-next",
	); !errors.Is(
		err,
		sysnet.ErrUnavailable,
	) {
		t.Fatalf("rename error = %v, want ErrUnavailable", err)
	}
	if native.name != name {
		t.Fatalf("unsupported rename changed name to %q", native.name)
	}
}

func TestUnsupportedTunOptionsFailBeforeMutation(t *testing.T) {
	system, factory, configurator := newCapabilityTestSystem(
		t,
		FeatureConfig{Tun: true},
	)

	opts := sysnet.TunOpts{
		Name:      "sn-no-name",
		TunAddrs:  []string{"10.23.0.2/32"},
		TunRoutes: []string{"10.23.0.0/24"},
		MTU:       1300,
	}
	want := opts.Copy()
	if err := system.CheckTunOpts(opts).
		Err(); !errors.Is(
		err,
		sysnet.ErrUnavailable,
	) {
		t.Fatalf("CheckTunOpts error = %v, want ErrUnavailable", err)
	}
	if !reflect.DeepEqual(opts, want) {
		t.Fatalf("CheckTunOpts changed input: got %+v, want %+v", opts, want)
	}
	if len(factory.created) != 0 {
		t.Fatal("CheckTunOpts created a TUN")
	}
	if _, err := system.BuildTun(opts); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("BuildTun error = %v, want ErrUnavailable", err)
	}
	if len(factory.created) != 0 {
		t.Fatal("unsupported named BuildTun invoked the TUN factory")
	}

	tunDevice, err := system.BuildTun(sysnet.TunOpts{MTU: 1300})
	if err != nil {
		t.Fatal(err)
	}
	native := factory.created[0]
	beforeMTU := configurator.mtu[native]
	beforeAddrs := append([]string(nil), configurator.addrs[native]...)
	if err := system.SetTunMTU(
		tunDevice,
		1600,
	); !errors.Is(
		err,
		sysnet.ErrUnavailable,
	) {
		t.Fatalf("SetTunMTU error = %v, want ErrUnavailable", err)
	}
	if err := system.AddTunAddr(
		tunDevice,
		"10.23.0.3/32",
	); !errors.Is(
		err,
		sysnet.ErrUnavailable,
	) {
		t.Fatalf("AddTunAddr error = %v, want ErrUnavailable", err)
	}
	if configurator.mtu[native] != beforeMTU ||
		!slices.Equal(configurator.addrs[native], beforeAddrs) {
		t.Fatal("unsupported dynamic operation invoked the TUN configurator")
	}

	validationErr := system.CheckTunOpts(sysnet.TunOpts{
		TunAddrs: []string{"not-a-prefix"},
	}).Err()
	var typedErr *sysnet.ValidationError
	if !errors.Is(validationErr, sysnet.ErrInvalidOptions) ||
		!errors.As(validationErr, &typedErr) {
		t.Fatalf(
			"invalid prefix error = %v, want typed ErrInvalidOptions",
			validationErr,
		)
	}
}

func TestDefaultTunValidationIsReadOnlyAndContextAware(t *testing.T) {
	system, factory, _ := newCapabilityTestSystem(
		t,
		allCapabilityTestFeatures(),
	)

	opts := sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
		Exclude:   []sysnet.Rule{{Type: "pid", Rule: "7"}},
		Include:   []sysnet.Rule{{Type: "comm", Rule: "curl"}},
	}
	want := opts.Copy()
	report := system.CheckDefaultTunOpts(opts)
	if err := report.Err(); !errors.Is(err, sysnet.ErrInvalidOptions) {
		t.Fatalf("CheckDefaultTunOpts error = %v, want ErrInvalidOptions", err)
	}
	if !reflect.DeepEqual(opts, want) {
		t.Fatalf(
			"CheckDefaultTunOpts changed input: got %+v, want %+v",
			opts,
			want,
		)
	}
	if len(factory.created) != 0 {
		t.Fatal("CheckDefaultTunOpts created a TUN")
	}
	if _, err := system.BuildDefaultTun(
		opts,
	); !errors.Is(
		err,
		sysnet.ErrInvalidOptions,
	) {
		t.Fatalf("BuildDefaultTun error = %v, want ErrInvalidOptions", err)
	}
	if len(factory.created) != 0 {
		t.Fatal("invalid BuildDefaultTun invoked the TUN factory")
	}

	routingKey := sysnet.RoutingProfileKey{
		Family: sysnet.FamilyIPv4, Mode: sysnet.RoutingExclude,
	}
	matcherKey := sysnet.MatcherProfileKey{
		Family: sysnet.FamilyIPv4, Transport: sysnet.TransportTCP,
	}
	err := system.CheckRule(
		sysnet.Rule{Type: "pid", Rule: "7"},
		sysnet.RuleContext{Routing: &routingKey, Matcher: &matcherKey},
	).Err()
	if !errors.Is(err, sysnet.ErrInvalidOptions) {
		t.Fatalf(
			"ambiguous CheckRule context error = %v, want ErrInvalidOptions",
			err,
		)
	}
	err = system.CheckRule(
		sysnet.Rule{Type: "future-rule", Rule: "x"},
		sysnet.RuleContext{Matcher: &matcherKey},
	).Err()
	if !errors.Is(err, sysnet.ErrNotSupported) {
		t.Fatalf("unknown rule error = %v, want ErrNotSupported", err)
	}
}

func TestDefaultTunCapabilitiesAndSetDNSFollowLifecycle(t *testing.T) {
	features := allCapabilityTestFeatures()
	features.DynDefaultTun = false
	system, factory, _ := newCapabilityTestSystem(t, features)

	unsupportedName := sysnet.DefaultTunOpts{
		Name:     "sn-default-cap",
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	}
	if err := system.CheckDefaultTunOpts(unsupportedName).Err(); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("named default TUN validation error = %v", err)
	}
	if _, err := system.BuildDefaultTun(unsupportedName); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("named default TUN build error = %v", err)
	}
	if len(factory.created) != 0 {
		t.Fatal("unsupported default TUN name invoked the TUN factory")
	}

	defaultTun, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	perTun, err := system.CapabilitiesForTun(defaultTun)
	if err != nil {
		t.Fatal(err)
	}
	if capability := perTun.Operation(sysnet.OperationKey{
		Target: sysnet.TargetDefaultTun, Operation: sysnet.OpRename, Family: sysnet.FamilyNone,
	}); capability.State != sysnet.CapabilityUnsupported {
		t.Fatalf(
			"default rename capability = %+v, want unsupported",
			capability,
		)
	}
	if err := system.SetTunName(
		defaultTun,
		"sn-default-next",
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("default rename error = %v, want ErrNotSupported", err)
	}
	if err := defaultTun.SetDNS(newFakeDNSProvider()); err != nil {
		t.Fatalf("SetDNS(provider) error = %v", err)
	}
	if err := defaultTun.SetDNS(nil); err != nil {
		t.Fatalf("SetDNS(nil) error = %v", err)
	}
	if err := defaultTun.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := system.CapabilitiesForTun(
		defaultTun,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("closed default TUN capability error = %v", err)
	}
	if err := defaultTun.SetDNS(nil); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("closed SetDNS error = %v, want ErrUnknownTun", err)
	}
}

func TestPolicyNetworksNeverClaimNativeAccess(t *testing.T) {
	system, _, _ := newCapabilityTestSystem(t, FeatureConfig{})
	if system.OutNet().IsNative() || system.LocalNet().IsNative() {
		t.Fatal("policy-enforcing network reported native access")
	}
}

func TestMatcherRulesUseCurrentOwnerProcessData(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	system, err := NewSystem(Config{
		Features:    FeatureConfig{MatcherRules: true},
		RuleTracker: multirule.New(),
		OwnerLookup: func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
			return &sockowner.SocketOwner{PIDs: []int{os.Getpid()}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, rule := range []sysnet.Rule{
		{Type: "exec", Rule: executable},
		{Type: "cmd", Rule: regexp.QuoteMeta(executable)},
	} {
		t.Run(rule.Type, func(t *testing.T) {
			matcher, err := system.BuildMatcher(rule)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := matcher.Close(); err != nil {
					t.Error(err)
				}
			})
			matched, err := matcher.Match(sockowner.FlowTuple{})
			if err != nil {
				t.Fatal(err)
			}
			if !matched {
				t.Fatalf(
					"matcher for %+v did not match its owner process",
					rule,
				)
			}
		})
	}
}
