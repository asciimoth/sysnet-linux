//go:build linux

//nolint:testpackage // Tests inspect the resolved native TUN and test fakes.
package linux

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/sysnet-linux/routing"
)

func TestDefaultTunDynamicMethodsResolvePublicWrapper(t *testing.T) {
	factory := &fakeTUNFactory{}
	tunConfig := &fakeTunConfig{}
	routingManager := &fakeRouting{}
	s := newDynamicDefaultTunTestSystem(
		t,
		factory,
		tunConfig,
		routingManager,
		func(gtun.Tun) (int, error) { return 99, nil },
	)

	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	native := factory.created[0]

	if err := s.SetTunMTU(dt, 1428); err != nil {
		t.Fatal(err)
	}
	if got := tunConfig.mtu[native]; got != 1428 {
		t.Fatalf("native MTU = %d, want 1428", got)
	}

	setAddrs := []string{"10.55.0.1/32", "2001:db8:55::1/128"}
	if err := s.SetTunAddrs(dt, setAddrs); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTunAddr(dt, "10.55.0.2/32"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTunAddr(dt, "10.55.0.2/32"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTunAddr(dt, "127.0.0.2/8"); err != nil {
		t.Fatal(err)
	}
	gotAddrs, err := s.GetTunAddrs(dt)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range append(setAddrs, "10.55.0.2/32") {
		if !slices.Contains(gotAddrs, want) {
			t.Fatalf("default TUN addresses = %v, want %s", gotAddrs, want)
		}
	}
	if count := countStrings(gotAddrs, "10.55.0.2/32"); count != 1 {
		t.Fatalf("duplicate address count = %d, want 1 in %v", count, gotAddrs)
	}
	if slices.Contains(gotAddrs, "127.0.0.2/8") {
		t.Fatalf("loopback address was added: %v", gotAddrs)
	}

	if err := s.SetTunRoutes(dt, []string{"::/0"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTunRoute(dt, "198.51.100.0/24"); err != nil {
		t.Fatal(err)
	}
	gotRoutes, err := s.GetTunRotue(dt)
	if err != nil {
		t.Fatal(err)
	}
	wantRoutes := []string{"::/0", "198.51.100.0/24"}
	if !slices.Equal(gotRoutes, wantRoutes) {
		t.Fatalf(
			"default TUN route intent = %v, want %v",
			gotRoutes,
			wantRoutes,
		)
	}
	if got := tunConfig.routes[native]; len(got) != 0 {
		t.Fatalf("native main-table routes = %v, want none", got)
	}
	if routingManager.applied == nil ||
		routingManager.applied.Families != routing.BothFamilies {
		t.Fatalf(
			"routing config = %+v, want both families",
			routingManager.applied,
		)
	}
	if _, configuredWrapper := tunConfig.addrs[dt]; configuredWrapper {
		t.Fatal(
			"configurator received the public wrapper instead of the native TUN",
		)
	}
}

func TestDefaultTunDynamicMethodsRejectForeignAndInactive(t *testing.T) {
	firstFactory := &fakeTUNFactory{}
	first := newDynamicDefaultTunTestSystem(
		t,
		firstFactory,
		&fakeTunConfig{},
		&fakeRouting{},
		func(gtun.Tun) (int, error) { return 10, nil },
	)
	secondFactory := &fakeTUNFactory{}
	second := newDynamicDefaultTunTestSystem(
		t,
		secondFactory,
		&fakeTunConfig{},
		&fakeRouting{},
		func(gtun.Tun) (int, error) { return 20, nil },
	)

	dt, err := first.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := second.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.56.0.1/32"},
		DnsIP:    "10.56.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, update := range map[string]func() error{
		"MTU":       func() error { return first.SetTunMTU(foreign, 1420) },
		"addresses": func() error { return first.SetTunAddrs(foreign, nil) },
		"address": func() error {
			return first.AddTunAddr(foreign, "10.1.0.1/32")
		},
		"routes": func() error { return first.SetTunRoutes(foreign, nil) },
		"route": func() error {
			return first.AddTunRoute(foreign, "0.0.0.0/0")
		},
	} {
		if err := update(); !errors.Is(err, sysnet.ErrUnknownTun) {
			t.Fatalf("foreign %s update = %v, want ErrUnknownTun", name, err)
		}
	}
	if _, err := first.GetTunAddrs(foreign); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("foreign GetTunAddrs = %v, want ErrUnknownTun", err)
	}
	if _, err := first.GetTunRotue(foreign); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("foreign GetTunRotue = %v, want ErrUnknownTun", err)
	}

	oldSource := defaultTunSourceForTest(t, dt).SourceGeneration()
	if err := dt.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := first.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.57.0.1/32"},
		DnsIP:    "10.57.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if current == dt {
		t.Fatal("a new active lifetime reused the closed wrapper")
	}
	currentSource := defaultTunSourceForTest(t, current)
	if got := currentSource.SourceGeneration(); got <= oldSource {
		t.Fatalf(
			"new source generation = %d, want greater than %d",
			got,
			oldSource,
		)
	}
	for name, update := range map[string]func() error{
		"MTU":       func() error { return first.SetTunMTU(dt, 1500) },
		"addresses": func() error { return first.SetTunAddrs(dt, nil) },
		"address": func() error {
			return first.AddTunAddr(dt, "10.1.0.1/32")
		},
		"routes": func() error { return first.SetTunRoutes(dt, nil) },
		"route": func() error {
			return first.AddTunRoute(dt, "0.0.0.0/0")
		},
	} {
		if err := update(); !errors.Is(err, sysnet.ErrUnknownTun) {
			t.Fatalf("inactive %s update = %v, want ErrUnknownTun", name, err)
		}
	}
	if _, err := first.GetTunAddrs(dt); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("inactive GetTunAddrs = %v, want ErrUnknownTun", err)
	}
	if _, err := first.GetTunRotue(dt); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("inactive GetTunRotue = %v, want ErrUnknownTun", err)
	}
	if _, err := dt.Read(nil, nil, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("inactive Read = %v, want closed error", err)
	}
	if _, err := dt.Write(nil, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("inactive Write = %v, want closed error", err)
	}
	if _, err := dt.MTU(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("inactive MTU = %v, want closed error", err)
	}
	if _, err := dt.Name(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("inactive Name = %v, want closed error", err)
	}
	if dt.File() != nil || dt.IsNative() || dt.MWO() != 0 || dt.MRO() != 0 ||
		dt.BatchSize() != 1 {
		t.Fatal("inactive metadata did not return safe zero values")
	}
	select {
	case _, open := <-dt.Events():
		if open {
			t.Fatal("inactive Events channel is open")
		}
	default:
		t.Fatal("inactive Events channel did not close")
	}
	if err := dt.Close(); err != nil {
		t.Fatal(err)
	}
	if firstFactory.created[1].closed {
		t.Fatal("closing an inactive wrapper closed the active native TUN")
	}
}

func TestDefaultTunAddressUpdateRollsBackConfiguratorFailure(t *testing.T) {
	factory := &fakeTUNFactory{}
	tunConfig := &failingDefaultTunConfig{fakeTunConfig: &fakeTunConfig{}}
	s := newDynamicDefaultTunTestSystem(
		t,
		factory,
		tunConfig,
		&fakeRouting{},
		func(gtun.Tun) (int, error) { return 99, nil },
	)

	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	native := factory.created[0]
	oldAddrs := append([]string(nil), tunConfig.addrs[native]...)
	tunConfig.failSetRoutes = true
	err = s.SetTunAddrs(
		dt,
		[]string{"10.55.0.1/32", "2001:db8:55::1/128"},
	)
	if !errors.Is(err, errInjectedTunConfig) {
		t.Fatalf("SetTunAddrs error = %v, want injected failure", err)
	}
	if got := tunConfig.addrs[native]; !slices.Equal(got, oldAddrs) {
		t.Fatalf("addresses after rollback = %v, want %v", got, oldAddrs)
	}
	if got := tunConfig.routes[native]; len(got) != 0 {
		t.Fatalf("main-table routes after rollback = %v, want none", got)
	}
}

func TestDefaultTunDynamicUpdateMatchesFullRebuild(t *testing.T) {
	factory := &fakeTUNFactory{}
	tunConfig := &fakeTunConfig{}
	routingManager := &fakeRouting{}
	s := newDynamicDefaultTunTestSystem(
		t,
		factory,
		tunConfig,
		routingManager,
		func(gtun.Tun) (int, error) { return 99, nil },
	)

	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
		MTU:       1280,
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceGeneration := defaultTunSourceForTest(t, dt).SourceGeneration()
	native := factory.created[0]
	wantAddrs := []string{
		"127.0.0.2/8",
		"10.55.0.1/32",
		"10.55.0.1/32",
		"2001:db8:55::1/128",
	}
	wantRoutes := []string{
		"0.0.0.0/0",
		"::/0",
		"::/0",
		"127.0.0.0/8",
	}

	if err := s.SetTunMTU(dt, 9000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTunAddrs(dt, wantAddrs); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTunRoutes(dt, wantRoutes); err != nil {
		t.Fatal(err)
	}
	dynamicAddrs := append([]string(nil), tunConfig.addrs[native]...)
	dynamicRoutes, err := s.GetTunRotue(dt)
	if err != nil {
		t.Fatal(err)
	}
	dynamicRC := cloneRoutingConfigForTest(*routingManager.applied)

	rebuilt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  wantAddrs,
		TunRoutes: wantRoutes,
		DnsIP:     "10.55.0.1",
		MTU:       9000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt != dt {
		t.Fatal("full rebuild changed the stable wrapper")
	}
	currentSource := defaultTunSourceForTest(t, dt)
	if got := currentSource.SourceGeneration(); got != sourceGeneration {
		t.Fatalf(
			"full rebuild source generation = %d, want %d",
			got,
			sourceGeneration,
		)
	}
	if got := tunConfig.addrs[native]; !slices.Equal(got, dynamicAddrs) {
		t.Fatalf(
			"rebuilt addresses = %v, want dynamic state %v",
			got,
			dynamicAddrs,
		)
	}
	if got := tunConfig.mtu[native]; got != 9000 {
		t.Fatalf("rebuilt MTU = %d, want 9000", got)
	}
	if got, err := s.GetTunRotue(dt); err != nil {
		t.Fatal(err)
	} else if !slices.Equal(got, dynamicRoutes) {
		t.Fatalf("rebuilt route intent = %v, want %v", got, dynamicRoutes)
	}
	if got := *routingManager.applied; !reflect.DeepEqual(got, dynamicRC) {
		t.Fatalf("rebuilt routing config = %+v, want %+v", got, dynamicRC)
	}
	if got := tunConfig.routes[native]; len(got) != 0 {
		t.Fatalf("rebuilt main-table routes = %v, want none", got)
	}
}

func TestDefaultTunDynamicMTUEdgeValues(t *testing.T) {
	factory := &fakeTUNFactory{}
	tunConfig := &fakeTunConfig{}
	s := newDynamicDefaultTunTestSystem(
		t,
		factory,
		tunConfig,
		&fakeRouting{},
		func(gtun.Tun) (int, error) { return 99, nil },
	)
	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	native := factory.created[0]
	for _, mtu := range []int{1280, 1420, 1428, 1500, 9000} {
		if err := s.SetTunMTU(dt, mtu); err != nil {
			t.Fatalf("SetTunMTU(%d): %v", mtu, err)
		}
		if got := tunConfig.mtu[native]; got != mtu {
			t.Fatalf("native MTU after %d = %d", mtu, got)
		}
	}
}

func TestDefaultTunDynamicAddressValidationIsAtomic(t *testing.T) {
	factory := &fakeTUNFactory{}
	tunConfig := &fakeTunConfig{}
	routingManager := &fakeRouting{}
	s := newDynamicDefaultTunTestSystem(
		t,
		factory,
		tunConfig,
		routingManager,
		func(gtun.Tun) (int, error) { return 99, nil },
	)
	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32", "100.64.0.2/32"},
		DnsIP:    "10.55.0.1",
		SourceRoutes: []sysnet.TunSourceRoute{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	native := factory.created[0]
	originalAddrs := append([]string(nil), tunConfig.addrs[native]...)
	originalApplyCount := len(routingManager.appliedConfigs)

	tests := []struct {
		name        string
		addrs       []string
		wantIs      error
		wantErrText string
	}{
		{
			name:   "DNS address removed",
			addrs:  []string{"10.56.0.1/32", "100.64.0.2/32"},
			wantIs: sysnet.ErrNotSupported,
		},
		{
			name:        "source-route address removed",
			addrs:       []string{"10.55.0.1/32"},
			wantErrText: "removes source route address",
		},
		{
			name:        "invalid prefix",
			addrs:       []string{"not-a-prefix"},
			wantErrText: "ParsePrefix",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := s.SetTunAddrs(dt, test.addrs)
			if err == nil {
				t.Fatal("SetTunAddrs error = nil")
			}
			if test.wantIs != nil && !errors.Is(err, test.wantIs) {
				t.Fatalf("SetTunAddrs error = %v, want %v", err, test.wantIs)
			}
			if test.wantErrText != "" &&
				!strings.Contains(err.Error(), test.wantErrText) {
				t.Fatalf(
					"SetTunAddrs error = %q, want text %q",
					err,
					test.wantErrText,
				)
			}
			gotAddrs := tunConfig.addrs[native]
			if !slices.Equal(gotAddrs, originalAddrs) {
				t.Fatalf(
					"addresses changed to %v, want %v",
					gotAddrs,
					originalAddrs,
				)
			}
			gotApplyCount := len(routingManager.appliedConfigs)
			if gotApplyCount != originalApplyCount {
				t.Fatalf(
					"routing apply count = %d, want %d",
					gotApplyCount,
					originalApplyCount,
				)
			}
		})
	}
}

func TestDefaultTunRouteUpdateRollsBackRoutingFailure(t *testing.T) {
	factory := &fakeTUNFactory{}
	tunConfig := &fakeTunConfig{}
	routingManager := &failOnceRouting{fakeRouting: &fakeRouting{}}
	s := newDynamicDefaultTunTestSystem(
		t,
		factory,
		tunConfig,
		routingManager,
		func(gtun.Tun) (int, error) { return 99, nil },
	)
	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldRC := cloneRoutingConfigForTest(*routingManager.applied)
	routingManager.failNext = true
	err = s.SetTunRoutes(dt, []string{"::/0"})
	if !errors.Is(err, errInjectedRouting) {
		t.Fatalf("SetTunRoutes error = %v, want injected failure", err)
	}
	if got, err := s.GetTunRotue(dt); err != nil {
		t.Fatal(err)
	} else if !slices.Equal(got, []string{"0.0.0.0/0"}) {
		t.Fatalf("route intent after rollback = %v", got)
	}
	if got := *routingManager.applied; !reflect.DeepEqual(got, oldRC) {
		t.Fatalf("routing config after rollback = %+v, want %+v", got, oldRC)
	}
	if len(routingManager.rollbackConfigs) != 1 {
		t.Fatalf(
			"routing rollback calls = %d, want 1",
			len(routingManager.rollbackConfigs),
		)
	}
	if got := tunConfig.routes[factory.created[0]]; len(got) != 0 {
		t.Fatalf("main-table routes after rollback = %v, want none", got)
	}
}

func TestDefaultTunReplacementKeepsWrapperAndChangesSource(t *testing.T) {
	factory := &blockingTUNFactory{}
	tunConfig := &fakeTunConfig{}
	var linkDeleted atomic.Bool
	s := newDynamicDefaultTunTestSystem(
		t,
		factory,
		tunConfig,
		&fakeRouting{},
		func(tun gtun.Tun) (int, error) {
			if tun == factory.first() && linkDeleted.Load() {
				return 0, errors.New("link deleted")
			}
			return 99, nil
		},
	)

	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	source := defaultTunSourceForTest(t, dt)
	firstGeneration := source.SourceGeneration()
	sameSource, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.55.0.1/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		DnsIP:     "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sameSource != dt {
		t.Fatal("configuration rebuild changed the stable public wrapper")
	}
	if got := source.SourceGeneration(); got != firstGeneration {
		t.Fatalf(
			"configuration rebuild source generation = %d, want %d",
			got,
			firstGeneration,
		)
	}

	readDone := make(chan error, 1)
	go func() {
		_, err := dt.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0)
		readDone <- err
	}()
	<-factory.first().readStarted
	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, err := dt.Write([][]byte{{1}, {2}}, 0)
		writeDone <- writeResult{n: n, err: err}
	}()
	<-factory.first().writeStarted
	oldEvents := dt.Events()
	metadataDone := make(chan struct{})
	var metadataWG sync.WaitGroup
	metadataWG.Add(1)
	go func() {
		defer metadataWG.Done()
		for {
			select {
			case <-metadataDone:
				return
			default:
				_ = dt.File()
				_ = dt.IsNative()
				_ = dt.MWO()
				_ = dt.MRO()
				_, _ = dt.MTU()
				_, _ = dt.Name()
				_ = dt.Events()
				_ = dt.BatchSize()
				_ = source.SourceGeneration()
			}
		}
	}()

	linkDeleted.Store(true)
	rebuilt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err != nil {
		close(metadataDone)
		metadataWG.Wait()
		t.Fatal(err)
	}
	close(metadataDone)
	metadataWG.Wait()
	if rebuilt != dt {
		t.Fatal("native replacement changed the stable public wrapper")
	}
	if got := source.SourceGeneration(); got != firstGeneration+1 {
		t.Fatalf("source generation = %d, want %d", got, firstGeneration+1)
	}
	if err := <-readDone; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("read on replaced source = %v, want closed error", err)
	}
	write := <-writeDone
	if write.n != 1 || !errors.Is(write.err, os.ErrClosed) {
		t.Fatalf(
			"write on replaced source = (%d, %v), want (1, closed error)",
			write.n,
			write.err,
		)
	}
	select {
	case _, open := <-oldEvents:
		if open {
			t.Fatal("old event source produced an unexpected event")
		}
	default:
		t.Fatal("old event source remained open after replacement")
	}
	if newEvents := dt.Events(); newEvents == oldEvents {
		t.Fatal("replacement kept the old event source")
	}

	_, err = dt.Read(
		[][]byte{make([]byte, 64)},
		make([]int, 1),
		0,
	)
	if !errors.Is(err, errReplacementRead) {
		t.Fatalf("read after replacement = %v, want replacement source", err)
	}
	if _, err := dt.Write([][]byte{{1}}, 0); !errors.Is(
		err,
		errReplacementWrite,
	) {
		t.Fatalf("write after replacement = %v, want replacement source", err)
	}
}

func TestDefaultTunRejectsIncompatibleNativeReplacement(t *testing.T) {
	factory := &blockingTUNFactory{replacementBatch: 3}
	var linkDeleted atomic.Bool
	s := newDynamicDefaultTunTestSystem(
		t,
		factory,
		&fakeTunConfig{},
		&fakeRouting{},
		func(tun gtun.Tun) (int, error) {
			if tun == factory.first() && linkDeleted.Load() {
				return 0, errors.New("link deleted")
			}
			return 99, nil
		},
	)
	dt, err := s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	generation := defaultTunSourceForTest(t, dt).SourceGeneration()
	linkDeleted.Store(true)
	_, err = s.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.55.0.1/32"},
		DnsIP:    "10.55.0.1",
	})
	if err == nil || !strings.Contains(
		err.Error(),
		"incompatible I/O metadata",
	) {
		t.Fatalf("incompatible replacement error = %v", err)
	}
	source := defaultTunSourceForTest(t, dt)
	if got := source.SourceGeneration(); got != generation {
		t.Fatalf("source generation = %d, want unchanged %d", got, generation)
	}
	if factory.first().isClosed() {
		t.Fatal("incompatible replacement closed the active source")
	}
	if !factory.second().isClosed() {
		t.Fatal("incompatible replacement source was not closed")
	}
}

func newDynamicDefaultTunTestSystem(
	t *testing.T,
	factory TUNFactory,
	tunConfig TunConfigurator,
	routingManager RoutingManager,
	tunIndex TUNIndexFunc,
) *System {
	t.Helper()
	s, err := NewSystem(Config{
		Features: FeatureConfig{
			Tun:           true,
			DefaultTun:    true,
			DynTun:        true,
			DynDefaultTun: true,
			DNSControl:    true,
			Routing:       true,
		},
		DNSProvider:    newFakeDNSProvider(),
		RoutingManager: routingManager,
		TUNFactory:     factory,
		TunConfig:      tunConfig,
		PacketListen:   (&fakePacketListen{}).listen,
		TUNIndex:       tunIndex,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close test system: %v", err)
		}
	})
	return s
}

func defaultTunSourceForTest(
	t *testing.T,
	tun sysnet.DefaultTun,
) DefaultTunSource {
	t.Helper()
	source, ok := tun.(DefaultTunSource)
	if !ok {
		t.Fatal("default TUN does not expose its source generation")
	}
	return source
}

func countStrings(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

var errReplacementRead = errors.New("replacement read")

var errReplacementWrite = errors.New("replacement write")

var errInjectedTunConfig = errors.New("injected TUN configurator failure")

var errInjectedRouting = errors.New("injected routing failure")

type failOnceRouting struct {
	*fakeRouting
	failNext bool
}

func (r *failOnceRouting) Apply(config routing.Config) error {
	if r.failNext {
		r.failNext = false
		return errInjectedRouting
	}
	return r.fakeRouting.Apply(config)
}

type failingDefaultTunConfig struct {
	*fakeTunConfig
	failSetRoutes bool
}

func (c *failingDefaultTunConfig) SetTunRoutes(
	tun gtun.Tun,
	routes []string,
) error {
	if c.failSetRoutes {
		c.failSetRoutes = false
		return errInjectedTunConfig
	}
	return c.fakeTunConfig.SetTunRoutes(tun, routes)
}

type blockingTUNFactory struct {
	mu               sync.Mutex
	created          []*blockingTun
	replacementBatch int
}

func (f *blockingTUNFactory) CreateTUN(string, int) (gtun.Tun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tun := &blockingTun{
		events:       make(chan gtun.Event),
		readStarted:  make(chan struct{}),
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
		batchSize:    2,
	}
	if len(f.created) > 0 {
		tun.readErr = errReplacementRead
		tun.writeErr = errReplacementWrite
		if f.replacementBatch > 0 {
			tun.batchSize = f.replacementBatch
		}
	}
	f.created = append(f.created, tun)
	return tun, nil
}

func (f *blockingTUNFactory) first() *blockingTun {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created[0]
}

func (f *blockingTUNFactory) second() *blockingTun {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created[1]
}

type blockingTun struct {
	closeOnce    sync.Once
	readOnce     sync.Once
	writeOnce    sync.Once
	events       chan gtun.Event
	readStarted  chan struct{}
	writeStarted chan struct{}
	closed       chan struct{}
	readErr      error
	writeErr     error
	batchSize    int
}

func (t *blockingTun) File() *os.File { return nil }
func (t *blockingTun) IsNative() bool { return true }
func (t *blockingTun) Read([][]byte, []int, int) (int, error) {
	t.readOnce.Do(func() { close(t.readStarted) })
	if t.readErr != nil {
		return 0, t.readErr
	}
	<-t.closed
	return 0, os.ErrClosed
}
func (t *blockingTun) Write([][]byte, int) (int, error) {
	t.writeOnce.Do(func() { close(t.writeStarted) })
	if t.writeErr != nil {
		return 0, t.writeErr
	}
	<-t.closed
	return 1, os.ErrClosed
}
func (t *blockingTun) MWO() int          { return 0 }
func (t *blockingTun) MRO() int          { return 0 }
func (t *blockingTun) MTU() (int, error) { return 1500, nil }
func (t *blockingTun) Name() (string, error) {
	return "blocking0", nil
}
func (t *blockingTun) Events() <-chan gtun.Event { return t.events }
func (t *blockingTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}
func (t *blockingTun) BatchSize() int { return t.batchSize }

func (t *blockingTun) isClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
