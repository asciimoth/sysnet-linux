//go:build linux

//nolint:testpackage // Tests cover package-private monitor injection.
package routing

import (
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const monitorTestTimeout = 3 * time.Second

func TestManagerRouteMonitorTracksNonStrictNetworkChanges(t *testing.T) {
	adapter := newFakeAdapter()
	ethernet := route("192.168.10.0/24")
	ethernet.LinkIndex = 2
	adapter.routes = append(adapter.routes, ethernet)
	manager, updates := newMonitoredTestManager(t, adapter)
	defer func() { _ = manager.Close() }()

	config := testConfig()
	config.Strictness = NonStrict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}
	assertManagerSafeRoutes(t, manager, "192.168.10.0/24")

	manager.mu.Lock()
	adapter.routes = deleteMainRoute(adapter.routes, ethernet.Dst)
	manager.mu.Unlock()
	updates <- mainRouteUpdate()
	awaitManagerSafeRoutes(t, manager)

	wifi := route("10.44.0.0/24")
	wifi.LinkIndex = 3
	manager.mu.Lock()
	adapter.routes = append(adapter.routes, wifi)
	manager.mu.Unlock()
	updates <- mainRouteUpdate()
	awaitManagerSafeRoutes(t, manager, "10.44.0.0/24")

	manager.mu.Lock()
	adapter.routes = deleteMainRoute(adapter.routes, wifi.Dst)
	adapter.routes = append(adapter.routes, ethernet)
	manager.mu.Unlock()
	updates <- mainRouteUpdate()
	awaitManagerSafeRoutes(t, manager, "192.168.10.0/24")
}

func TestManagerRouteMonitorIgnoresStrictPolicy(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.routes = append(adapter.routes, route("192.168.10.0/24"))
	manager, updates := newMonitoredTestManager(t, adapter)
	defer func() { _ = manager.Close() }()

	config := testConfig()
	config.Strictness = Strict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}

	manager.mu.Lock()
	adapter.routes = append(adapter.routes, route("10.44.0.0/24"))
	manager.mu.Unlock()
	updates <- mainRouteUpdate()
	time.Sleep(4 * manager.monitorDebounce)
	assertManagerSafeRoutes(t, manager, "192.168.10.0/24")
}

func TestManagerRouteMonitorIgnoresOwnedTables(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.routes = append(adapter.routes, route("192.168.10.0/24"))
	manager, updates := newMonitoredTestManager(t, adapter)
	defer func() { _ = manager.Close() }()

	config := testConfig()
	config.Strictness = NonStrict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}
	manager.mu.Lock()
	adapter.routes = append(adapter.routes, route("10.44.0.0/24"))
	manager.mu.Unlock()
	updates <- netlink.RouteUpdate{Route: netlink.Route{Table: config.SafeTable}}
	time.Sleep(4 * manager.monitorDebounce)
	assertManagerSafeRoutes(t, manager, "192.168.10.0/24")
}

func TestManagerRouteMonitorRetriesFailedRefresh(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.routes = append(adapter.routes, route("192.168.10.0/24"))
	manager, updates := newMonitoredTestManager(t, adapter)
	defer func() { _ = manager.Close() }()

	config := testConfig()
	config.Strictness = NonStrict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}

	manager.mu.Lock()
	adapter.routes = append(adapter.routes, route("10.44.0.0/24"))
	adapter.replaceRouteErr = errBoom
	manager.mu.Unlock()
	updates <- mainRouteUpdate()

	awaitMonitorCondition(t, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return hasPriority(
			adapter.rules,
			config.PriorityBase+ruleOffsetTransitionGuard,
		)
	})
	manager.mu.Lock()
	adapter.replaceRouteErr = nil
	manager.mu.Unlock()
	awaitManagerSafeRoutes(
		t,
		manager,
		"192.168.10.0/24",
		"10.44.0.0/24",
	)
}

func TestManagerRouteMonitorGuardsBeforeSnapshotAndKeepsGuardOnFailure(
	t *testing.T,
) {
	adapter := newFakeAdapter()
	adapter.routes = append(adapter.routes, route("192.168.10.0/24"))
	manager, updates := newMonitoredTestManager(t, adapter)
	manager.monitorDebounce = 100 * time.Millisecond
	defer func() { _ = manager.Close() }()

	config := testConfig()
	config.Strictness = NonStrict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}

	manager.mu.Lock()
	adapter.routes = append(adapter.routes, route("10.44.0.0/24"))
	adapter.listRoutesErr = errBoom
	manager.mu.Unlock()
	updates <- mainRouteUpdate()
	awaitMonitorCondition(t, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return hasPriority(
			adapter.rules,
			config.PriorityBase+ruleOffsetTransitionGuard,
		)
	})

	time.Sleep(2 * manager.monitorDebounce)
	manager.mu.Lock()
	guardActive := hasPriority(
		adapter.rules,
		config.PriorityBase+ruleOffsetTransitionGuard,
	)
	adapter.listRoutesErr = nil
	manager.mu.Unlock()
	if !guardActive {
		t.Fatal("route-change guard was removed after snapshot failure")
	}
	awaitManagerSafeRoutes(
		t,
		manager,
		"192.168.10.0/24",
		"10.44.0.0/24",
	)
}

func TestManagerRouteMonitorResubscribesAndRefreshesAfterClosure(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.routes = append(adapter.routes, route("192.168.10.0/24"))
	manager := newManagerWithAdapter(adapter)
	manager.monitorDebounce = 5 * time.Millisecond
	manager.monitorRetry = 10 * time.Millisecond
	namespace := netns.NsHandle(123)
	manager.monitorOptions.Namespace = &namespace
	type testSubscription struct {
		fail      chan struct{}
		namespace *netns.NsHandle
	}
	subscriptions := make(chan testSubscription, 2)
	if err := manager.startRouteMonitor(func(
		out chan<- netlink.RouteUpdate,
		done <-chan struct{},
		options netlink.RouteSubscribeOptions,
	) error {
		fail := make(chan struct{})
		subscriptions <- testSubscription{
			fail:      fail,
			namespace: options.Namespace,
		}
		go func() {
			select {
			case <-done:
			case <-fail:
			}
			close(out)
		}()
		return nil
	}); err != nil {
		t.Fatalf("startRouteMonitor error = %v", err)
	}
	defer func() { _ = manager.Close() }()

	config := testConfig()
	config.Strictness = NonStrict
	if err := manager.Apply(config); err != nil {
		t.Fatalf("Apply error = %v", err)
	}
	first := awaitRouteSubscription(t, subscriptions)
	if first.namespace != &namespace {
		t.Fatal("initial subscription did not use captured namespace")
	}
	manager.mu.Lock()
	adapter.routes = append(adapter.routes, route("10.44.0.0/24"))
	manager.mu.Unlock()
	close(first.fail)
	second := awaitRouteSubscription(t, subscriptions)
	if second.namespace != &namespace {
		t.Fatal("recovered subscription changed namespace")
	}
	awaitManagerSafeRoutes(
		t,
		manager,
		"192.168.10.0/24",
		"10.44.0.0/24",
	)
}

func TestManagerCloseDrainsSubscriptionProducer(t *testing.T) {
	adapter := newFakeAdapter()
	manager := newManagerWithAdapter(adapter)
	producerDone := make(chan struct{})
	if err := manager.startRouteMonitor(func(
		out chan<- netlink.RouteUpdate,
		done <-chan struct{},
		_ netlink.RouteSubscribeOptions,
	) error {
		go func() {
			<-done
			for range 128 {
				out <- mainRouteUpdate()
			}
			close(out)
			close(producerDone)
		}()
		return nil
	}); err != nil {
		t.Fatalf("startRouteMonitor error = %v", err)
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- manager.Close() }()
	select {
	case <-producerDone:
	case <-time.After(monitorTestTimeout):
		t.Fatal("subscription producer remained blocked during Close")
	}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("Close error = %v", err)
		}
	case <-time.After(monitorTestTimeout):
		t.Fatal("Close did not finish after subscription drained")
	}
}

func TestManagerConcurrentCloseWaitsForAdapter(t *testing.T) {
	adapter := newFakeAdapter()
	adapter.closeStarted = make(chan struct{})
	adapter.closeRelease = make(chan struct{})
	manager := newManagerWithAdapter(adapter)

	first := make(chan error, 1)
	go func() { first <- manager.Close() }()
	select {
	case <-adapter.closeStarted:
	case <-time.After(monitorTestTimeout):
		t.Fatal("adapter Close did not start")
	}
	second := make(chan error, 1)
	go func() { second <- manager.Close() }()
	select {
	case err := <-second:
		t.Fatalf("concurrent Close returned early with %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(adapter.closeRelease)
	for i, result := range []<-chan error{first, second} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("Close %d error = %v", i+1, err)
			}
		case <-time.After(monitorTestTimeout):
			t.Fatalf("Close %d did not finish", i+1)
		}
	}
	if adapter.closeCalls != 1 {
		t.Fatalf("adapter Close calls = %d, want 1", adapter.closeCalls)
	}
}

func newMonitoredTestManager(
	t *testing.T,
	adapter *fakeAdapter,
) (*Manager, chan<- netlink.RouteUpdate) {
	t.Helper()
	updates := make(chan netlink.RouteUpdate, 8)
	manager := newManagerWithAdapter(adapter)
	manager.monitorDebounce = 5 * time.Millisecond
	manager.monitorRetry = 10 * time.Millisecond
	err := manager.startRouteMonitor(func(
		out chan<- netlink.RouteUpdate,
		done <-chan struct{},
		_ netlink.RouteSubscribeOptions,
	) error {
		go func() {
			defer close(out)
			for {
				select {
				case <-done:
					return
				case update := <-updates:
					select {
					case <-done:
						return
					case out <- update:
					}
				}
			}
		}()
		return nil
	})
	if err != nil {
		t.Fatalf("startRouteMonitor error = %v", err)
	}
	return manager, updates
}

func mainRouteUpdate() netlink.RouteUpdate {
	return netlink.RouteUpdate{
		Type:  unix.RTM_NEWROUTE,
		Route: netlink.Route{Table: unix.RT_TABLE_MAIN},
	}
}

func awaitRouteSubscription[T any](
	t *testing.T,
	subscriptions <-chan T,
) T {
	t.Helper()
	select {
	case subscription := <-subscriptions:
		return subscription
	case <-time.After(monitorTestTimeout):
		t.Fatal("timed out waiting for route monitor subscription")
		var zero T
		return zero
	}
}

func deleteMainRoute(routes []Route, prefix netip.Prefix) []Route {
	out := routes[:0]
	for _, candidate := range routes {
		if candidate.Table == unix.RT_TABLE_MAIN && candidate.Dst == prefix {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func awaitManagerSafeRoutes(t *testing.T, manager *Manager, want ...string) {
	t.Helper()
	awaitMonitorCondition(t, func() bool {
		return managerHasSafeRoutes(manager, want...)
	})
}

func assertManagerSafeRoutes(t *testing.T, manager *Manager, want ...string) {
	t.Helper()
	if !managerHasSafeRoutes(manager, want...) {
		state, _ := manager.Status()
		t.Fatalf("safe routes = %+v, want %v", state.SafeRoutes, want)
	}
}

func managerHasSafeRoutes(manager *Manager, want ...string) bool {
	state, ok := manager.Status()
	if !ok || len(state.SafeRoutes) != len(want) {
		return false
	}
	for _, prefix := range want {
		if !hasRoute(state.SafeRoutes, state.Config.SafeTable, prefix) {
			return false
		}
	}
	return true
}

func awaitMonitorCondition(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(monitorTestTimeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for route monitor")
}
