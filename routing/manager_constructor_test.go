//go:build linux

//nolint:testpackage // Tests cover package-private constructor dependencies.
package routing

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestManagerNamespaceModes(t *testing.T) {
	tests := []struct {
		name           string
		mode           MonitorNamespace
		wantNamespace  bool
		wantGetCalls   int
		wantCloseCalls int
	}{
		{
			name:           "pinned",
			mode:           PinnedNamespace,
			wantNamespace:  true,
			wantGetCalls:   1,
			wantCloseCalls: 1,
		},
		{name: "current", mode: CurrentNamespace},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := newFakeAdapter()
			getCalls := 0
			namespaceCloseCalls := 0
			var subscribedNamespace *netns.NsHandle
			manager, err := newManager(
				ManagerOptions{MonitorNamespace: test.mode},
				managerDependencies{
					newAdapter: func() (netlinkAdapter, error) {
						return adapter, nil
					},
					getNamespace: func() (netns.NsHandle, error) {
						getCalls++
						return netns.NsHandle(123), nil
					},
					closeNamespace: func(netns.NsHandle) error {
						namespaceCloseCalls++
						return nil
					},
					subscribe: func(
						out chan<- netlink.RouteUpdate,
						done <-chan struct{},
						options netlink.RouteSubscribeOptions,
					) error {
						subscribedNamespace = options.Namespace
						go func() {
							<-done
							close(out)
						}()
						return nil
					},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if (subscribedNamespace != nil) != test.wantNamespace {
				t.Fatalf(
					"subscription namespace set = %v, want %v",
					subscribedNamespace != nil,
					test.wantNamespace,
				)
			}
			if getCalls != test.wantGetCalls {
				t.Fatalf(
					"namespace get calls = %d, want %d",
					getCalls,
					test.wantGetCalls,
				)
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			if adapter.closeCalls != 1 {
				t.Fatalf("adapter close calls = %d, want 1", adapter.closeCalls)
			}
			if namespaceCloseCalls != test.wantCloseCalls {
				t.Fatalf(
					"namespace close calls = %d, want %d",
					namespaceCloseCalls,
					test.wantCloseCalls,
				)
			}
		})
	}
}

func TestManagerConstructionFailureClosesResources(t *testing.T) {
	tests := []struct {
		name                    string
		mode                    MonitorNamespace
		getErr                  error
		subscribeErr            error
		wantNamespaceCloseCalls int
	}{
		{name: "namespace acquisition", mode: PinnedNamespace, getErr: errBoom},
		{
			name:                    "pinned subscription",
			mode:                    PinnedNamespace,
			subscribeErr:            errBoom,
			wantNamespaceCloseCalls: 1,
		},
		{
			name:         "current subscription",
			mode:         CurrentNamespace,
			subscribeErr: errBoom,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := newFakeAdapter()
			namespaceCloseCalls := 0
			_, err := newManager(
				ManagerOptions{MonitorNamespace: test.mode},
				managerDependencies{
					newAdapter: func() (netlinkAdapter, error) { return adapter, nil },
					getNamespace: func() (netns.NsHandle, error) {
						return netns.NsHandle(123), test.getErr
					},
					closeNamespace: func(netns.NsHandle) error {
						namespaceCloseCalls++
						return nil
					},
					subscribe: func(
						chan<- netlink.RouteUpdate,
						<-chan struct{},
						netlink.RouteSubscribeOptions,
					) error {
						return test.subscribeErr
					},
				},
			)
			if !errors.Is(err, errBoom) {
				t.Fatalf("construction error = %v, want %v", err, errBoom)
			}
			if adapter.closeCalls != 1 {
				t.Fatalf("adapter close calls = %d, want 1", adapter.closeCalls)
			}
			if namespaceCloseCalls != test.wantNamespaceCloseCalls {
				t.Fatalf(
					"namespace close calls = %d, want %d",
					namespaceCloseCalls,
					test.wantNamespaceCloseCalls,
				)
			}
		})
	}
}
