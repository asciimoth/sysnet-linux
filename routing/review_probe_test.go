//nolint:testpackage // Tests exercise package-private desired-state details.
package routing

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReviewBroadGatewayPrefixesAreNotSafe(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/1", "10.0.0.0/7", "192.168.0.0/13"} {
		t.Run(prefix, func(t *testing.T) {
			route := Route{
				Family:    unix.AF_INET,
				Table:     unix.RT_TABLE_MAIN,
				Dst:       netip.MustParsePrefix(prefix),
				Gateway:   netip.MustParseAddr("192.168.1.1"),
				LinkIndex: 2,
				Type:      RouteTypeUnicast,
			}
			if ClassifySafeRoute(route, 77) == RouteSafe {
				t.Errorf("%s via LAN gateway is accepted as safe", prefix)
			}
			cfg := DefaultConfig()
			cfg.TUNIndex = 77
			cfg.UserMark = 0x4d000001
			cfg.Strictness = NonStrict
			state, err := CompileDesiredState(
				cfg,
				Snapshot{MainRoutes: []Route{route}},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.SafeRoutes) != 0 {
				t.Errorf("route copied into safe table: %+v", state.SafeRoutes)
			}
		})
	}
}
