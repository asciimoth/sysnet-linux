//go:build linux

//nolint:testpackage // The tests use internal probe injection points.
package linux

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/sysnet-linux/dns"
	"github.com/asciimoth/sysnet-linux/killswitch"
)

func TestProbeTUNCreation(t *testing.T) {
	firstCreateErr := errors.New("first create failed")
	secondCreateErr := errors.New("second create failed")
	finalCreateErr := errors.New("final create failed")
	closeErr := errors.New("close failed")

	tests := []struct {
		name         string
		results      []tunProbeCreateResult
		wantCalls    int
		wantWaits    []time.Duration
		wantErr      error
		wantCloseErr error
	}{
		{
			name:      "first creation succeeds",
			results:   []tunProbeCreateResult{{tun: &tunProbeTUN{}}},
			wantCalls: 1,
		},
		{
			name: "second creation succeeds",
			results: []tunProbeCreateResult{
				{err: firstCreateErr},
				{tun: &tunProbeTUN{}},
			},
			wantCalls: 2,
			wantWaits: []time.Duration{20 * time.Millisecond},
		},
		{
			name: "third creation succeeds",
			results: []tunProbeCreateResult{
				{err: firstCreateErr},
				{err: secondCreateErr},
				{tun: &tunProbeTUN{}},
			},
			wantCalls: 3,
			wantWaits: []time.Duration{
				20 * time.Millisecond,
				40 * time.Millisecond,
			},
		},
		{
			name: "all creations fail",
			results: []tunProbeCreateResult{
				{err: firstCreateErr},
				{err: secondCreateErr},
				{err: finalCreateErr},
			},
			wantCalls: 3,
			wantWaits: []time.Duration{
				20 * time.Millisecond,
				40 * time.Millisecond,
			},
			wantErr: finalCreateErr,
		},
		{
			name: "EPIPE during cleanup",
			results: []tunProbeCreateResult{{
				tun: &tunProbeTUN{closeErr: syscall.EPIPE},
			}},
			wantCalls:    1,
			wantCloseErr: syscall.EPIPE,
		},
		{
			name: "other error during cleanup",
			results: []tunProbeCreateResult{{
				tun: &tunProbeTUN{closeErr: closeErr},
			}},
			wantCalls:    1,
			wantCloseErr: closeErr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := &tunProbeFactory{results: test.results}
			var waits []time.Duration
			var warnings []string

			err := probeTUNCreation(
				factory,
				func(delay time.Duration) {
					waits = append(waits, delay)
				},
				func(format string, args ...any) {
					warnings = append(warnings, fmt.Sprintf(format, args...))
				},
			)

			if !errors.Is(err, test.wantErr) {
				t.Fatalf("probe error = %v, want %v", err, test.wantErr)
			}
			if factory.calls != test.wantCalls {
				t.Fatalf(
					"creation calls = %d, want %d",
					factory.calls,
					test.wantCalls,
				)
			}
			if !slices.Equal(waits, test.wantWaits) {
				t.Fatalf("waits = %v, want %v", waits, test.wantWaits)
			}
			for _, result := range test.results {
				if result.tun != nil && result.tun.closeCalls != 1 {
					t.Fatalf(
						"close calls = %d, want 1",
						result.tun.closeCalls,
					)
				}
			}
			if test.wantCloseErr == nil {
				if len(warnings) != 0 {
					t.Fatalf("warnings = %v, want none", warnings)
				}
				return
			}
			want := fmt.Sprintf(
				"system auto-detect: TUN probe cleanup failed: %v",
				test.wantCloseErr,
			)
			if !slices.Equal(warnings, []string{want}) {
				t.Fatalf("warnings = %v, want [%q]", warnings, want)
			}
		})
	}
}

func TestNewRetriesOnlyTUNProbe(t *testing.T) {
	oldEnv := autoSystemEnv
	defer func() { autoSystemEnv = oldEnv }()

	probeFactory := &tunProbeFactory{results: []tunProbeCreateResult{
		{err: errors.New("temporary create failure")},
		{tun: &tunProbeTUN{}},
	}}
	var waits []time.Duration
	var routingCalls int
	var dnsCalls int
	var pmarkCalls int
	var killswitchCalls int
	autoSystemEnv = systemAutoEnvironment{
		hasCapability: func(int) bool { return true },
		probeTUN:      probeTUNCreation,
		waitTUNProbeRetry: func(delay time.Duration) {
			waits = append(waits, delay)
		},
		newRoutingManager: func() (RoutingManager, error) {
			routingCalls++
			return &fakeRouting{}, nil
		},
		newDNSProvider: func(
			SystemConfig,
			gonnect.Network,
			gonnect.Network,
		) (dns.DNSProvider, error) {
			dnsCalls++
			return newFakeDNSProvider(), nil
		},
		newPmark: func(
			SystemConfig,
			func(format string, args ...any),
		) (PmarkController, []io.Closer, error) {
			pmarkCalls++
			return &fakePmark{}, nil, nil
		},
		newKillswitch: func(string, killswitch.Logf) KillswitchClient {
			killswitchCalls++
			return &fakeKillswitch{}
		},
	}
	autoSystemEnv.probeTUN = func(
		_ TUNFactory,
		wait func(time.Duration),
		warnf func(string, ...any),
	) error {
		return probeTUNCreation(probeFactory, wait, warnf)
	}

	system, err := New(SystemConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := system.Close(); err != nil {
			t.Error(err)
		}
	}()

	if !system.Features().Tun {
		t.Fatal("TUN feature is disabled after successful retry")
	}
	if probeFactory.calls != 2 {
		t.Fatalf("TUN creation calls = %d, want 2", probeFactory.calls)
	}
	wantWaits := []time.Duration{20 * time.Millisecond}
	if !slices.Equal(waits, wantWaits) {
		t.Fatalf("waits = %v, want %v", waits, wantWaits)
	}
	if routingCalls != 1 || dnsCalls != 1 || pmarkCalls != 1 ||
		killswitchCalls != 1 {
		t.Fatalf(
			"constructor calls = routing:%d DNS:%d p-mark:%d killswitch:%d, want 1 each",
			routingCalls,
			dnsCalls,
			pmarkCalls,
			killswitchCalls,
		)
	}
}

func TestNewDisablesTUNAfterAllProbeAttemptsFail(t *testing.T) {
	oldEnv := autoSystemEnv
	defer func() { autoSystemEnv = oldEnv }()

	finalCreateErr := errors.New("final create failure")
	probeFactory := &tunProbeFactory{results: []tunProbeCreateResult{
		{err: errors.New("first create failure")},
		{err: errors.New("second create failure")},
		{err: finalCreateErr},
	}}
	var waits []time.Duration
	autoSystemEnv.hasCapability = func(int) bool { return true }
	autoSystemEnv.probeTUN = func(
		_ TUNFactory,
		wait func(time.Duration),
		warnf func(string, ...any),
	) error {
		return probeTUNCreation(probeFactory, wait, warnf)
	}
	autoSystemEnv.waitTUNProbeRetry = func(delay time.Duration) {
		waits = append(waits, delay)
	}

	var logs []string
	system, err := New(SystemConfig{
		Features: FeatureConfig{Tun: true},
		Logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := system.Close(); err != nil {
			t.Error(err)
		}
	}()

	if system.Features().Tun {
		t.Fatal("TUN feature remains enabled after three creation failures")
	}
	if probeFactory.calls != 3 {
		t.Fatalf("TUN creation calls = %d, want 3", probeFactory.calls)
	}
	wantWaits := []time.Duration{
		20 * time.Millisecond,
		40 * time.Millisecond,
	}
	if !slices.Equal(waits, wantWaits) {
		t.Fatalf("waits = %v, want %v", waits, wantWaits)
	}
	wantLog := fmt.Sprintf(
		"system auto-detect: disabling TUN: %v",
		finalCreateErr,
	)
	if !slices.Equal(logs, []string{wantLog}) {
		t.Fatalf("logs = %v, want [%q]", logs, wantLog)
	}
}

type tunProbeCreateResult struct {
	tun *tunProbeTUN
	err error
}

type tunProbeFactory struct {
	results []tunProbeCreateResult
	calls   int
}

func (f *tunProbeFactory) CreateTUN(string, int) (gtun.Tun, error) {
	result := f.results[f.calls]
	f.calls++
	return result.tun, result.err
}

type tunProbeTUN struct {
	fakeTun
	closeCalls int
	closeErr   error
}

func (t *tunProbeTUN) Close() error {
	t.closeCalls++
	return t.closeErr
}
