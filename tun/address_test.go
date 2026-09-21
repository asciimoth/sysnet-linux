//go:build linux

package tun //nolint:testpackage // Tests cover internal reconciliation plans.

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNetlinkAddrFromPrefixSetsIPv6NoDAD(t *testing.T) {
	tests := []struct {
		name      string
		prefix    string
		wantNoDAD bool
	}{
		{name: "IPv4", prefix: "192.0.2.1/24", wantNoDAD: false},
		{name: "IPv6", prefix: "fd00::1/64", wantNoDAD: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr, err := netlinkAddrFromPrefix(
				netip.MustParsePrefix(test.prefix),
			)
			if err != nil {
				t.Fatalf("netlinkAddrFromPrefix error = %v", err)
			}
			gotNoDAD := addr.Flags&unix.IFA_F_NODAD != 0
			if gotNoDAD != test.wantNoDAD {
				t.Fatalf(
					"IFA_F_NODAD set = %t, want %t",
					gotNoDAD,
					test.wantNoDAD,
				)
			}
		})
	}
}

func TestPlanTunAddrReconciliationPreservesUnchangedAddresses(t *testing.T) {
	current := []netlink.Addr{
		testTunAddr(t, "192.0.2.1/24", unix.IFA_F_PERMANENT),
		testTunAddr(
			t,
			"fd00::1/64",
			unix.IFA_F_PERMANENT|unix.IFA_F_NODAD,
		),
	}
	desired := []netip.Prefix{
		netip.MustParsePrefix("fd00:0::1/64"),
		netip.MustParsePrefix("192.0.2.1/24"),
		netip.MustParsePrefix("fd00::1/64"),
	}

	changes, err := planTunAddrReconciliation(current, desired)
	if err != nil {
		t.Fatalf("planTunAddrReconciliation error = %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("changes = %v, want none", tunAddrChangeDescriptions(changes))
	}
}

func TestPlanTunAddrReconciliationAddsBeforeDeleting(t *testing.T) {
	current := []netlink.Addr{
		testTunAddr(t, "192.0.2.1/24", unix.IFA_F_PERMANENT),
	}
	desired := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.1/24"),
	}

	changes, err := planTunAddrReconciliation(current, desired)
	if err != nil {
		t.Fatalf("planTunAddrReconciliation error = %v", err)
	}
	want := []string{
		"replace 198.51.100.1/24",
		"delete 192.0.2.1/24",
	}
	if got := tunAddrChangeDescriptions(changes); !slices.Equal(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}
}

func TestPlanTunAddrReconciliationAdoptsReadyIPv6Address(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00::1/64")
	current := []netlink.Addr{
		testTunAddr(t, prefix.String(), unix.IFA_F_PERMANENT),
	}

	changes, err := planTunAddrReconciliation(
		current,
		[]netip.Prefix{prefix},
	)
	if err != nil {
		t.Fatalf("planTunAddrReconciliation error = %v", err)
	}
	want := []string{"replace fd00::1/64"}
	if got := tunAddrChangeDescriptions(changes); !slices.Equal(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}
	if changes[0].addr.Flags&unix.IFA_F_NODAD == 0 {
		t.Fatal("replacement does not have IFA_F_NODAD")
	}
}

func TestPlanTunAddrReconciliationRepairsUnusableIPv6Address(t *testing.T) {
	tests := []struct {
		name  string
		flags int
	}{
		{name: "tentative", flags: unix.IFA_F_TENTATIVE},
		{name: "DAD failed", flags: unix.IFA_F_DADFAILED},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix("fd00::1/64")
			current := []netlink.Addr{
				testTunAddr(
					t,
					prefix.String(),
					unix.IFA_F_PERMANENT|test.flags,
				),
			}

			changes, err := planTunAddrReconciliation(
				current,
				[]netip.Prefix{prefix},
			)
			if err != nil {
				t.Fatalf("planTunAddrReconciliation error = %v", err)
			}
			want := []string{
				"delete fd00::1/64",
				"replace fd00::1/64",
			}
			if got := tunAddrChangeDescriptions(changes); !slices.Equal(
				got,
				want,
			) {
				t.Fatalf("changes = %v, want %v", got, want)
			}
			if changes[1].addr.Flags&unix.IFA_F_NODAD == 0 {
				t.Fatal("replacement does not have IFA_F_NODAD")
			}
		})
	}
}

func TestPlanTunAddrReconciliationDeletesPrefixConflictFirst(t *testing.T) {
	current := []netlink.Addr{
		testTunAddr(t, "fd00::1/64", unix.IFA_F_PERMANENT),
	}
	desired := []netip.Prefix{netip.MustParsePrefix("fd00::1/128")}

	changes, err := planTunAddrReconciliation(current, desired)
	if err != nil {
		t.Fatalf("planTunAddrReconciliation error = %v", err)
	}
	want := []string{
		"delete fd00::1/64",
		"replace fd00::1/128",
	}
	if got := tunAddrChangeDescriptions(changes); !slices.Equal(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}
}

func TestPlanTunAddrAdditionEnforcesIPv6Readiness(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00::1/64")
	tests := []struct {
		name    string
		current netlink.Addr
		want    []string
	}{
		{
			name: "managed and ready",
			current: testTunAddr(
				t,
				prefix.String(),
				unix.IFA_F_PERMANENT|unix.IFA_F_NODAD,
			),
		},
		{
			name:    "ready without NODAD",
			current: testTunAddr(t, prefix.String(), unix.IFA_F_PERMANENT),
			want:    []string{"replace fd00::1/64"},
		},
		{
			name: "tentative",
			current: testTunAddr(
				t,
				prefix.String(),
				unix.IFA_F_PERMANENT|unix.IFA_F_TENTATIVE,
			),
			want: []string{"delete fd00::1/64", "replace fd00::1/64"},
		},
		{
			name: "different prefix length",
			current: testTunAddr(
				t,
				"fd00::1/128",
				unix.IFA_F_PERMANENT|unix.IFA_F_NODAD,
			),
			want: []string{"delete fd00::1/128", "replace fd00::1/64"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changes, err := planTunAddrAddition(
				[]netlink.Addr{test.current},
				prefix,
			)
			if err != nil {
				t.Fatalf("planTunAddrAddition error = %v", err)
			}
			if got := tunAddrChangeDescriptions(changes); !slices.Equal(
				got,
				test.want,
			) {
				t.Fatalf("changes = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSetTunAddrPrefixesRejectsPrefixConflictBeforeNetlink(t *testing.T) {
	adapter := &memoryTunAddrNetlink{}
	err := setTunAddrPrefixes(
		adapter,
		nil,
		[]netip.Prefix{
			netip.MustParsePrefix("fd00::1/64"),
			netip.MustParsePrefix("fd00::1/128"),
		},
	)
	if err == nil {
		t.Fatal("setTunAddrPrefixes error = nil")
	}
	if adapter.listCalls != 0 || len(adapter.operations) != 0 {
		t.Fatalf(
			"netlink calls = list:%d operations:%v, want none",
			adapter.listCalls,
			adapter.operations,
		)
	}
}

func TestSetTunAddrPrefixesReconcilesAndIsIdempotent(t *testing.T) {
	desired := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/24"),
		netip.MustParsePrefix("198.51.100.1/24"),
		netip.MustParsePrefix("fd00::1/64"),
		netip.MustParsePrefix("fd00::2/64"),
	}
	adapter := &memoryTunAddrNetlink{addrs: []netlink.Addr{
		testTunAddr(t, "192.0.2.1/24", unix.IFA_F_PERMANENT),
		testTunAddr(t, "203.0.113.1/24", unix.IFA_F_PERMANENT),
		testTunAddr(
			t,
			"fd00::1/64",
			unix.IFA_F_PERMANENT|unix.IFA_F_NODAD,
		),
		testTunAddr(
			t,
			"fd00::2/64",
			unix.IFA_F_PERMANENT|unix.IFA_F_TENTATIVE,
		),
	}}

	if err := setTunAddrPrefixes(adapter, nil, desired); err != nil {
		t.Fatalf("first setTunAddrPrefixes error = %v", err)
	}
	wantOperations := []string{
		"replace 198.51.100.1/24",
		"delete fd00::2/64",
		"replace fd00::2/64",
		"delete 203.0.113.1/24",
	}
	if !slices.Equal(adapter.operations, wantOperations) {
		t.Fatalf(
			"first operations = %v, want %v",
			adapter.operations,
			wantOperations,
		)
	}
	adapter.operations = nil

	if err := setTunAddrPrefixes(adapter, nil, desired); err != nil {
		t.Fatalf("second setTunAddrPrefixes error = %v", err)
	}
	if len(adapter.operations) != 0 {
		t.Fatalf("second operations = %v, want none", adapter.operations)
	}
}

func TestVerifyTunAddrPrefixesRejectsUnreadyIPv6(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00::1/64")
	tests := []struct {
		name    string
		flags   int
		wantErr string
	}{
		{name: "no NODAD", flags: unix.IFA_F_PERMANENT, wantErr: "NODAD"},
		{
			name: "tentative",
			flags: unix.IFA_F_PERMANENT |
				unix.IFA_F_NODAD |
				unix.IFA_F_TENTATIVE,
			wantErr: "unusable flags",
		},
		{
			name: "DAD failed",
			flags: unix.IFA_F_PERMANENT |
				unix.IFA_F_NODAD |
				unix.IFA_F_DADFAILED,
			wantErr: "unusable flags",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := &memoryTunAddrNetlink{addrs: []netlink.Addr{
				testTunAddr(t, prefix.String(), test.flags),
			}}
			err := verifyTunAddrPrefixes(adapter, nil, []netip.Prefix{prefix})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"verifyTunAddrPrefixes error = %v, want text %q",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func TestApplyTunAddrChangesAddsOperationContext(t *testing.T) {
	wantErr := errors.New("injected replacement failure")
	adapter := &memoryTunAddrNetlink{replaceErr: wantErr}
	change, err := replaceTunAddrChange(netip.MustParsePrefix("fd00::1/64"))
	if err != nil {
		t.Fatal(err)
	}
	err = applyTunAddrChanges(adapter, nil, []tunAddrChange{change})
	if !errors.Is(err, wantErr) ||
		!strings.Contains(err.Error(), "replace address fd00::1/64") {
		t.Fatalf("applyTunAddrChanges error = %v", err)
	}
}

type memoryTunAddrNetlink struct {
	addrs      []netlink.Addr
	operations []string
	listCalls  int
	replaceErr error
}

func (a *memoryTunAddrNetlink) List(netlink.Link) ([]netlink.Addr, error) {
	a.listCalls++
	return append([]netlink.Addr(nil), a.addrs...), nil
}

func (a *memoryTunAddrNetlink) Replace(
	_ netlink.Link,
	addr *netlink.Addr,
) error {
	prefix, ok := tunAddrPrefix(*addr)
	if !ok {
		return errors.New("replacement address has no prefix")
	}
	a.operations = append(a.operations, "replace "+prefix.String())
	if a.replaceErr != nil {
		return a.replaceErr
	}
	for i := range a.addrs {
		currentPrefix, currentOK := tunAddrPrefix(a.addrs[i])
		if !currentOK {
			continue
		}
		matches := currentPrefix == prefix
		if prefix.Addr().Is6() {
			matches = currentPrefix.Addr() == prefix.Addr()
		}
		if !matches {
			continue
		}
		stateFlags := a.addrs[i].Flags & unusableIPv6AddrFlags
		a.addrs[i].Flags = addr.Flags | unix.IFA_F_PERMANENT | stateFlags
		return nil
	}
	added := *addr
	added.Flags |= unix.IFA_F_PERMANENT
	a.addrs = append(a.addrs, added)
	return nil
}

func (a *memoryTunAddrNetlink) Delete(
	_ netlink.Link,
	addr *netlink.Addr,
) error {
	prefix, ok := tunAddrPrefix(*addr)
	if !ok {
		return errors.New("deleted address has no prefix")
	}
	a.operations = append(a.operations, "delete "+prefix.String())
	for i := range a.addrs {
		currentPrefix, currentOK := tunAddrPrefix(a.addrs[i])
		if currentOK && currentPrefix == prefix {
			a.addrs = slices.Delete(a.addrs, i, i+1)
			break
		}
	}
	return nil
}

func testTunAddr(t *testing.T, value string, flags int) netlink.Addr {
	t.Helper()
	ipNet, err := ipNetFromPrefix(netip.MustParsePrefix(value))
	if err != nil {
		t.Fatal(err)
	}
	return netlink.Addr{IPNet: ipNet, Flags: flags}
}

func tunAddrChangeDescriptions(changes []tunAddrChange) []string {
	descriptions := make([]string, 0, len(changes))
	for _, change := range changes {
		operation := "replace"
		if change.kind == tunAddrDelete {
			operation = "delete"
		}
		descriptions = append(
			descriptions,
			operation+" "+change.prefix.String(),
		)
	}
	return descriptions
}
