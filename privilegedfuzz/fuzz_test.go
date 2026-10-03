//go:build linux

package privilegedfuzz_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/asciimoth/sysnet-linux/connmark"
	"github.com/asciimoth/sysnet-linux/routing"
	linuxtun "github.com/asciimoth/sysnet-linux/tun"
	"github.com/vishvananda/netlink"
)

func FuzzUntrustedInput(f *testing.F) {
	f.Add([]byte("kernel-state-sequence"))
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Fuzz(func(t *testing.T, input []byte) {
		if os.Getenv("SYSNET_PRIVILEGED_FUZZ_CONTAINER") != "1" {
			t.Skip("privileged fuzzing runs only in its isolated container")
		}
		if len(input) > 4<<10 {
			input = input[:4<<10]
		}
		fuzzKernelState(t, input)
	})
}

func fuzzKernelState(t *testing.T, input []byte) {
	t.Helper()
	octet := byte(1)
	if len(input) != 0 {
		octet = input[0]
	}
	tunnel, err := linuxtun.CreateDefaultTUN("szf", 1280+int(octet)%221)
	if err != nil {
		t.Fatalf("create isolated TUN: %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	name, err := tunnel.Name()
	if err != nil {
		t.Fatalf("get TUN name: %v", err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("lookup TUN link: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring TUN up: %v", err)
	}
	address := fmt.Sprintf("100.64.%d.2/32", octet)
	if err := linuxtun.SetTunAddrs(tunnel, []string{address}); err != nil {
		t.Fatalf("set TUN addresses: %v", err)
	}
	if err := linuxtun.SetTunRoutes(
		tunnel,
		[]string{"198.18.0.0/15"},
	); err != nil {
		t.Fatalf("set TUN routes: %v", err)
	}

	config := routing.DefaultConfig()
	config.TUNIndex = link.Attrs().Index
	config.VPNTable = 20010
	config.SafeTable = 20011
	config.PriorityBase = 12000
	config.UserMark = 0x4d000000 | uint32(octet)
	if config.UserMark == config.AppBypassMark {
		config.UserMark ^= 1
	}
	config.Families = routing.FamilySet{IPv4: true}
	config.TunnelFamilies = config.Families
	manager, err := routing.NewManager()
	if err != nil {
		t.Fatalf("create routing manager: %v", err)
	}
	defer func() { _ = manager.Close() }()
	defer func() { _ = manager.Rollback(config) }()

	marks := connmark.Config{Marks: []connmark.Mark{
		{Value: config.AppBypassMark, Mask: config.AppBypassMask},
		{Value: config.UserMark, Mask: config.UserMarkMask},
	}}
	markManager := connmark.NewManager()
	defer func() { _ = markManager.Close() }()
	defer func() { _ = markManager.Rollback() }()

	if err := manager.Apply(config); err != nil {
		t.Fatalf("apply routing state: %v", err)
	}
	if err := markManager.Apply(marks); err != nil {
		t.Fatalf("apply connmark state: %v", err)
	}
	for _, operation := range input[:min(len(input), 32)] {
		switch operation % 8 {
		case 0:
			_ = manager.Refresh()
		case 1:
			_, _ = manager.Status()
		case 2:
			_ = manager.Rollback(config)
		case 3:
			_ = manager.Apply(config)
		case 4:
			_ = markManager.Rollback()
		case 5:
			_ = markManager.Apply(marks)
		case 6:
			_ = linuxtun.AddTunAddr(
				tunnel,
				fmt.Sprintf("100.65.%d.2/32", operation),
			)
		case 7:
			_, _ = linuxtun.GetTunRoutes(tunnel)
		}
	}
}
