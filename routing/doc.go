//go:build linux

// Package routing owns Linux policy routing for sending selected traffic
// through an already-created VPN TUN interface.
//
// The package never installs VPN defaults into the system main table. Instead
// it compiles desired routes into package-owned VPN and safe-bypass tables, and
// reconciles only policy rules inside the caller-provided priority block. This
// keeps rollback narrow: all package-owned rules can be removed by priority and
// all package-owned tables can be flushed without touching host routing state.
package routing
