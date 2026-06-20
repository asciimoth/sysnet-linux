# gonnect/sysnet.System Implementation Plan

## Goal

Implement the root `github.com/asciimoth/sysnet-linux` package as a Linux
implementation of `github.com/asciimoth/gonnect/sysnet.System`.

The root package should compose the existing low-level packages in this repo:

- `dns`: host DNS integration and upstream forwarding.
- `subnet`: system-aware IP/subnet allocation.
- `tun`: TUN creation and interface address/route configuration.
- `routing`: policy routing for DefaultTun and app/user fwmarks.
- `killswitch`: temporary killswitch allow rules.

It should also integrate external Linux process/socket helpers:

- `github.com/asciimoth/p-mark`: process tracking and mark propagation.
- `github.com/asciimoth/p-mark/fwmark`: applying pmark values as socket
  `SO_MARK`.
- `github.com/asciimoth/p-mark/multirule`: userspace process rule tracking to use for Matcher rules.
- `github.com/asciimoth/gonnect/sockowner`: socket owner lookup.
- `github.com/asciimoth/gonnect/sockopt`: setting `SO_MARK` on sockets opened
  by OutNet and LocalNet.

## Existing Contracts

The target interface is `gonnect/sysnet.System`.

Important contract points:

- `Features()` and `ListRules()` must reflect what is both configured and
  possible with the components supplied to `System`.
- `OutNet()` must bypass any DefaultTun built by the same `System`.
- `LocalNet()` should be suitable for local listeners and should also bypass
  DefaultTun.
- `OutDNS()` should resolve over OutNet.
- `BuildMatcher(rule)` returns a `sysnet.Matcher` backed by
  `gonnect/sockowner` and `p-mark/multirule`.
- `BuildDefaultTun(opts)` may be called multiple times. Only the latest
  DefaultTun should remain actual.
- `DefaultTun.SetDns(nil)` means the local DNS server should drop/fail incoming
  DNS requests.
- Tun mutation methods should reject TUNs not built by this `System` with
  `sysnet.ErrUnknownTun`.

## Marks

There are two independent Linux fwmarks:

1. App bypass mark.
   Used for sysnet-owned traffic: OutNet and LocalNet sockets. This mark is
   written directly with `SO_MARK` in `gonnect.NativeConfig.Control`,
   `ControlContext`, and listener controls such as
   `NativeConfig.ListenCfg.Control` when available, via
   `gonnect/sockopt.SetRoutingMark`. `routing.Config` uses it as
   `AppBypassMark`.

2. User/process mark.
   Used for traffic owned by processes selected by DefaultTun Exclude/Include
   rules. This mark is emitted through `p-mark` as a 64-bit process mark and
   translated to a socket fwmark by `p-mark/fwmark`. `routing.Config` uses the
   resulting 32-bit value as `UserMark`.

The marks must not overlap under their masks. Reuse `routing.ValidateConfig` to
catch invalid combinations before applying routing.

Recommended defaults:

- App bypass mark: `routing.DefaultAppBypassMark`.
- App bypass mask: `routing.DefaultMarkMask`.
- User mark: constructor config should require or default a non-overlapping
  mark, for example `0x4d000001`.
- User mark mask: `routing.DefaultMarkMask`.
- Pmark priority: constructor config should expose this as a System field and
  default it to `0`.

## Rule Types

Both TunRules and MatcherRules should report these rule types when supported:

| Type | Description |
| --- | --- |
| `comm` | Process' command regexp matcher. |
| `exec` | Process' executable path matcher. |
| `cmd` | Process' command line regexp matcher. |
| `pid` | Process' PID. |
| `user` | Name of user owning process. |
| `uid` | UID owning process. |
| `group` | Name of group owning process. |
| `gid` | GID owning process. |

Rule value contract:

- `comm` and `cmd` values are regular expressions.
- `exec` values are exact executable paths or absolute path templates, for
  example `/usr/bin/*`.
  - A value without a slash is a basename-style suffix match: `bash` matches
    any executable path ending with `bash`.
  - Relative paths such as `./whatever` are invalid.
- `pid`, `uid`, and `gid` values are either a single decimal number or a
  space-separated list of decimal numbers.

`user` and `group` rules should be resolved at rule-add/verify time to numeric
UID/GID and then use UID/GID matching internally.

The two contexts share the user-facing contract but have different mechanics:

- TunRules run in the pmark checker path against `pmark.ProcessInfo`.
- MatcherRules run in matcher implementations against `sockowner.SocketOwner`.

TunRules require the pmark integration to be available and enabled. MatcherRules
require sockowner lookup to be enabled. Since `gonnect/sockowner` is a normal
library dependency, matcher support can be enabled independently from pmark.

## System Shape

Root package should expose a `System` struct implementing `sysnet.System`.

Planned fields:

- `mu sync.Mutex`: protects lifecycle and active DefaultTun state.
- `closed bool`.
- `features SystemFeaturesConfig`: booleans requested by caller.
- `allocator *subnet.CombinedAllocator`: shared allocator for `AllocIP`,
  `AllocSubnet`, and DefaultTun fallback address reservation.
- `defaultTunIP net.IP`: lazily or eagerly reserved address used when
  `DefaultTunOpts.TunAddrs` is empty or does not provide a usable DNS address.
- `outNet gonnect.Network`.
- `localNet gonnect.Network`.
- `outDNS sysdns.DNSProvider` or `gdns.Interface`.
- `dnsProvider sysdns.DNSProvider`: provider used by DefaultTun `SetDns`.
- `routingManager RoutingManager`.
- `pmark PmarkController`.
- `killswitch KillswitchClient`.
- `appBypassMark uint32`.
- `appBypassMask uint32`.
- `userMark uint32`.
- `userMarkMask uint32`.
- `pmarkPriority int`.
- `killswitchAllowExclude bool`.
- `logf func(format string, args ...any)`.
- `callbacks Callbacks`.
- `tuns map[gtun.Tun]*tunState`: owned regular TUNs.
- `defaultTun *defaultTunState`: active DefaultTun wrapper/state.

The actual field names can be adjusted during implementation, but the ownership
boundaries should stay clear:

- System owns networks it constructs.
- System owns regular TUN bookkeeping.
- System owns the active DefaultTun and all DefaultTun side effects.
- Optional external components may be supplied by constructor interfaces and
  closed only if the constructor contract says System owns them.

## Constructor

For the first implementation, constructor accepts ready components or narrow
interfaces. It should not discover/build every dependency under the hood yet.

Suggested public constructor:

```go
type Config struct {
    Features FeatureConfig
    Allocator *subnet.CombinedAllocator

    DNSProvider dns.DNSProvider
    RoutingManager RoutingManager
    Pmark PmarkController
    Killswitch KillswitchClient

    AppBypassMark uint32
    AppBypassMask uint32
    UserMark uint32
    UserMarkMask uint32
    PmarkPriority int

    KillswitchAllowExclude bool
    Logf func(format string, args ...any)
    Callbacks Callbacks
}

func NewSystem(config Config) (*System, error)
```

The allocator field should be required or defaulted to
`subnet.NewDefaultAllocator`. This same `CombinedAllocator` serves:

- `System.AllocIP()`.
- `System.AllocSubnet()`.
- the one-time reserved DefaultTun fallback IP.

For tests, keep external dependencies as interfaces:

- `RoutingManager`: `Apply`, `Refresh`, `Rollback`, `Status`, `Close`.
- `PmarkController`: install/update checker, force traversal, register rule
  callbacks as needed.
- `KillswitchClient`: create/update/delete temporary rulesets.
- `TUNFactory`: create native TUN by base name and MTU.
- `DNSProvider`: already exists in `./dns`.

## Feature Config And Dynamic Degradation

`FeatureConfig` should represent caller intent:

```go
type FeatureConfig struct {
    Tun bool
    DefaultTun bool
    DynTun bool
    DynDefaultTun bool
    TunNames bool
    DefaultTunNames bool
    StrictMode bool
    TunRules bool
    MatcherRules bool
    DNSControl bool
    Routing bool
    Pmark bool
    Killswitch bool
}
```

Effective support is `enabled && possible`.

Examples:

- `Features().Tun` requires feature enabled and a TUN factory/configurator.
- `Features().DefaultTun` requires Tun support plus DNS server support and
  enough routing/DNS pieces for the selected mode.
- `Features().DynDefaultTun` requires an active reusable DefaultTun design,
  routing manager, tun configurator, and DNS server attach/detach.
- `Features().StrictMode` requires routing support.
- TunRules require feature enabled, pmark controller present, pmark fwmark
  plumbing present, and user mark configured.
- MatcherRules require feature enabled and sockowner support enabled.

When a feature is unsupported:

- Report it as false in `Features()` or omit rules from `ListRules()`.
- Return `sysnet.ErrNotSupported` from build/mutation methods that require it.
- Keep OutNet, LocalNet, OutDNS, and allocation functional whenever possible.

## OutNet, LocalNet, And OutDNS

OutNet and LocalNet should be `gonnect.NativeNetwork` instances configured to
set the app bypass fwmark on every socket they create.

Build order:

1. Create app-marked `NativeNetwork`.
2. Build a system DNS provider suitable for the current host, passing that
   NativeNetwork as the dial network so upstream DNS bypasses DefaultTun.
3. Build a `gonnect/dns.Resolver` from `DNSProvider.Requests()`.
4. Call `NativeNetwork.SetResolver(resolver)`.

This does not loop because the DNS provider must forward `Requests()` to its
original upstreams, never to the DNS server installed by `SetDNS`.

Implementation detail:

- Use `NativeConfig.Control` and `ControlContext` to call
  `sockopt.SetRoutingMark` on the raw socket.
- Also set the same app bypass mark from `NativeConfig.ListenCfg.Control` for
  listener sockets when the `gonnect.NativeNetwork`/Go listen path supports it.
- If setting the mark on socket fails due to privileges, log it and continue with unmarked socket.

`OutDNS()` returns the provider/interface used by OutNet's resolver.

## Allocator And DefaultTun DNS IP Reservation

`System` should hold one `*subnet.CombinedAllocator`.

At construction allocate one IP address from this allocator for DefaultTun fallback usage:

- Prefer IPv4 if available, because the DNS server can bind a plain IPv4 TUN
  address and many host DNS stacks handle IPv4 DNS more predictably.
- Store the chosen IP and prefix returned by AllocIP4() in `System` fields.
- Do not free it between DefaultTun rebuilds; it is a System-lifetime
  reservation.

BuildDefaultTun address normalization:

1. Filter out loopback addresses from `opts.TunAddrs`.
2. Add `defaultTunIP` to `opts.TunAddrs` with a stored host prefix
3. If `opts.DnsIP` is provided and belongs to the normalized TUN address set,
   use it.
4. Otherwise choose `defaultTunIP`.

The local DNS server must listen on the selected DefaultTun-owned address, not
on loopback.

## DefaultTun Build

Initial build sequence:

1. Verify options:
   - Exclude and Include are mutually exclusive.
   - rules are valid and supported.
   - addresses/routes parse and loopback entries are ignored.
   - Strict requires `Features().StrictMode`.
2. Create TUN via `tun.CreateDefaultTUN(base, mtu)`.
3. Bring/configure TUN as needed.
4. Normalize/add TUN addresses, including the reserved DNS IP.
5. Start a UDP DNS server on the selected TUN-owned DNS IP at port 53.
   - Use `gonnect/dns.NewServer`.
   - Start detached/no-op, so incoming requests fail with server failure until
     `DefaultTun.SetDns(resolver)` is called.
6. Set TUN addresses and routes via `./tun`.
7. Compile process rules for pmark checker.
8. Install/update pmark checker:
   - Exclude mode marks matching processes with user mark.
   - Include mode marks matching processes with user mark.
   - The routing mode determines whether that mark means bypass or include.
9. Apply routing:
   - `routing.Config.TUNIndex` from the created TUN.
   - `ModeExclude` if `opts.Exclude` is set or both lists are empty.
   - `ModeInclude` if `opts.Include` is set.
   - `Strict` or `NonStrict` from `opts.Strict`.
   - app and user marks from System config.
10. Configure DNS provider with the local DNS IP so system DNS points at the
    DefaultTun DNS server.
11. Add/update killswitch temporary allow rules if killswitch is enabled.
12. Wrap native TUN and DNS/routing side effects in a DefaultTun object.

## DefaultTun Rebuild

If `BuildDefaultTun` is called while a previous DefaultTun is still alive:

- Do not create a new TUN.
- Reset local DNS server to no-op using `server.Detach()` or
  `DefaultTun.SetDns(nil)`.
- Re-normalize addresses and ensure the reserved fallback DNS IP is still
  present if needed.
- Re-apply TUN MTU, addresses, and routes.
- Rebuild and install pmark checker for the new Exclude/Include rules.
- Set DefaultTun DNS resolver back to no-op until caller invokes `SetDns`.
- Switch routing mode/strictness if changed.
- Update killswitch temporary rules.
- Return a new wrapper around the same underlying TUN state, or return the same
  wrapper after updating its option snapshot. The important external guarantee
  is that older wrappers no longer control the active DNS/routing policy.

Rollback ordering should be fail-closed where practical:

- Detach DNS upstream before changing routes/rules.
- Apply routing transition guard is already handled inside `routing.Manager`.
- If rebuild fails after partial mutation, either restore previous known-good
  state or close/rollback the active DefaultTun and report the error.

## DefaultTun SetDns

The DefaultTun wrapper should hold a pointer/reference to its DNS server.

- `SetDns(nil)` detaches the upstream.
- `SetDns(resolver)` attaches the provided `gdns.Interface`.
- On close, detach upstream, close DNS server/listener, unset provider DNS,
  rollback routing, remove killswitch temporary rules, unregister pmark rules,
  and close the TUN only when the System/defaultTun lifecycle says it should.

`DefaultTun.SetDns` should not call the host `DNSProvider.SetDNS`; that is
System's job during DefaultTun construction/rebuild because the DNS provider is
part of host DNS configuration, not the packet-serving upstream selection.

## Pmark Integration

For TunRules, implement rule matching in the pmark checker path.

Recommended structure:

- `ruleCompiler` converts `sysnet.Rule` either to registered
  `multirule.Tracker` rule IDs for `comm`/`exec`/`cmd`/`pid`, or to a
  `func(pmark.ProcessInfo) bool` for rules that still need checker-side
  evaluation.
- `pmarkController` owns:
  - `*pmark.Daemon`.
  - optional `*fwmark.Manager`.
  - optional `*multirule.Tracker`.
  - currently registered DefaultTun rule IDs.

Rule implementations:

- `comm`, `exec`, `cmd`, `pid`, `uid`, and `gid` values must be parsed and
  validated according to the shared Rule Types contract above before
  registration or checker-side matching.
- `comm`, `exec`, `cmd`, and `pid`: register and update
  `p-mark/multirule.Tracker` rules, then match by rule IDs associated with the
  process PID rather than duplicating this matching in the checker.
- `user`: resolve once with `os/user.Lookup`, parse UID, then UID rule.
- `uid`: process UID lookup. `pmark.ProcessInfo` does not include UID today,
  so implementation needs a procfs enrichment helper or a pmark upstream change.
- `group`: resolve once with `os/user.LookupGroup`, parse GID, then GID rule.
- `gid`: process GID lookup, likewise requiring procfs enrichment.

Pmark `ProcessInfo` currently exposes PID, PPID, comm, cmdline, and
exe but not UID/GID. So the implementation must read `/proc/<pid>/status`.

The checker should return:

- priority: `System.pmarkPriority`, defaulting to `0`.
- mark: `fwmark.ToMark(System.userMark)`.
- ok: true when any active rule matches.

When rules change:

- call `Daemon.SetChecker(newChecker)`.
- call `Daemon.ForceProcessTraversal()` if needed by the selected controller.
- make sure `fwmark.Manager.ProcessUpdateCallback()` remains installed so
  already-open sockets are reconciled.

## Matcher Implementation

`BuildMatcher(rule)` returns a matcher that resolves a flow owner with
`sockowner.GetSockOwner(flow)`, reads the owner PIDs, and asks
`multirule.Tracker.RuleIDsByPID(pid)` whether any registered rule for this
matcher applies.

Rule implementations:

- `comm`, `exec`, `cmd`, `pid`, `uid`, and `gid` values must be parsed and
  validated according to the shared Rule Types contract above before
  registration or direct owner matching.
- `comm`, `exec`, `cmd`, and `pid`: register as `multirule.Tracker` rules. The
  matcher should use `sockowner` only to discover candidate PIDs, then check
  those PIDs through `RuleIDsByPID`.
- `user`/`uid`: match `SocketOwner.UID`.
- `group`/`gid`: match `SocketOwner.GID`.

Matcher lifecycle is simple:

- A matcher owns its registered `multirule.Tracker` rule IDs and removes them
  on close.
- `Close()` marks it closed.
- `Match` after close should return false or a closed error consistently.

## Routing Integration

Use `routing.Manager` as the only owner of DefaultTun policy routing.

Config mapping:

- `TUNIndex`: from the active TUN link.
- `VPNTable`, `SafeTable`, `PriorityBase`, `PrioritySpan`: constructor config
  or routing defaults.
- `AppBypassMark`, `AppBypassMask`: System app mark.
- `UserMark`, `UserMarkMask`: pmark/fwmark process mark.
- `Mode`: `ModeExclude` or `ModeInclude`.
- `Strictness`: `Strict` if `opts.Strict`, else `NonStrict`.
- `Families`: inferred from enabled TUN addresses/routes or config default.

Apply on build/rebuild. Refresh can be exposed internally for network-change
callbacks later.

Close should call `Rollback(config)` with the last applied config.

## Killswitch Integration

If killswitch client is present and feature is enabled, System should maintain a
temporary ruleset allowing:

- app bypass mark for OutNet and LocalNet.
- user/process mark when `KillswitchAllowExclude` is true and DefaultTun is in
  Exclude mode.

Rules use `killswitch.AllowRules.AllowedMarks`, formatted as hexadecimal
strings.

Lifecycle:

- Create a temp ruleset on first need.
- Update it on DefaultTun build/rebuild or option changes.
- Delete it on DefaultTun close or System close.

If killswitch is configured as optional, failures should be logged and should
not necessarily disable OutNet/LocalNet. If configured as required, failures
should make DefaultTun build fail.

## Regular Tun Support

`BuildTun(opts)` should:

- require `Features().Tun`.
- create a TUN via the configured factory.
- apply MTU, addresses, and routes using `./tun`.
- record ownership in `System.tuns`.

Mutation methods should:

- check System ownership first.
- reject DefaultTun in `SetTunName`.
- call existing `./tun` helpers.
- return `sysnet.ErrUnknownTun` for unknown TUNs.

`TunNameVerify` should validate Linux interface name constraints and check
availability. Existing `tun.CreateDefaultTUN` generates names, but name support
is currently limited because `sysnet.SetTunName` has no name argument.

## Callbacks

Provide a callback struct with nil-safe function fields, for example:

```go
type Callbacks struct {
    TunCreated func(tun gtun.Tun)
    TunConfigured func(tun gtun.Tun, opts sysnet.TunOpts)
    DefaultTunCreated func(tun sysnet.DefaultTun)
    DefaultTunConfigured func(tun sysnet.DefaultTun, opts sysnet.DefaultTunOpts)
    DefaultTunClosed func()
    RoutingApplied func(config routing.Config)
    DNSConfigured func(server netip.Addr)
    KillswitchUpdated func(rules killswitch.AllowRules)
}
```

Callbacks should never be required. Invoke them after the relevant operation
succeeds, outside internal locks when possible.

## Logging

Every component wrapper should use `System.logf`.

Rules:

- Nil `Logf` becomes no-op.
- Log recoverable degradation and external component failures.
- Do not log high-volume packet or DNS request events.

## Close Semantics

`System.Close()` should be idempotent and should:

1. Mark System closed.
2. Close active DefaultTun state:
   - detach DNS upstream.
   - close DNS server/listener.
   - `DNSProvider.UnsetDNS()`.
   - routing rollback.
   - killswitch temp ruleset delete.
   - pmark checker reset/unregister.
   - close TUN.
3. Close regular TUNs built by the System.
4. Close owned networks/providers/controllers
5. Keep the allocator object alive but no longer usable through closed System

## Tests

Unit tests should avoid requiring root by using interfaces and fakes.

Recommended test areas:

- Feature matrix:
  - missing TUN factory disables Tun/DefaultTun.
  - missing pmark disables TunRules but not MatcherRules.
  - missing routing disables DefaultTun/StrictMode.
- Rule compilation:
  - regexp validation for `comm` and `cmd`.
  - `exec` exact path, path template, basename suffix, and relative path
    rejection.
  - pid/uid/gid single-number and space-separated list parsing.
  - user/group resolution with fake resolver.
  - `comm`/`exec`/`cmd`/`pid` registration through `multirule.Tracker`.
- Matcher:
  - owner PID lookup through `sockowner`.
  - `RuleIDsByPID` matching for `comm`/`exec`/`cmd`/`pid`.
  - close behavior.
- DefaultTun option normalization:
  - loopback addrs ignored.
  - empty `TunAddrs` adds reserved allocator IP.
  - provided `DnsIP` must belong to TUN addrs.
  - reserved IP reused across rebuilds.
- DefaultTun rebuild:
  - no new TUN created.
  - DNS server detached before reattach.
  - tun addrs/routes replaced.
  - routing config switched from exclude to include and strict to non-strict.
- Killswitch:
  - app mark always allowed when enabled.
  - user mark allowed only when `KillswitchAllowExclude` and Exclude mode.
- Ownership:
  - mutation rejects unknown TUN.
  - regular Tun and DefaultTun tracked separately.

Keep existing package tests for `dns`, `routing`, `subnet`, `tun`, and
`killswitch` as lower-level coverage.

## Implementation Phases

1. Define root package interfaces, `Config`, `FeatureConfig`, `Callbacks`, and
   `System` skeleton.
2. Implement allocator ownership and `AllocIP`/`AllocSubnet`.
3. Implement OutNet, LocalNet, OutDNS construction from supplied provider and
   app mark controls.
4. Implement regular TUN build/mutation/ownership.
5. Implement rule parsing/verification and matcher enrichment.
6. Implement pmark controller adapter and TunRules.
7. Implement DefaultTun state wrapper, DNS server binding on TUN-owned DNS IP,
   and SetDns attach/detach.
8. Integrate routing manager.
9. Integrate killswitch temp rulesets.
10. Add dynamic rebuild path and rollback behavior.
11. Add tests and root package documentation.
