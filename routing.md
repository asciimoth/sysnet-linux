# `./routing` Design Doc and Implementation Plan

## 1. Purpose

The `./routing` package owns Linux policy-routing setup for the VPN app.

It is responsible for:

* routing selected traffic through an already-created VPN TUN interface;
* bypassing the VPN for the VPN app’s own transport packets;
* supporting user-provided include/exclude `fwmark` behavior;
* supporting strict and non-strict behavior;
* allowing safe local/direct traffic in non-strict modes;
* switching between modes;
* rolling back all package-owned routing configuration.

It is not responsible for:

* creating or configuring the TUN interface;
* setting `fwmark` on application traffic;
* setting the VPN app’s socket mark;
* firewall or nftables setup;
* Docker/network-manager integration beyond route observation;
* modifying the system `main` routing table.

## 2. Core design principle

Do not install the VPN default route into the system `main` table.

Instead:

* `main` remains the system’s normal direct routing view.
* `VPN_TABLE` contains the VPN default route through the owned TUN interface.
* `SAFE_TABLE` contains only routes considered safe to bypass the VPN.
* package-owned policy rules decide which table is consulted.

This gives the package a simple rollback story: delete package-owned rules and flush package-owned tables.

## 3. Tables

### 3.1 `main`

The package treats `main` as:

> the network as if this VPN package did not exist.

The package must not add, replace, or delete routes in `main`.

Traffic sent to `main` is direct/bypass traffic. This includes normal physical default routes, lower-priority default routes, static routes, Docker bridge routes, Wi-Fi routes, and whatever the host would otherwise use.

### 3.2 `VPN_TABLE`

Owned by `./routing`.

Contains:

* IPv4 default route through the owned TUN interface, when IPv4 is enabled;
* IPv6 default route through the owned TUN interface, when IPv6 is enabled;
* optional future VPN-specific routes, if needed.

The table represents:

> wrap this traffic in my VPN.

If a packet is supposed to use the VPN but no VPN route is available, it must not fall through to `main`. The rule chain must fail closed with an unreachable rule.

### 3.3 `SAFE_TABLE`

Owned by `./routing`.

Contains a filtered copy of safe routes from `main`.

The package uses it only in non-strict modes.

A route is safe when:

* it is not a default route;
* it does not use the owned VPN interface;
* it is not a gatewayed route to public/global IP space.

A route is unsafe when:

* destination is IPv4 `0.0.0.0/0`;
* destination is IPv6 `::/0`;
* route has a gateway and destination is public/global IP space;
* route uses the owned VPN TUN interface.

Examples of normally safe routes:

* directly connected Wi-Fi/LAN prefixes;
* Docker bridge prefixes;
* Podman/CNI bridge prefixes;
* libvirt bridge prefixes;
* IPv6 link-local routes;
* private IPv4 routes;
* IPv6 ULA routes;
* specific public route without gateway, if the host is directly attached to that prefix.

Examples of unsafe routes:

* physical default route;
* cellular default route;
* public prefix via gateway;
* arbitrary internet route via physical router;
* route through this VPN’s TUN interface.

## 4. Rule model

The package owns a fixed priority range.

Example conceptual layout:

|       Priority area | Meaning                                            |
| ------------------: | -------------------------------------------------- |
| kernel priority `0` | keep kernel local table untouched                  |
|     app bypass area | VPN app transport bypass                           |
|    transition guard | temporary fail-closed guard during reconfiguration |
|      user mark area | include/exclude mark behavior                      |
|           safe area | non-strict safe bypass                             |
|            VPN area | VPN lookup and fail-closed guard                   |
|    strict drop area | final unreachable rule in strict modes             |

The exact numbers should be configurable, but the package should require a dedicated priority block.

Recommended constraint:

* the caller supplies `PriorityBase`;
* the package owns a contiguous range from `PriorityBase` to `PriorityBase + PrioritySpan`;
* the package deletes only rules in that owned range;
* the range must not overlap kernel built-ins or other known application ranges.

## 5. Public package shape

The package should expose one main object:

### `Manager`

Conceptual responsibilities:

* validate configuration;
* build desired route/rule state;
* apply desired state;
* switch modes;
* refresh safe routes;
* rollback package-owned state;
* close netlink resources.

The package should expose these conceptual operations:

| Operation      | Purpose                                                 |
| -------------- | ------------------------------------------------------- |
| create manager | initialize netlink adapter and package options          |
| apply config   | configure or switch to a desired routing mode           |
| refresh        | rebuild `SAFE_TABLE` from current `main` routes         |
| rollback       | remove all package-owned rules and flush owned tables   |
| inspect/status | return current desired/applied state for logs and tests |
| close          | close netlink handle resources                          |

Do not expose low-level netlink objects in the public API unless necessary. Keep vishvananda-specific details behind an internal adapter so tests can use a fake backend.

## 6. Configuration model

The main configuration should contain:

### Required

* VPN TUN interface index (gonnect/tun.Tun should be passed and index extracted from it).
* `VPN_TABLE` ID.
* `SAFE_TABLE` ID.
* owned priority range.
* VPN app bypass mark value.
* VPN app bypass mark mask.
* user mark value.
* user mark mask.
* mode: `exclude` or `include`.
* strictness: `strict` or `non-strict`.
* IP families: IPv4, IPv6, or both.

There should be suggested default values for numeric params provided via pkg-lvl public constants.
- for VPN app bypass mark value it is `0xeb9f0001`
- for VPN app bypass mark mask and user mark mask it is masks that match whole mark

Mode is exclude by default.

### Validation rules

Reject configuration when:

* table IDs are reserved or equal to `main`, `local`, `default`, or unspecified table IDs;
* `VPN_TABLE` equals `SAFE_TABLE`;
* priority range is too small;
* priority range overlaps kernel built-in rules;
* TUN interface does not exist;
* user mark and app bypass mark have ambiguous overlap;
* mark mask is zero;
* requested IP family is unsupported by the current TUN configuration.

The user mark and app bypass mark should be treated as separate namespaces. 
If their masks allow the same packet mark to match both, reject by default. 
The app bypass rule is intentionally higher priority, but ambiguous mark design is still dangerous and hard to debug.

## 7. Mode semantics

The kernel local table remains first and untouched in every mode. This preserves loopback and host-local addresses.

The app bypass mark is also common to every mode.

Common prefix:

| Match             | Action        |
| ----------------- | ------------- |
| `APP_BYPASS_MARK` | lookup `main` |
| `APP_BYPASS_MARK` | unreachable   |

The second rule is a fail-closed guard. If the VPN app’s own transport cannot route directly, it must not fall into the VPN path and loop.

## 8. Mode rule chains

### 8.1 Exclude + strict

Requirements:

* excluded traffic behaves as if this VPN does not exist;
* excluded traffic may use physical default routes and lower-priority direct defaults;
* non-excluded traffic must go through the VPN;
* non-excluded traffic must fail closed if VPN routing is unavailable;
* safe routes are not specially allowed.

Rule chain:

| Order | Match           | Action             |
| ----: | --------------- | ------------------ |
|     1 | app bypass mark | lookup `main`      |
|     2 | app bypass mark | unreachable        |
|     3 | user mark       | lookup `main`      |
|     4 | user mark       | unreachable        |
|     5 | all             | lookup `VPN_TABLE` |
|     6 | all             | unreachable        |

Behavior:

| Traffic                         | Result                     |
| ------------------------------- | -------------------------- |
| app transport                   | direct via `main`          |
| excluded marked traffic         | direct via `main`          |
| non-excluded internet traffic   | VPN                        |
| non-excluded LAN/Docker traffic | VPN or drop                |
| VPN unavailable                 | non-excluded traffic drops |

### 8.2 Exclude + non-strict

Requirements:

* excluded traffic behaves as if this VPN does not exist;
* non-excluded traffic goes VPN by default;
* non-excluded safe traffic may bypass the VPN;
* unsafe non-excluded traffic must not leak direct.

Rule chain:

| Order | Match           | Action              |
| ----: | --------------- | ------------------- |
|     1 | app bypass mark | lookup `main`       |
|     2 | app bypass mark | unreachable         |
|     3 | user mark       | lookup `main`       |
|     4 | user mark       | unreachable         |
|     5 | all             | lookup `SAFE_TABLE` |
|     6 | all             | lookup `VPN_TABLE`  |
|     7 | all             | unreachable         |

Behavior:

| Traffic                            | Result                            |
| ---------------------------------- | --------------------------------- |
| app transport                      | direct via `main`                 |
| excluded marked traffic            | direct via `main`                 |
| safe LAN/Docker/local-link traffic | direct via `SAFE_TABLE`           |
| ordinary internet traffic          | VPN                               |
| VPN unavailable                    | unsafe non-excluded traffic drops |

### 8.3 Include + strict

Requirements:

* default is drop;
* included traffic goes through VPN;
* loopback and host-local traffic survive via kernel local table;
* app transport bypass still works.

Rule chain:

| Order | Match           | Action             |
| ----: | --------------- | ------------------ |
|     1 | app bypass mark | lookup `main`      |
|     2 | app bypass mark | unreachable        |
|     3 | user mark       | lookup `VPN_TABLE` |
|     4 | user mark       | unreachable        |
|     5 | all             | unreachable        |

Behavior:

| Traffic                 | Result                        |
| ----------------------- | ----------------------------- |
| app transport           | direct via `main`             |
| included marked traffic | VPN                           |
| unmarked traffic        | dropped                       |
| loopback / host-local   | allowed by kernel local table |
| VPN unavailable         | included traffic drops        |

### 8.4 Include + non-strict

Requirements:

* unmarked traffic behaves as if this VPN does not exist;
* included traffic goes through VPN;
* included traffic may bypass VPN if it is safe;
* included unsafe traffic must not leak direct if VPN is unavailable.

Rule chain:

| Order | Match           | Action              |
| ----: | --------------- | ------------------- |
|     1 | app bypass mark | lookup `main`       |
|     2 | app bypass mark | unreachable         |
|     3 | all             | lookup `SAFE_TABLE` |
|     4 | user mark       | lookup `VPN_TABLE`  |
|     5 | user mark       | unreachable         |
|     6 | all             | lookup `main`       |

Behavior:

| Traffic                                             | Result                  |
| --------------------------------------------------- | ----------------------- |
| app transport                                       | direct via `main`       |
| safe traffic, marked or unmarked                    | direct via `SAFE_TABLE` |
| included marked internet traffic                    | VPN                     |
| included marked unsafe traffic when VPN unavailable | dropped                 |
| unmarked ordinary traffic                           | direct via `main`       |

The safe lookup must happen before the user-mark VPN rule in this mode, because the desired behavior is “included traffic goes to VPN except when it is safe.”

## 9. Route snapshot design

The package needs a route snapshot step before building `SAFE_TABLE`.

Conceptual flow:

1. list IPv4 routes from `main`;
2. list IPv6 routes from `main`;
3. remove routes using the owned VPN interface;
4. classify each remaining route as safe or unsafe;
5. copy safe routes into desired `SAFE_TABLE` route set;
6. create desired default route through TUN in `VPN_TABLE`.

Do not copy from `local`. The kernel local table remains first and should not be duplicated.

## 10. Safe route classifier

The classifier should be deterministic and separately unit-tested.

Inputs:

* route destination;
* route gateway;
* route link index;
* route family;
* route type;
* route nexthops, if multipath;
* owned VPN interface index.

Output:

* safe;
* unsafe;
* unsupported/ignore.

Recommended MVP rules:

| Condition                                          | Classification   |
| -------------------------------------------------- | ---------------- |
| route destination is default                       | unsafe           |
| route output interface is owned TUN                | unsafe           |
| route has gateway and destination is public/global | unsafe           |
| route is directly connected and non-default        | safe             |
| route destination is private IPv4                  | safe             |
| route destination is IPv6 ULA                      | safe             |
| route destination is IPv6 link-local               | safe             |
| route has gateway to private destination           | safe             |
| route has unsupported encapsulation or type        | ignore initially |

For multipath routes:

* classify as safe only if every nexthop is safe;
* if any nexthop is unsafe, exclude the whole route from `SAFE_TABLE`;
* if nexthop parsing is incomplete, ignore the route rather than accidentally allow it.

The classifier should not make DNS or interface-name assumptions. It should classify by route properties and IP prefix categories.

## 11. Netlink adapter layer

Create an internal adapter that wraps vishvananda/netlink.

The rest of the package should depend on an internal interface, not directly on the package-level netlink functions.

The adapter should provide conceptual operations for:

* link lookup by name or index;
* route list by family/table;
* route replace;
* route delete;
* rule list by family;
* rule add;
* rule delete;
* handle close.

Why:

* unit tests can use a fake adapter without root;
* integration tests can use the real adapter;
* retry/error behavior is centralized;
* equality/normalization for routes and rules is centralized.

## 12. Desired state compiler

The compiler is pure logic.

Inputs:

* validated configuration;
* TUN link index;
* route snapshot;
* selected mode;
* strictness;
* family selection.

Outputs:

* desired rules for IPv4;
* desired rules for IPv6;
* desired routes for `VPN_TABLE`;
* desired routes for `SAFE_TABLE`.

The compiler should not mutate system state.

This makes the most important logic testable without Linux privileges.

## 13. Applier design

The applier reconciles actual kernel state with desired state.

It should own only:

* rules in the configured priority range;
* routes in `VPN_TABLE`;
* routes in `SAFE_TABLE`.

It must never mutate:

* `main` routes;
* `local` routes;
* routes outside owned tables;
* rules outside owned priority range;
* TUN interface configuration.

### Apply flow

1. Validate configuration.
2. Resolve the TUN link.
3. Build route snapshot from `main`.
4. Compile desired state.
5. Install or refresh app-bypass rules.
6. Install temporary transition guard.
7. Flush owned route tables.
8. Install desired routes into `VPN_TABLE` and `SAFE_TABLE`.
9. Delete old mode rules in the owned priority range, excluding app-bypass and transition guard.
10. Install desired mode rules.
11. Remove transition guard.
12. Record in-memory applied state for diagnostics.

### Transition guard

The transition guard is a temporary high-priority unreachable rule inside the package-owned priority range.

It must be ordered after:

* kernel local rule;
* app-bypass direct rule;
* app-bypass unreachable guard.

It must be ordered before:

* all mode-specific rules;
* any old broad direct or VPN rule.

Purpose:

* during reconfiguration, non-local non-app traffic fails closed instead of leaking direct or accidentally routing through the wrong table.

If apply fails while the guard is installed, the package should attempt best-effort rollback to the last applied in-memory state. If that fails, leaving the guard installed is safer than leaking traffic. The explicit rollback operation must be able to remove it later.

## 14. Rollback design

Rollback must be idempotent.

Rollback should:

1. list IPv4 and IPv6 rules;
2. delete every rule in the package-owned priority range;
3. flush `VPN_TABLE`;
4. flush `SAFE_TABLE`;
5. close or reset internal state as needed.

Rollback should not require knowing which mode was previously applied.

Rollback should succeed after:

* a complete apply;
* a partial apply;
* failed apply after table flush;
* failed apply after some rules were installed;
* failed apply with transition guard still active.

Rollback may leave the TUN interface untouched because TUN lifecycle is out of scope.

## 15. Switching modes

Switching is just applying a new desired config.

Examples:

* exclude strict → exclude non-strict;
* include strict → include non-strict;
* include non-strict → exclude strict;
* IPv4-only → dual-stack;
* changed user mark;
* changed table IDs;
* changed priority range.

The package should not have mode-specific imperative switch functions. It should have one reconcile/apply path.

Mode-specific behavior belongs only in the compiler.

## 16. Handling changing host routes

For the MVP, the package can rebuild `SAFE_TABLE` during every apply and expose a manual refresh operation.

Package should use route subscription support to refresh automatically when `main` changes.
Package should rebuild `SAFE_TABLE` during every apply, on auto-refresh and expose a manual refresh operation.

Refresh behavior:

* take new snapshot of `main`;
* rebuild `SAFE_TABLE`;
* leave rules unchanged;
* leave `VPN_TABLE` unchanged unless TUN state changed.

Note: observed events related to our owned Tun should not lead to auto-refresh cause it can leed too loop.

## 17. Route normalization and equality
The package needs stable route comparison.

Normalize before comparing or applying:

* family;
* destination;
* gateway;
* source, if relevant;
* link index;
* table;
* priority/metric;
* scope;
* protocol;
* type;
* multipath nexthops.

Do not compare string renderings of routes. Use structured fields.

For `SAFE_TABLE`, copied routes should preserve enough fields to behave like the original route, while changing only the table ID.

For `VPN_TABLE`, generated routes should be minimal and deterministic.

## 18. Rule normalization and equality

Rules should be generated deterministically.

Each generated rule should have:

* explicit family;
* explicit priority;
* explicit table or unreachable type;
* explicit mark/mask where needed;
* no accidental inherited selector fields.

Cleanup should not rely on reconstructing rules. It should list actual rules and delete those whose priority is inside the owned range.

This is important because a partial failure may leave rules that do not match the current desired config.

## 19. Error model

Use typed errors or wrapped sentinel categories for:

* invalid config;
* permission denied / missing capability;
* TUN link not found;
* table conflict;
* priority conflict;
* netlink transient error;
* apply failed with guard removed;
* apply failed with guard still active;
* rollback incomplete.

The caller needs to know whether the system is likely:

* unchanged;
* switched successfully;
* failed closed;
* partially rolled back;
* rolled back fully.

## 20. Package layout

Recommended files:

| File                        | Responsibility                                |
| --------------------------- | --------------------------------------------- |
| `doc.go`                    | package documentation and high-level behavior |
| `config.go`                 | public config types and validation            |
| `manager.go`                | public manager lifecycle                      |
| `compiler.go`               | pure mode-to-rules compiler                   |
| `tables.go`                 | desired table construction                    |
| `safe.go`                   | safe route classifier                         |
| `snapshot.go`               | route snapshot model                          |
| `apply.go`                  | reconciliation/apply logic                    |
| `rollback.go`               | cleanup logic                                 |
| `netlink_adapter.go`        | real vishvananda/netlink adapter              |
| `fake_adapter_test.go`      | fake backend for unit tests                   |
| `compiler_test.go`          | mode matrix tests                             |
| `safe_test.go`              | classifier tests                              |
| `apply_test.go`             | reconciliation tests                          |

## 21. Unit test plan

### Compiler tests

Test every mode:

* exclude + strict;
* exclude + non-strict;
* include + strict;
* include + non-strict.

For each, assert:

* exact rule order;
* exact priorities;
* exact tables;
* exact mark/mask matching;
* unreachable guards are present;
* safe rule appears only in non-strict modes;
* safe rule appears before user VPN rule in include non-strict.

### Safe classifier tests

Test:

* default IPv4 route is unsafe;
* default IPv6 route is unsafe;
* directly connected RFC1918 route is safe;
* Docker bridge route is safe;
* IPv6 link-local route is safe;
* IPv6 ULA route is safe;
* public route via gateway is unsafe;
* public route without gateway is safe under the current definition;
* route through owned TUN is unsafe;
* multipath route with one unsafe nexthop is unsafe;
* unsupported route type is ignored.

### Apply tests with fake adapter

Test:

* first apply installs tables and rules;
* second identical apply is idempotent;
* switching modes deletes stale rules;
* apply uses transition guard;
* failure during route install leaves or removes guard according to policy;
* rollback deletes all owned rules and flushes owned tables;
* rollback works after partial apply;
* rollback ignores missing objects.

### Validation tests

Test:

* reserved table IDs rejected;
* duplicate table IDs rejected;
* invalid priority range rejected;
* overlapping app/user marks rejected;
* missing TUN rejected;
* zero mark mask rejected;
* unsupported mode rejected.

### Phase 1: Pure model

Implement:

* config model;
* validation;
* route/rule desired-state structs;
* mode compiler;
* safe classifier;
* unit tests.

No real netlink mutations yet.

### Phase 2: Netlink adapter

Implement:

* real adapter around vishvananda/netlink;
* fake adapter;
* route/rule normalization;
* list/delete/replace helpers.

Add tests using fake adapter.

### Phase 3: Apply and rollback

Implement:

* table flush;
* rule cleanup by owned priority range;
* transition guard;
* desired route install;
* desired rule install;
* rollback.

Add partial-failure tests.

## 22. Important invariants

The package must preserve these invariants:

1. Never modify `main`.
2. Never modify `local`.
3. Never modify routes outside `VPN_TABLE` and `SAFE_TABLE`.
4. Never delete rules outside the owned priority range.
5. Never allow VPN-required traffic to fall through to direct routing.
6. Always keep app-bypass above VPN catch-all rules.
7. Always keep kernel local table first.
8. In non-strict modes, safe bypass is destination-based, not interface-based.
9. In strict modes, safe bypass is disabled.
10. Rollback is idempotent and independent of current mode.

## 24. Final mental model

`main` answers:

> what would the host do without my VPN?

`SAFE_TABLE` answers:

> which direct destinations am I willing to preserve while VPN is active?

`VPN_TABLE` answers:

> what traffic must be wrapped?

Unreachable guards answer:

> what must not leak when the expected route is missing?

The package should be implemented as a deterministic compiler plus a cautious reconciler. The compiler decides what should exist. The reconciler makes kernel state match it, using a temporary fail-closed guard during transitions.

