//go:build linux

package linux

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
)

// capabilityFailures preserves why the high-level constructor disabled a
// component. NewSystem callers do not need this metadata because requested
// features and missing injected dependencies are distinguishable directly.
type capabilityFailures struct {
	tun     []sysnet.CapabilityReason
	routing []sysnet.CapabilityReason
	dns     []sysnet.CapabilityReason
	pmark   []sysnet.CapabilityReason
}

func (f capabilityFailures) clone() capabilityFailures {
	return capabilityFailures{
		tun:     append([]sysnet.CapabilityReason(nil), f.tun...),
		routing: append([]sysnet.CapabilityReason(nil), f.routing...),
		dns:     append([]sysnet.CapabilityReason(nil), f.dns...),
		pmark:   append([]sysnet.CapabilityReason(nil), f.pmark...),
	}
}

var (
	availableCapability = sysnet.Capability{
		State: sysnet.CapabilityAvailable,
	}
	notImplementedCapability = sysnet.Capability{
		State:   sysnet.CapabilityUnsupported,
		Reasons: []sysnet.CapabilityReason{sysnet.ReasonNotImplemented},
	}
)

// Capabilities returns a deep, independently owned snapshot. The Linux
// backend has static capabilities after construction, except that close changes
// all previously usable entries to system_closed.
func (s *System) Capabilities() sysnet.CapabilityReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capabilitiesLocked()
}

func (s *System) capabilitiesLocked() sysnet.CapabilityReport {
	report := s.capabilityReport.Clone()
	if s.closed {
		markCapabilityReportClosed(&report)
		report.Revision++
	}
	return report
}

func (s *System) openCapabilityReportLocked() sysnet.CapabilityReport {
	report := sysnet.CapabilityReport{
		SchemaVersion: sysnet.CapabilitySchemaVersion,
	}
	addOperation := func(
		target sysnet.Target,
		operation sysnet.Operation,
		family sysnet.AddressFamily,
		capability sysnet.Capability,
	) {
		operationCapability := sysnet.OperationCapability{
			Key: sysnet.OperationKey{
				Target:    target,
				Operation: operation,
				Family:    family,
			},
			Capability: capability.Clone(),
		}
		report.Operations = append(report.Operations, operationCapability)
	}

	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
	} {
		addOperation(
			sysnet.TargetSystem,
			sysnet.OpAllocateIP,
			family,
			availableCapability,
		)
		addOperation(
			sysnet.TargetSystem,
			sysnet.OpAllocateSubnet,
			family,
			availableCapability,
		)
	}

	tunCapability := componentCapability(
		s.features.Tun,
		s.tunFactory != nil && s.tunConfig != nil,
		s.capabilityFailures.tun,
	)
	tunDynamic := dependentConfiguredCapability(
		tunCapability,
		s.features.DynTun,
	)
	tunNames := dependentConfiguredCapability(
		tunCapability,
		s.features.TunNames,
	)
	tunRename := combineCapabilities(tunDynamic, tunNames)

	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyNone,
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
		sysnet.FamilyDual,
	} {
		addOperation(sysnet.TargetTun, sysnet.OpCreate, family, tunCapability)
		addOperation(sysnet.TargetTun, sysnet.OpCreateNamed, family, tunNames)
	}
	addOperation(
		sysnet.TargetTun,
		sysnet.OpSetMTU,
		sysnet.FamilyNone,
		tunDynamic,
	)
	addOperation(
		sysnet.TargetTun,
		sysnet.OpRename,
		sysnet.FamilyNone,
		tunRename,
	)
	addTunListOperations := func(
		target sysnet.Target,
		family sysnet.AddressFamily,
		capability sysnet.Capability,
	) {
		for _, operation := range []sysnet.Operation{
			sysnet.OpSetAddresses,
			sysnet.OpAddAddress,
			sysnet.OpGetAddresses,
			sysnet.OpSetRoutes,
			sysnet.OpAddRoute,
			sysnet.OpGetRoutes,
		} {
			addOperation(target, operation, family, capability)
		}
	}
	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
		sysnet.FamilyDual,
	} {
		addTunListOperations(sysnet.TargetTun, family, tunDynamic)
	}

	routingCapability := componentCapability(
		s.features.Routing,
		s.routingManager != nil,
		s.capabilityFailures.routing,
	)
	dnsCapability := componentCapability(
		s.features.DNSControl,
		s.dnsProvider != nil && s.packetListen != nil,
		s.capabilityFailures.dns,
	)
	defaultFailures := append(
		append([]sysnet.CapabilityReason(nil), s.capabilityFailures.tun...),
		s.capabilityFailures.routing...,
	)
	defaultFailures = append(defaultFailures, s.capabilityFailures.dns...)
	defaultCapability := combineCapabilities(
		componentCapability(s.features.DefaultTun, true, defaultFailures),
		tunCapability,
		routingCapability,
		dnsCapability,
	)
	defaultDynamic := dependentConfiguredCapability(
		defaultCapability,
		s.features.DynDefaultTun,
	)
	// Renaming an active default TUN invalidates its installed Linux routes.
	// Keep both name operations unsupported until one transaction can update the
	// device and every dependent policy safely.
	defaultNames := notImplementedCapability
	defaultRename := notImplementedCapability

	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
		sysnet.FamilyDual,
	} {
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpCreate,
			family,
			defaultCapability,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpCreateNamed,
			family,
			defaultNames,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpReconfigureInPlace,
			family,
			defaultCapability,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpSourceRoutes,
			family,
			defaultCapability,
		)
		addTunListOperations(
			sysnet.TargetDefaultTun,
			family,
			defaultDynamic,
		)
	}
	addOperation(
		sysnet.TargetDefaultTun,
		sysnet.OpSetMTU,
		sysnet.FamilyNone,
		defaultDynamic,
	)
	addOperation(
		sysnet.TargetDefaultTun,
		sysnet.OpRename,
		sysnet.FamilyNone,
		defaultRename,
	)
	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
	} {
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpDNSProvider,
			family,
			defaultCapability,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpDNSConfigure,
			family,
			defaultCapability,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpDNSPort53Exclusive,
			family,
			notImplementedCapability,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpDNSSystemExclusive,
			family,
			notImplementedCapability,
		)
	}

	for _, target := range []sysnet.Target{
		sysnet.TargetOutNet,
		sysnet.TargetLocalNet,
	} {
		for _, family := range []sysnet.AddressFamily{
			sysnet.FamilyIPv4,
			sysnet.FamilyIPv6,
		} {
			for _, operation := range []sysnet.Operation{
				sysnet.OpDialTCP,
				sysnet.OpDialUDP,
				sysnet.OpPacketDialUDP,
				sysnet.OpListenTCP,
				sysnet.OpListenUDP,
				sysnet.OpListenPacketUDP,
				sysnet.OpMulticastUDP,
			} {
				addOperation(target, operation, family, availableCapability)
			}
		}
		addOperation(
			target,
			sysnet.OpResolve,
			sysnet.FamilyNone,
			availableCapability,
		)
		addOperation(
			target,
			sysnet.OpInterfaces,
			sysnet.FamilyNone,
			availableCapability,
		)
	}
	outDNSCapability := componentCapability(
		s.dnsProvider != nil,
		s.outDNS != nil,
		s.capabilityFailures.dns,
	)
	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
	} {
		addOperation(
			sysnet.TargetOutDNS,
			sysnet.OpQueryUDP,
			family,
			outDNSCapability,
		)
		addOperation(
			sysnet.TargetOutDNS,
			sysnet.OpQueryTCP,
			family,
			outDNSCapability,
		)
	}

	matcherCapability := componentCapability(
		s.features.MatcherRules,
		s.ruleTracker != nil && s.ownerLookup != nil,
		nil,
	)
	tunRuleCapability := componentCapability(
		s.features.TunRules,
		s.features.Pmark && s.pmark != nil && s.ruleTracker != nil,
		s.capabilityFailures.pmark,
	)

	matcherKeys := []sysnet.MatcherProfileKey{
		{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportTCP},
		{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportUDP},
		{Family: sysnet.FamilyIPv6, Transport: sysnet.TransportTCP},
		{Family: sysnet.FamilyIPv6, Transport: sysnet.TransportUDP},
	}
	for _, definition := range supportedRules {
		completion := notImplementedCapability
		if definition.Completion {
			completion = availableCapability
		}
		rule := sysnet.RuleCapability{
			Type:        definition.Type,
			Description: definition.Description,
			ValueKind:   definition.ValueKind,
			SemanticsID: definition.SemanticsID,
			Validation:  availableCapability,
			Completion:  completion,
		}
		for _, key := range matcherKeys {
			quality := sysnet.MatchQualityBestEffortTuple
			if key.Transport == sysnet.TransportUDP {
				quality = sysnet.MatchQualityBestEffortLocalEndpoint
			}
			rule.Matchers = append(rule.Matchers, sysnet.MatcherProfile{
				Key:        key,
				Capability: matcherCapability.Clone(),
				Quality:    quality,
			})
		}
		report.Rules = append(report.Rules, rule)
	}

	strictCapability := dependentConfiguredCapability(
		routingCapability,
		s.features.StrictMode,
	)
	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
		sysnet.FamilyDual,
	} {
		for _, mode := range []sysnet.RoutingMode{
			sysnet.RoutingFull,
			sysnet.RoutingExclude,
			sysnet.RoutingInclude,
		} {
			for _, strict := range []bool{false, true} {
				capability := defaultCapability
				if strict {
					capability = dependentCapability(
						capability,
						strictCapability,
					)
				}
				if mode != sysnet.RoutingFull {
					capability = dependentCapability(
						capability,
						tunRuleCapability,
					)
				}
				profile := sysnet.DefaultTunProfile{
					Key: sysnet.RoutingProfileKey{
						Family: family,
						Mode:   mode,
						Strict: strict,
					},
					Capability: capability,
				}
				if mode != sysnet.RoutingFull {
					for _, definition := range supportedRules {
						binding := sysnet.RuleBinding{
							Type:       definition.Type,
							Capability: capability.Clone(),
						}
						profile.Rules = append(profile.Rules, binding)
					}
				}
				report.DefaultTunProfiles = append(
					report.DefaultTunProfiles,
					profile,
				)
			}
		}
	}

	for _, key := range matcherKeys {
		quality := sysnet.MatchQualityBestEffortTuple
		if key.Transport == sysnet.TransportUDP {
			quality = sysnet.MatchQualityBestEffortLocalEndpoint
		}
		report.Ownership = append(report.Ownership, sysnet.OwnerCapability{
			Key:        key,
			Capability: matcherCapability.Clone(),
			Quality:    quality,
			Fields: []sysnet.OwnerFieldCapability{
				{Field: sysnet.OwnerPID, Capability: matcherCapability.Clone()},
				{
					Field:      sysnet.OwnerProcessName,
					Capability: matcherCapability.Clone(),
				},
				{
					Field:      sysnet.OwnerExecutablePath,
					Capability: matcherCapability.Clone(),
				},
				{Field: sysnet.OwnerUID, Capability: matcherCapability.Clone()},
				{Field: sysnet.OwnerGID, Capability: matcherCapability.Clone()},
				{
					Field:      sysnet.OwnerUserSID,
					Capability: notImplementedCapability.Clone(),
				},
			},
		})
	}

	return report
}

func componentCapability(
	enabled bool,
	dependenciesPresent bool,
	failures []sysnet.CapabilityReason,
) sysnet.Capability {
	if len(failures) != 0 {
		return sysnet.Capability{
			State:   sysnet.CapabilityUnavailable,
			Reasons: uniqueReasons(failures),
		}
	}
	if !enabled {
		return sysnet.Capability{
			State: sysnet.CapabilityUnavailable,
			Reasons: []sysnet.CapabilityReason{
				sysnet.ReasonDisabledByConfig,
			},
		}
	}
	if !dependenciesPresent {
		return sysnet.Capability{
			State: sysnet.CapabilityUnavailable,
			Reasons: []sysnet.CapabilityReason{
				sysnet.ReasonMissingDependency,
			},
		}
	}
	return availableCapability
}

func configuredCapability(enabled bool) sysnet.Capability {
	return componentCapability(enabled, true, nil)
}

// dependentConfiguredCapability reports the dependency failure without adding
// a misleading configuration reason. The feature switch is relevant only when
// the dependency is usable.
func dependentConfiguredCapability(
	dependency sysnet.Capability,
	enabled bool,
) sysnet.Capability {
	if dependency.State != sysnet.CapabilityAvailable {
		return dependency.Clone()
	}
	return configuredCapability(enabled)
}

// dependentCapability adds a requirement only when the base operation can be
// used. This prevents secondary feature switches from hiding the primary host
// failure that already blocks the operation.
func dependentCapability(
	base sysnet.Capability,
	requirement sysnet.Capability,
) sysnet.Capability {
	if base.State != sysnet.CapabilityAvailable {
		return base.Clone()
	}
	return combineCapabilities(base, requirement)
}

func combineCapabilities(capabilities ...sysnet.Capability) sysnet.Capability {
	state := sysnet.CapabilityAvailable
	reasonCount := 0
	limitationCount := 0
	for _, capability := range capabilities {
		reasonCount += len(capability.Reasons)
		limitationCount += len(capability.Limitations)
	}
	reasons := make([]sysnet.CapabilityReason, 0, reasonCount)
	limitations := make([]sysnet.LimitationID, 0, limitationCount)
	for _, capability := range capabilities {
		if capability.State < state {
			state = capability.State
		}
		reasons = append(reasons, capability.Reasons...)
		limitations = append(limitations, capability.Limitations...)
	}
	return sysnet.Capability{
		State:       state,
		Reasons:     uniqueReasons(reasons),
		Limitations: uniqueLimitations(limitations),
	}
}

func uniqueReasons(values []sysnet.CapabilityReason) []sysnet.CapabilityReason {
	seen := make(map[sysnet.CapabilityReason]struct{}, len(values))
	out := make([]sysnet.CapabilityReason, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueLimitations(values []sysnet.LimitationID) []sysnet.LimitationID {
	seen := make(map[sysnet.LimitationID]struct{}, len(values))
	out := make([]sysnet.LimitationID, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func markCapabilityReportClosed(report *sysnet.CapabilityReport) {
	closeCapability := func(capability *sysnet.Capability) {
		if capability.State != sysnet.CapabilityAvailable {
			return
		}
		*capability = sysnet.Capability{
			State:   sysnet.CapabilityUnavailable,
			Reasons: []sysnet.CapabilityReason{sysnet.ReasonSystemClosed},
		}
	}
	for i := range report.Operations {
		closeCapability(&report.Operations[i].Capability)
	}
	for i := range report.DefaultTunProfiles {
		closeCapability(&report.DefaultTunProfiles[i].Capability)
		for j := range report.DefaultTunProfiles[i].Rules {
			closeCapability(&report.DefaultTunProfiles[i].Rules[j].Capability)
		}
	}
	for i := range report.Rules {
		closeCapability(&report.Rules[i].Validation)
		closeCapability(&report.Rules[i].Completion)
		for j := range report.Rules[i].Matchers {
			closeCapability(&report.Rules[i].Matchers[j].Capability)
		}
	}
	for i := range report.Ownership {
		closeCapability(&report.Ownership[i].Capability)
		for j := range report.Ownership[i].Fields {
			closeCapability(&report.Ownership[i].Fields[j].Capability)
		}
	}
}

// CapabilitiesForTun returns the operations for one live owned TUN.
func (s *System) CapabilitiesForTun(
	t gtun.Tun,
) (sysnet.TunCapabilityReport, error) {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || t == nil {
		return sysnet.TunCapabilityReport{}, sysnet.ErrUnknownTun
	}

	target, instanceRevision, err := s.tunCapabilityTargetLocked(t)
	if err != nil {
		return sysnet.TunCapabilityReport{}, err
	}

	report := s.capabilitiesLocked()
	result := sysnet.TunCapabilityReport{
		SystemRevision:   report.Revision,
		InstanceRevision: instanceRevision,
	}
	for _, operation := range report.Operations {
		if operation.Key.Target == target &&
			operation.Key.Operation != sysnet.OpCreate &&
			operation.Key.Operation != sysnet.OpCreateNamed {
			result.Operations = append(result.Operations, operation)
		}
	}
	return result.Clone(), nil
}

// tunCapabilityTargetLocked resolves a live object while System.mu is held.
func (s *System) tunCapabilityTargetLocked(
	t gtun.Tun,
) (sysnet.Target, uint64, error) {
	if defaultTun, ok := t.(*defaultTun); ok {
		return s.defaultTunCapabilityTargetLocked(defaultTun)
	}
	typeOfTun := reflect.TypeOf(t)
	if typeOfTun == nil || !typeOfTun.Comparable() {
		return "", 0, sysnet.ErrUnknownTun
	}
	state := s.tuns[t]
	if state == nil || state.public != t {
		return "", 0, sysnet.ErrUnknownTun
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.tun == nil {
		return "", 0, sysnet.ErrUnknownTun
	}
	return sysnet.TargetTun, state.revision, nil
}

func (s *System) defaultTunCapabilityTargetLocked(
	t *defaultTun,
) (sysnet.Target, uint64, error) {
	if t == nil || t.defaultTunState == nil ||
		t.system != s || s.defaultTun != t.defaultTunState {
		return "", 0, sysnet.ErrUnknownTun
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tun == nil {
		return "", 0, sysnet.ErrUnknownTun
	}
	return sysnet.TargetDefaultTun, t.generation, nil
}

// CheckTunOpts validates regular-TUN options without changing host state.
func (s *System) CheckTunOpts(opts sysnet.TunOpts) sysnet.ValidationReport {
	opts = opts.Copy()
	report := s.Capabilities()
	result := sysnet.ValidationReport{CapabilityRevision: report.Revision}
	result.Issues = append(
		result.Issues,
		prefixListIssues("TunAddrs", opts.TunAddrs)...,
	)
	result.Issues = append(
		result.Issues,
		prefixListIssues("TunRoutes", opts.TunRoutes)...,
	)
	family := optionFamily(opts.TunAddrs, opts.TunRoutes)
	operation := sysnet.OpCreate
	if opts.Name != "" {
		operation = sysnet.OpCreateNamed
	}
	appendCapabilityIssue(&result, "", report.Operation(sysnet.OperationKey{
		Target:    sysnet.TargetTun,
		Operation: operation,
		Family:    family,
	}))
	if opts.Name != "" {
		valid, free := s.TunNameVerify(opts.Name)
		if !valid || !free {
			result.Issues = append(result.Issues, invalidIssue(
				"Name",
				"TUN name is invalid or already in use",
				nil,
			))
		}
	}
	return result
}

// CheckDefaultTunOpts validates default-TUN options without changing host
// state. It uses the same address, route, source-route, and rule compilers as
// BuildDefaultTun.
func (s *System) CheckDefaultTunOpts(
	opts sysnet.DefaultTunOpts,
) sysnet.ValidationReport {
	opts = opts.Copy()
	report := s.Capabilities()
	result := sysnet.ValidationReport{CapabilityRevision: report.Revision}
	if len(opts.Exclude) != 0 && len(opts.Include) != 0 {
		result.Issues = append(result.Issues, invalidIssue(
			"Include",
			"Include and Exclude are mutually exclusive",
			nil,
		))
	}
	addrIssues := prefixListIssues("TunAddrs", opts.TunAddrs)
	routeIssues := prefixListIssues("TunRoutes", opts.TunRoutes)
	result.Issues = append(result.Issues, addrIssues...)
	result.Issues = append(result.Issues, routeIssues...)

	addrs := append([]string(nil), opts.TunAddrs...)
	dnsIP := netip.Addr{}
	if len(addrIssues) == 0 {
		var err error
		addrs, dnsIP, err = normalizeTunAddrs(
			opts.TunAddrs,
			s.defaultTunCIDR,
			opts.DnsIP,
		)
		if err != nil {
			result.Issues = append(result.Issues, invalidIssue(
				"TunAddrs",
				"invalid TUN addresses",
				err,
			))
		}
	}
	routes := append([]string(nil), opts.TunRoutes...)
	if len(routeIssues) == 0 {
		var err error
		routes, err = normalizeTunRoutes(opts.TunRoutes)
		if err != nil {
			result.Issues = append(result.Issues, invalidIssue(
				"TunRoutes",
				"invalid TUN routes",
				err,
			))
		}
	}
	if !dnsIP.IsValid() {
		result.Issues = append(result.Issues, invalidIssue(
			"DnsIP",
			"default TUN DNS address is unavailable",
			nil,
		))
	}
	family := optionFamily(addrs, routes)
	if family == sysnet.FamilyNone {
		family = sysnet.FamilyDual
	}
	operation := sysnet.OpCreate
	if opts.Name != "" {
		operation = sysnet.OpCreateNamed
	}
	appendCapabilityIssue(&result, "", report.Operation(sysnet.OperationKey{
		Target:    sysnet.TargetDefaultTun,
		Operation: operation,
		Family:    family,
	}))

	mode := sysnet.RoutingFull
	rules := opts.Exclude
	rulePath := "Exclude"
	if len(opts.Exclude) != 0 {
		mode = sysnet.RoutingExclude
	} else if len(opts.Include) != 0 {
		mode = sysnet.RoutingInclude
		rules = opts.Include
		rulePath = "Include"
	}
	profileKey := sysnet.RoutingProfileKey{
		Family: family,
		Mode:   mode,
		Strict: opts.Strict,
	}
	profile := report.DefaultTunProfile(profileKey)
	appendCapabilityIssue(&result, "", profile.Capability)
	for index, rule := range rules {
		context := sysnet.RuleContext{Routing: &profileKey}
		ruleReport := checkRuleAgainstReport(report, rule, context)
		for _, issue := range ruleReport.Issues {
			if issue.Path == "" {
				issue.Path = fmt.Sprintf("%s[%d]", rulePath, index)
			} else {
				issue.Path = fmt.Sprintf(
					"%s[%d].%s",
					rulePath,
					index,
					issue.Path,
				)
			}
			result.Issues = append(result.Issues, issue)
		}
	}
	if len(opts.SourceRoutes) != 0 {
		appendCapabilityIssue(&result, "SourceRoutes", report.Operation(
			sysnet.OperationKey{
				Target:    sysnet.TargetDefaultTun,
				Operation: sysnet.OpSourceRoutes,
				Family:    family,
			},
		))
		_, err := normalizeTunSourceRoutes(addrs, opts.SourceRoutes)
		if err != nil {
			result.Issues = append(result.Issues, invalidIssue(
				"SourceRoutes",
				"invalid source-route policy",
				err,
			))
		}
	}
	if opts.Name != "" {
		valid, free := s.TunNameVerify(opts.Name)
		if valid && !free && s.activeDefaultTunName() == opts.Name {
			free = true
		}
		if !valid || !free {
			result.Issues = append(result.Issues, invalidIssue(
				"Name",
				"TUN name is invalid or already in use",
				nil,
			))
		}
	}
	return result
}

func (s *System) activeDefaultTunName() string {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	s.mu.Lock()
	state := s.defaultTun
	closed := s.closed
	s.mu.Unlock()
	if closed || state == nil {
		return ""
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.tun == nil {
		return ""
	}
	name, _ := state.tun.Name()
	return name
}

// CheckRule validates a rule in one exact routing or matcher context.
func (s *System) CheckRule(
	rule sysnet.Rule,
	context sysnet.RuleContext,
) sysnet.ValidationReport {
	return checkRuleAgainstReport(s.Capabilities(), rule, context.Clone())
}

func checkRuleAgainstReport(
	report sysnet.CapabilityReport,
	rule sysnet.Rule,
	context sysnet.RuleContext,
) sysnet.ValidationReport {
	result := sysnet.ValidationReport{CapabilityRevision: report.Revision}
	if (context.Routing == nil) == (context.Matcher == nil) {
		result.Issues = append(result.Issues, invalidIssue(
			"Context",
			"exactly one rule context must be set",
			nil,
		))
		return result
	}
	definition, known := findRuleDefinition(rule.Type)
	if !known {
		appendCapabilityIssue(&result, "Type", sysnet.Capability{
			State:   sysnet.CapabilityUnsupported,
			Reasons: []sysnet.CapabilityReason{sysnet.ReasonNotImplemented},
		})
		return result
	}
	ruleCapability := report.Rule(definition.Type)
	appendCapabilityIssue(&result, "Type", ruleCapability.Validation)
	if context.Routing != nil {
		profile := report.DefaultTunProfile(*context.Routing)
		appendCapabilityIssue(&result, "Context", profile.Capability)
		binding := sysnet.Capability{State: sysnet.CapabilityUnknown}
		for _, candidate := range profile.Rules {
			if candidate.Type == rule.Type {
				binding = candidate.Capability
				break
			}
		}
		appendCapabilityIssue(&result, "Type", binding)
	} else {
		matcher := sysnet.Capability{State: sysnet.CapabilityUnknown}
		for _, candidate := range ruleCapability.Matchers {
			if candidate.Key == *context.Matcher {
				matcher = candidate.Capability
				break
			}
		}
		appendCapabilityIssue(&result, "Context", matcher)
	}
	if _, err := compileRule(rule); err != nil {
		result.Issues = append(result.Issues, invalidIssue(
			"Rule",
			"invalid rule value",
			err,
		))
	}
	return result
}

// CompleteRule returns bounded suggestions in one exact use context.
func (s *System) CompleteRule(
	rule sysnet.Rule,
	context sysnet.RuleContext,
) (values []string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("complete %s rule: %v", rule.Type, recovered)
			values = nil
		}
	}()
	report := s.Capabilities()
	issue := completionContextIssue(report, rule.Type, context.Clone())
	if issue != nil {
		return nil, (sysnet.ValidationReport{
			CapabilityRevision: report.Revision,
			Issues:             []sysnet.ValidationIssue{*issue},
		}).Err()
	}
	values, err = completeRuleValue(rule)
	if err != nil {
		s.logCompletionErrorf(
			"complete %s rule %q: %v",
			rule.Type,
			rule.Rule,
			err,
		)
		return nil, err
	}
	return append([]string(nil), values...), nil
}

func completionContextIssue(
	report sysnet.CapabilityReport,
	ruleType string,
	context sysnet.RuleContext,
) *sysnet.ValidationIssue {
	if (context.Routing == nil) == (context.Matcher == nil) {
		issue := invalidIssue(
			"Context",
			"exactly one rule context must be set",
			nil,
		)
		return &issue
	}
	definition, known := findRuleDefinition(ruleType)
	if !known {
		return issueForCapability("Type", notImplementedCapability)
	}
	rule := report.Rule(definition.Type)
	if issue := issueForCapability("Type", rule.Completion); issue != nil {
		return issue
	}
	if context.Routing != nil {
		profile := report.DefaultTunProfile(*context.Routing)
		issue := issueForCapability("Context", profile.Capability)
		if issue != nil {
			return issue
		}
		for _, binding := range profile.Rules {
			if binding.Type == ruleType {
				return issueForCapability("Type", binding.Capability)
			}
		}
		return issueForCapability(
			"Type",
			sysnet.Capability{State: sysnet.CapabilityUnknown},
		)
	}
	for _, matcher := range rule.Matchers {
		if matcher.Key == *context.Matcher {
			return issueForCapability("Context", matcher.Capability)
		}
	}
	return issueForCapability(
		"Context",
		sysnet.Capability{State: sysnet.CapabilityUnknown},
	)
}

func findRuleDefinition(ruleType string) (ruleDefinition, bool) {
	for _, definition := range supportedRules {
		if definition.Type == ruleType {
			return definition, true
		}
	}
	return ruleDefinition{}, false
}

func optionFamily(addrs, routes []string) sysnet.AddressFamily {
	hasIPv4 := false
	hasIPv6 := false
	for _, value := range append(append([]string(nil), addrs...), routes...) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().IsLoopback() {
			continue
		}
		if prefix.Addr().Is4() {
			hasIPv4 = true
		} else if prefix.Addr().Is6() {
			hasIPv6 = true
		}
	}
	switch {
	case hasIPv4 && hasIPv6:
		return sysnet.FamilyDual
	case hasIPv4:
		return sysnet.FamilyIPv4
	case hasIPv6:
		return sysnet.FamilyIPv6
	default:
		return sysnet.FamilyNone
	}
}

func prefixListIssues(path string, values []string) []sysnet.ValidationIssue {
	var issues []sysnet.ValidationIssue
	for index, value := range values {
		if _, err := netip.ParsePrefix(value); err != nil {
			issues = append(issues, invalidIssue(
				fmt.Sprintf("%s[%d]", path, index),
				"invalid IP prefix",
				err,
			))
		}
	}
	return issues
}

func appendCapabilityIssue(
	report *sysnet.ValidationReport,
	path string,
	capability sysnet.Capability,
) {
	if issue := issueForCapability(path, capability); issue != nil {
		report.Issues = append(report.Issues, *issue)
	}
}

func issueForCapability(
	path string,
	capability sysnet.Capability,
) *sysnet.ValidationIssue {
	if capability.State == sysnet.CapabilityAvailable {
		return nil
	}
	issue := sysnet.ValidationIssue{
		Path:   path,
		State:  capability.State,
		Detail: capability.Detail,
	}
	if len(capability.Reasons) != 0 {
		issue.Reason = capability.Reasons[0]
	}
	return &issue
}

func invalidIssue(
	path string,
	detail string,
	cause error,
) sysnet.ValidationIssue {
	if cause == nil {
		cause = sysnet.ErrInvalidOptions
	} else if !errors.Is(cause, sysnet.ErrInvalidOptions) {
		cause = errors.Join(sysnet.ErrInvalidOptions, cause)
	}
	return sysnet.ValidationIssue{
		Path:   path,
		State:  sysnet.CapabilityUnknown,
		Detail: detail,
		Err:    cause,
	}
}

func capabilityError(capability sysnet.Capability) error {
	if capability.State == sysnet.CapabilityAvailable {
		return nil
	}
	report := sysnet.ValidationReport{}
	appendCapabilityIssue(&report, "", capability)
	return report.Err()
}
