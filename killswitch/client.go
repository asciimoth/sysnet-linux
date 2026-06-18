//go:build linux

// Package killswitch provides a minimal client for the killswitch daemon admin
// API.
//
// The daemon accepts only one temporary ruleset per admin API connection. This
// package therefore keeps all caller-created temporary rulesets in memory,
// merges them into one connection-level ruleset, and re-sends that merged
// ruleset whenever local state changes or the daemon connection is restored.
package killswitch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	DefaultAdminSocketPath = "/run/killswitch/admin.sock"

	messageTypeConfigRequest  = "config_request"
	messageTypeConfig         = "config"
	messageTypeSubscribe      = "subscribe"
	messageTypeEvent          = "event"
	messageTypeMutation       = "mutation"
	messageTypeMutationResult = "mutation_result"

	eventTypeInterfaces = "interfaces"

	mutationRemove = "remove"
	mutationSet    = "set"

	targetTMPRuleset = "tmp_ruleset"
)

// Logf is the logging callback used by Client.
type Logf func(format string, args ...any)

// AllowRules is the policy part of a killswitch temporary ruleset.
//
// String fields use the daemon's admin API syntax:
//   - AllowedMarks accepts integer marks such as "0x8000" or "32768".
//   - AllowedPorts accepts "tcp/443" or "udp/53".
//   - AllowedV4Hosts and AllowedV6Hosts accept plain IP addresses.
//   - AllowedV4Pairs and AllowedV6Pairs accept "tcp/192.0.2.1:443",
//     "udp/[2001:db8::1]:53", and similar host-port rules.
type AllowRules struct {
	AllowAll       bool     `json:"allow_all"`                      //nolint:tagliatelle
	EnableV4       bool     `json:"enable_v4"`                      //nolint:tagliatelle
	EnableV6       bool     `json:"enable_v6"`                      //nolint:tagliatelle
	AllowedMarks   []string `json:"allowed_marks,omitempty"`        //nolint:tagliatelle
	AllowedPorts   []string `json:"allowed_ports,omitempty"`        //nolint:tagliatelle
	AllowedV4Hosts []string `json:"allowed_v4_hosts,omitempty"`     //nolint:tagliatelle
	AllowedV6Hosts []string `json:"allowed_v6_hosts,omitempty"`     //nolint:tagliatelle
	AllowedV4Pairs []string `json:"allowed_v4_hostports,omitempty"` //nolint:tagliatelle
	AllowedV6Pairs []string `json:"allowed_v6_hostports,omitempty"` //nolint:tagliatelle
}

// Client maintains temporary killswitch rulesets over the daemon admin API.
//
// Client hides IPC state from callers. Temporary ruleset methods are available
// before the daemon socket exists, while the daemon is down, and after
// disconnects. A background goroutine reconnects forever with exponential
// backoff from 1s to 64s, resetting the delay after every successful
// connection. Close stops that goroutine.
//
// The daemon applies temporary rulesets to explicit interface names. Client
// subscribes to interface events, tracks the current daemon-reported interface
// name list, and attaches the merged temporary ruleset to every available
// interface. Interface property-only events do not trigger a re-send; only a
// changed set of interface names does.
type Client struct {
	path string
	logf Logf

	mu              sync.Mutex
	closed          bool
	version         uint64
	nextRulesetID   uint64
	rulesets        map[uint64]AllowRules
	interfaceNames  []string
	interfacesKnown bool
	wake            chan struct{}
	done            chan struct{}
}

// NewClient starts a killswitch admin API client for path.
//
// logf may be nil. The returned client immediately starts trying to connect,
// but temporary ruleset methods do not require the connection to be available.
// If path is empty, DefaultAdminSocketPath is used.
func NewClient(path string, logf Logf) *Client {
	if path == "" {
		path = DefaultAdminSocketPath
	}
	c := &Client{
		path:     path,
		logf:     logf,
		rulesets: make(map[uint64]AllowRules),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	go c.run()
	return c
}

// CreateTMPRuleset stores a new temporary ruleset, schedules a daemon update,
// and returns the generated ruleset ID. Callers must keep the ID and pass it to
// UpdateTMPRuleset or DeleteTMPRuleset to modify or remove the same ruleset.
func (c *Client) CreateTMPRuleset(rules AllowRules) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("killswitch: client is closed")
	}
	if c.nextRulesetID == ^uint64(0) {
		return 0, errors.New("killswitch: temporary ruleset ID space exhausted")
	}
	c.nextRulesetID++
	id := c.nextRulesetID
	c.rulesets[id] = cloneAllowRules(rules)
	c.changedLocked()
	return id, nil
}

// UpdateTMPRuleset replaces an existing temporary ruleset and schedules a
// daemon update. It returns an error if id does not identify an existing
// ruleset.
func (c *Client) UpdateTMPRuleset(id uint64, rules AllowRules) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("killswitch: client is closed")
	}
	if _, ok := c.rulesets[id]; !ok {
		return fmt.Errorf("killswitch: temporary ruleset %d does not exist", id)
	}
	c.rulesets[id] = cloneAllowRules(rules)
	c.changedLocked()
	return nil
}

// DeleteTMPRuleset removes a temporary ruleset and schedules a daemon update.
// Deleting a missing ruleset is a no-op.
func (c *Client) DeleteTMPRuleset(id uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("killswitch: client is closed")
	}
	if _, ok := c.rulesets[id]; !ok {
		return nil
	}
	delete(c.rulesets, id)
	c.changedLocked()
	return nil
}

// Close stops reconnecting and closes the current admin API connection, if any.
// It does not clear the in-memory ruleset map.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)
	c.mu.Unlock()
	c.notify()
	return nil
}

func (c *Client) run() {
	delay := time.Second
	for {
		if c.isClosed() {
			return
		}

		conn, err := net.Dial("unix", c.path) //nolint:noctx
		if err != nil {
			c.log("connect to killswitch admin API %s: %s", c.path, err)
			if !c.sleep(delay) {
				return
			}
			delay = nextDelay(delay)
			continue
		}

		c.log("connected to killswitch admin API %s", c.path)
		delay = time.Second
		c.serveConn(conn)
	}
}

func (c *Client) serveConn(conn net.Conn) {
	defer conn.Close() //nolint:errcheck

	c.resetInterfaces()

	session := newAPISession(conn, c.setInterfaces, c.log)
	defer session.close()

	if err := session.start(); err != nil {
		c.log("start killswitch admin API session: %s", err)
		return
	}

	appliedVersion := uint64(0)
	for {
		version, merged, ready, ok := c.snapshot()
		if !ok {
			return
		}
		if ready && version != appliedVersion {
			if err := session.apply(merged); err != nil {
				c.log("write killswitch temporary ruleset: %s", err)
				return
			}
			appliedVersion = version
		}

		select {
		case <-c.wake:
		case <-session.closed:
			c.log("killswitch admin API connection closed")
			return
		case <-c.done:
			return
		}
	}
}

func (c *Client) snapshot() (uint64, *mergedTMPRuleset, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, nil, false, false
	}
	if !c.interfacesKnown {
		return c.version, nil, false, true
	}
	return c.version, mergeTMPRulesets(c.rulesets, c.interfaceNames), true, true
}

func (c *Client) changedLocked() {
	c.version++
	c.notify()
}

func (c *Client) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Client) resetInterfaces() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.interfaceNames = nil
	c.interfacesKnown = false
	c.changedLocked()
}

func (c *Client) setInterfaces(interfaces []apiInterface) {
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Name != "" {
			names = append(names, iface.Name)
		}
	}
	names = uniqueSortedStrings(names)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.interfacesKnown && equalStrings(c.interfaceNames, names) {
		return
	}
	c.interfaceNames = names
	c.interfacesKnown = true
	c.changedLocked()
}

func (c *Client) sleep(d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-c.done:
		return false
	}
}

func (c *Client) log(format string, args ...any) { //nolint:goprintffuncname
	if c.logf != nil {
		c.logf(format, args...)
	}
}

type apiSession struct {
	enc           *json.Encoder
	conn          net.Conn
	write         sync.Mutex
	once          sync.Once
	closed        chan struct{}
	setInterfaces func([]apiInterface)
	logf          Logf
}

func newAPISession(
	conn net.Conn,
	setInterfaces func([]apiInterface),
	logf Logf,
) *apiSession {
	s := &apiSession{
		enc:           json.NewEncoder(conn),
		conn:          conn,
		closed:        make(chan struct{}),
		setInterfaces: setInterfaces,
		logf:          logf,
	}
	go s.readLoop(json.NewDecoder(conn))
	return s
}

func (s *apiSession) start() error {
	if err := s.send(envelope{
		Type: messageTypeSubscribe,
		Payload: mustRawMessage(subscribePayload{
			EventTypes: []string{eventTypeInterfaces},
		}),
	}); err != nil {
		return err
	}
	return s.send(envelope{
		Type:    messageTypeConfigRequest,
		Payload: mustRawMessage(struct{}{}),
	})
}

func (s *apiSession) apply(merged *mergedTMPRuleset) error {
	req := envelope{
		Type: messageTypeMutation,
		Payload: mustRawMessage(mutationPayload{
			Operation: mutationRemove,
			Target:    targetTMPRuleset,
		}),
	}
	if merged != nil {
		req.Payload = mustRawMessage(mutationPayload{
			Operation:  mutationSet,
			Target:     targetTMPRuleset,
			Interfaces: merged.Interfaces,
			Policy:     &merged.Policy,
		})
	}
	return s.send(req)
}

func (s *apiSession) send(msg envelope) error {
	s.write.Lock()
	defer s.write.Unlock()
	if err := s.enc.Encode(msg); err != nil {
		s.close()
		return err
	}
	return nil
}

func (s *apiSession) readLoop(dec *json.Decoder) {
	defer s.close()
	for {
		var env envelope
		if err := dec.Decode(&env); err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				s.log("read killswitch admin API message: %s", err)
			}
			return
		}
		s.handleMessage(env)
	}
}

func (s *apiSession) handleMessage(env envelope) {
	switch env.Type {
	case messageTypeConfig:
		var msg configPayload
		if !s.decode(env.Payload, &msg, "config") {
			return
		}
		if s.setInterfaces != nil {
			s.setInterfaces(msg.Config.Interfaces)
		}
	case messageTypeEvent:
		var msg eventPayload
		if !s.decode(env.Payload, &msg, "event") {
			return
		}
		if msg.EventType == eventTypeInterfaces && s.setInterfaces != nil {
			s.setInterfaces(msg.Config.Interfaces)
		}
	case messageTypeMutationResult:
		var result mutationResult
		if !s.decode(env.Payload, &result, "mutation result") {
			return
		}
		if !result.OK {
			s.log(
				"killswitch rejected temporary ruleset update: %s",
				result.Error,
			)
		}
	}
}

func (s *apiSession) decode(
	payload json.RawMessage,
	dst any,
	name string,
) bool {
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		s.log("decode killswitch %s: %s", name, err)
		return false
	}
	return true
}

func (s *apiSession) close() {
	s.once.Do(func() {
		_ = s.conn.Close()
		close(s.closed)
	})
}

func (s *apiSession) log(format string, args ...any) { //nolint:goprintffuncname
	if s.logf != nil {
		s.logf(format, args...)
	}
}

type envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type subscribePayload struct {
	EventTypes []string `json:"event_types"` //nolint:tagliatelle
}

type mutationPayload struct {
	Operation  string      `json:"operation"`
	Target     string      `json:"target"`
	Interfaces []string    `json:"interfaces,omitempty"`
	Policy     *AllowRules `json:"policy,omitempty"`
}

type configPayload struct {
	Config currentConfig `json:"config"`
}

type eventPayload struct {
	EventType string        `json:"event_type"` //nolint:tagliatelle
	Config    currentConfig `json:"config"`
}

type currentConfig struct {
	Interfaces []apiInterface `json:"interfaces,omitempty"`
}

type apiInterface struct {
	Name string `json:"name"`
}

type mutationResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type mergedTMPRuleset struct {
	Interfaces []string
	Policy     AllowRules
}

func mergeTMPRulesets(
	rulesets map[uint64]AllowRules,
	interfaces []string,
) *mergedTMPRuleset {
	if len(rulesets) == 0 || len(interfaces) == 0 {
		return nil
	}

	ids := make([]uint64, 0, len(rulesets))
	for id := range rulesets {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})

	var merged mergedTMPRuleset
	for _, id := range ids {
		merged.Policy = mergeAllowRules(merged.Policy, rulesets[id])
	}
	merged.Interfaces = append([]string(nil), interfaces...)
	normalizeAllowRules(&merged.Policy)
	return &merged
}

func mergeAllowRules(a, b AllowRules) AllowRules {
	return AllowRules{
		AllowAll:       a.AllowAll || b.AllowAll,
		EnableV4:       a.EnableV4 || b.EnableV4,
		EnableV6:       a.EnableV6 || b.EnableV6,
		AllowedMarks:   append(a.AllowedMarks, b.AllowedMarks...),
		AllowedPorts:   append(a.AllowedPorts, b.AllowedPorts...),
		AllowedV4Hosts: append(a.AllowedV4Hosts, b.AllowedV4Hosts...),
		AllowedV6Hosts: append(a.AllowedV6Hosts, b.AllowedV6Hosts...),
		AllowedV4Pairs: append(a.AllowedV4Pairs, b.AllowedV4Pairs...),
		AllowedV6Pairs: append(a.AllowedV6Pairs, b.AllowedV6Pairs...),
	}
}

func normalizeAllowRules(rules *AllowRules) {
	rules.AllowedMarks = uniqueSortedStrings(rules.AllowedMarks)
	rules.AllowedPorts = uniqueSortedStrings(rules.AllowedPorts)
	rules.AllowedV4Hosts = uniqueSortedStrings(rules.AllowedV4Hosts)
	rules.AllowedV6Hosts = uniqueSortedStrings(rules.AllowedV6Hosts)
	rules.AllowedV4Pairs = uniqueSortedStrings(rules.AllowedV4Pairs)
	rules.AllowedV6Pairs = uniqueSortedStrings(rules.AllowedV6Pairs)
}

func cloneAllowRules(rules AllowRules) AllowRules {
	return AllowRules{
		AllowAll:       rules.AllowAll,
		EnableV4:       rules.EnableV4,
		EnableV6:       rules.EnableV6,
		AllowedMarks:   append([]string(nil), rules.AllowedMarks...),
		AllowedPorts:   append([]string(nil), rules.AllowedPorts...),
		AllowedV4Hosts: append([]string(nil), rules.AllowedV4Hosts...),
		AllowedV6Hosts: append([]string(nil), rules.AllowedV6Hosts...),
		AllowedV4Pairs: append([]string(nil), rules.AllowedV4Pairs...),
		AllowedV6Pairs: append([]string(nil), rules.AllowedV6Pairs...),
	}
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustRawMessage(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func nextDelay(d time.Duration) time.Duration {
	next := d * 2
	if next > 64*time.Second {
		return 64 * time.Second
	}
	return next
}
