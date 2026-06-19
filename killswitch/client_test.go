//go:build linux

// nolint
package killswitch

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestMergeTMPRulesetsUsesDaemonInterfaces(t *testing.T) {
	merged := mergeTMPRulesets(map[uint64]AllowRules{
		2: {
			EnableV6:       true,
			AllowedPorts:   []string{"udp/53"},
			AllowedV6Hosts: []string{"2001:db8::1"},
		},
		1: {
			EnableV4:       true,
			AllowedPorts:   []string{"tcp/443", "udp/53"},
			AllowedV4Hosts: []string{"192.0.2.1"},
		},
	}, []string{"eth0", "wg0"})
	if merged == nil {
		t.Fatal("merged ruleset is nil")
	}
	if want := []string{
		"eth0",
		"wg0",
	}; !reflect.DeepEqual(
		merged.Interfaces,
		want,
	) {
		t.Fatalf("interfaces = %v, want %v", merged.Interfaces, want)
	}
	if !merged.Policy.EnableV4 || !merged.Policy.EnableV6 {
		t.Fatalf(
			"policy enables = v4:%v v6:%v, want both true",
			merged.Policy.EnableV4,
			merged.Policy.EnableV6,
		)
	}
	if want := []string{
		"tcp/443",
		"udp/53",
	}; !reflect.DeepEqual(
		merged.Policy.AllowedPorts,
		want,
	) {
		t.Fatalf(
			"allowed ports = %v, want %v",
			merged.Policy.AllowedPorts,
			want,
		)
	}
}

func TestClientSendsMergedRulesToDaemonInterfaces(t *testing.T) {
	server := startTestAdminServer(t, "wg1", "wg0")
	client := NewClient(server.path, t.Logf)
	defer closeClient(t, client)

	dnsID, err := client.CreateTMPRuleset(AllowRules{
		EnableV4:     true,
		AllowedPorts: []string{"udp/53"},
	})
	if err != nil {
		t.Fatalf("CreateTMPRuleset: %v", err)
	}
	if dnsID == 0 {
		t.Fatal("CreateTMPRuleset returned zero ID")
	}
	first := server.nextMutation(t)
	assertMutation(t, first, mutationSet, []string{"wg0", "wg1"}, AllowRules{
		EnableV4:     true,
		AllowedPorts: []string{"udp/53"},
	})

	webID, err := client.CreateTMPRuleset(AllowRules{
		EnableV6:     true,
		AllowedPorts: []string{"tcp/443"},
	})
	if err != nil {
		t.Fatalf("CreateTMPRuleset(web): %v", err)
	}
	if webID == dnsID {
		t.Fatalf("CreateTMPRuleset returned duplicate ID %d", webID)
	}
	second := server.nextMutation(t)
	assertMutation(t, second, mutationSet, []string{"wg0", "wg1"}, AllowRules{
		EnableV4:     true,
		EnableV6:     true,
		AllowedPorts: []string{"tcp/443", "udp/53"},
	})

	if err := client.UpdateTMPRuleset(dnsID, AllowRules{
		EnableV4:       true,
		AllowedV4Hosts: []string{"192.0.2.53"},
	}); err != nil {
		t.Fatalf("UpdateTMPRuleset: %v", err)
	}
	third := server.nextMutation(t)
	assertMutation(t, third, mutationSet, []string{"wg0", "wg1"}, AllowRules{
		EnableV4:       true,
		EnableV6:       true,
		AllowedPorts:   []string{"tcp/443"},
		AllowedV4Hosts: []string{"192.0.2.53"},
	})

	if err := client.DeleteTMPRuleset(dnsID); err != nil {
		t.Fatalf("DeleteTMPRuleset(dns): %v", err)
	}
	fourth := server.nextMutation(t)
	assertMutation(t, fourth, mutationSet, []string{"wg0", "wg1"}, AllowRules{
		EnableV6:     true,
		AllowedPorts: []string{"tcp/443"},
	})

	if err := client.DeleteTMPRuleset(webID); err != nil {
		t.Fatalf("DeleteTMPRuleset(web): %v", err)
	}
	fifth := server.nextMutation(t)
	if fifth.Operation != mutationRemove || fifth.Target != targetTMPRuleset {
		t.Fatalf("delete mutation = %+v, want remove tmp_ruleset", fifth)
	}
}

func TestClientResendsWhenInterfaceNameListChanges(t *testing.T) {
	server := startTestAdminServer(t, "wg0")
	client := NewClient(server.path, t.Logf)
	defer closeClient(t, client)

	if _, err := client.CreateTMPRuleset(AllowRules{
		EnableV4:     true,
		AllowedPorts: []string{"udp/53"},
	}); err != nil {
		t.Fatalf("CreateTMPRuleset: %v", err)
	}
	first := server.nextMutation(t)
	assertMutation(t, first, mutationSet, []string{"wg0"}, AllowRules{
		EnableV4:     true,
		AllowedPorts: []string{"udp/53"},
	})

	server.sendInterfaces(t, "wg0")
	server.assertNoMutation(t)

	server.sendInterfaces(t, "wg1", "wg0")
	second := server.nextMutation(t)
	assertMutation(t, second, mutationSet, []string{"wg0", "wg1"}, AllowRules{
		EnableV4:     true,
		AllowedPorts: []string{"udp/53"},
	})
}

func TestClientSendsStateAfterDaemonAppearsAndConfigArrives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	client := NewClient(path, t.Logf)
	defer closeClient(t, client)

	if _, err := client.CreateTMPRuleset(AllowRules{
		EnableV4:       true,
		AllowedV4Hosts: []string{"198.51.100.10"},
	}); err != nil {
		t.Fatalf("CreateTMPRuleset: %v", err)
	}

	server := startTestAdminServerAt(t, path, "wg-late")
	got := server.nextMutation(t)
	assertMutation(t, got, mutationSet, []string{"wg-late"}, AllowRules{
		EnableV4:       true,
		AllowedV4Hosts: []string{"198.51.100.10"},
	})
}

func TestClientValidatesRulesetOperations(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "missing.sock"), nil)
	defer closeClient(t, client)

	firstID, err := client.CreateTMPRuleset(AllowRules{})
	if err != nil {
		t.Fatalf("CreateTMPRuleset: %v", err)
	}
	secondID, err := client.CreateTMPRuleset(AllowRules{})
	if err != nil {
		t.Fatalf("CreateTMPRuleset second: %v", err)
	}
	if firstID == 0 || secondID == 0 {
		t.Fatalf(
			"generated IDs must be non-zero, got %d and %d",
			firstID,
			secondID,
		)
	}
	if firstID == secondID {
		t.Fatalf("generated IDs must be unique, got %d twice", firstID)
	}

	if err := client.UpdateTMPRuleset(secondID+1, AllowRules{}); err == nil {
		t.Fatal("UpdateTMPRuleset on missing ruleset succeeded")
	}
	if err := client.DeleteTMPRuleset(secondID + 1); err != nil {
		t.Fatalf("DeleteTMPRuleset on missing ruleset: %v", err)
	}
}

func TestNewClientUsesDefaultAdminSocketPath(t *testing.T) {
	client := NewClient("", nil)
	defer closeClient(t, client)

	if client.path != DefaultAdminSocketPath {
		t.Fatalf(
			"path = %q, want %q",
			client.path,
			DefaultAdminSocketPath,
		)
	}
}

func assertMutation(
	t *testing.T,
	got mutationPayload,
	op string,
	interfaces []string,
	policy AllowRules,
) {
	t.Helper()
	if got.Operation != op {
		t.Fatalf("operation = %q, want %q", got.Operation, op)
	}
	if got.Target != targetTMPRuleset {
		t.Fatalf("target = %q, want %q", got.Target, targetTMPRuleset)
	}
	if !reflect.DeepEqual(got.Interfaces, interfaces) {
		t.Fatalf("interfaces = %v, want %v", got.Interfaces, interfaces)
	}
	if got.Policy == nil {
		t.Fatal("policy is nil")
	}
	if !reflect.DeepEqual(*got.Policy, policy) {
		t.Fatalf("policy = %+v, want %+v", *got.Policy, policy)
	}
}

type testAdminServer struct {
	path     string
	listener net.Listener
	msgs     chan mutationPayload
	done     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup

	mu         sync.Mutex
	interfaces []apiInterface
	encoders   map[*json.Encoder]bool
	conns      map[net.Conn]bool
}

func startTestAdminServer(t *testing.T, interfaces ...string) *testAdminServer {
	t.Helper()
	return startTestAdminServerAt(
		t,
		filepath.Join(t.TempDir(), "admin.sock"),
		interfaces...)
}

func startTestAdminServerAt(
	t *testing.T,
	path string,
	interfaces ...string,
) *testAdminServer {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	server := &testAdminServer{
		path:       path,
		listener:   listener,
		msgs:       make(chan mutationPayload, 16),
		done:       make(chan struct{}),
		interfaces: namedInterfaces(interfaces...),
		encoders:   make(map[*json.Encoder]bool),
		conns:      make(map[net.Conn]bool),
	}
	t.Cleanup(server.close)
	server.wg.Add(1)
	go server.acceptLoop(t)
	return server
}

func (s *testAdminServer) acceptLoop(t *testing.T) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				t.Logf("accept: %v", err)
				return
			}
		}
		s.wg.Add(1)
		go s.handleConn(t, conn)
	}
}

func (s *testAdminServer) handleConn(t *testing.T, conn net.Conn) {
	defer s.wg.Done()
	s.addConn(conn)
	defer s.removeConn(conn)
	defer conn.Close() //nolint:errcheck
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	s.addEncoder(enc)
	defer s.removeEncoder(enc)

	for {
		var msg envelope
		if err := dec.Decode(&msg); err != nil {
			if !s.isDone() && !errors.Is(err, net.ErrClosed) {
				t.Logf("decode admin message: %v", err)
			}
			return
		}
		switch msg.Type {
		case messageTypeConfigRequest:
			if err := enc.Encode(s.configEnvelope()); err != nil {
				t.Logf("encode config: %v", err)
				return
			}
		case messageTypeMutation:
			var payload mutationPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				t.Logf("decode mutation payload: %v", err)
				return
			}
			select {
			case s.msgs <- payload:
			case <-s.done:
				return
			}
			if err := enc.Encode(envelope{
				Type: messageTypeMutationResult,
				Payload: mustJSON(t, mutationResult{
					OK: true,
				}),
			}); err != nil {
				t.Logf("encode mutation result: %v", err)
				return
			}
		case messageTypeSubscribe:
		default:
			t.Logf("unexpected admin message type %q", msg.Type)
		}
	}
}

func (s *testAdminServer) nextMutation(t *testing.T) mutationPayload {
	t.Helper()
	select {
	case msg := <-s.msgs:
		return msg
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for mutation")
		return mutationPayload{}
	}
}

func (s *testAdminServer) assertNoMutation(t *testing.T) {
	t.Helper()
	select {
	case msg := <-s.msgs:
		t.Fatalf("unexpected mutation: %+v", msg)
	case <-time.After(150 * time.Millisecond):
	}
}

func (s *testAdminServer) sendInterfaces(t *testing.T, names ...string) {
	t.Helper()
	s.mu.Lock()
	s.interfaces = namedInterfaces(names...)
	encoders := make([]*json.Encoder, 0, len(s.encoders))
	for enc := range s.encoders {
		encoders = append(encoders, enc)
	}
	event := envelope{
		Type: messageTypeEvent,
		Payload: mustJSON(t, eventPayload{
			EventType: eventTypeInterfaces,
			Config: currentConfig{
				Interfaces: append([]apiInterface(nil), s.interfaces...),
			},
		}),
	}
	s.mu.Unlock()

	for _, enc := range encoders {
		if err := enc.Encode(event); err != nil {
			t.Fatalf("send interfaces event: %v", err)
		}
	}
}

func (s *testAdminServer) configEnvelope() envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return envelope{
		Type: messageTypeConfig,
		Payload: mustRawMessage(configPayload{
			Config: currentConfig{
				Interfaces: append([]apiInterface(nil), s.interfaces...),
			},
		}),
	}
}

func (s *testAdminServer) addEncoder(enc *json.Encoder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encoders[enc] = true
}

func (s *testAdminServer) removeEncoder(enc *json.Encoder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.encoders, enc)
}

func (s *testAdminServer) addConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[conn] = true
}

func (s *testAdminServer) removeConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

func (s *testAdminServer) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *testAdminServer) close() {
	s.once.Do(func() {
		close(s.done)
		_ = s.listener.Close()
		s.mu.Lock()
		conns := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			conns = append(conns, conn)
		}
		s.mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		s.wg.Wait()
	})
}

func namedInterfaces(names ...string) []apiInterface {
	out := make([]apiInterface, 0, len(names))
	for _, name := range names {
		out = append(out, apiInterface{Name: name})
	}
	return out
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return data
}

func closeClient(t *testing.T, client *Client) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
