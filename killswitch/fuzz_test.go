//go:build linux

// nolint
package killswitch

import (
	"encoding/json"
	"net"
	"testing"
)

func FuzzUntrustedInput(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"type":"config","payload":{"config":{"interfaces":[{"name":"eth0"}]}}}`),
		[]byte(`{"type":"event","payload":{"event_type":"interfaces","config":{}}}`),
		[]byte(`{"type":"mutation_result","payload":{"ok":false,"error":"denied"}}`),
		[]byte("{\"type\":\"config\"}\n{\"type\":\"event\"}\n"),
		[]byte(`not-json`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64<<10 {
			input = input[:64<<10]
		}
		var env envelope
		if err := json.Unmarshal(input, &env); err == nil {
			session := &apiSession{
				setInterfaces: func([]apiInterface) {},
				logf:          func(string, ...any) {},
			}
			session.handleMessage(env)
		}

		var rules AllowRules
		_ = json.Unmarshal(input, &rules)
		normalizeAllowRules(&rules)
		_ = mergeAllowRules(rules, rules)
		fuzzClientState(input, rules)

		client, server := net.Pipe()
		session := newAPISession(
			client,
			func([]apiInterface) {},
			func(string, ...any) {},
		)
		go func() {
			_, _ = server.Write(input)
			_ = server.Close()
		}()
		<-session.closed
	})
}

func fuzzClientState(input []byte, base AllowRules) {
	client := &Client{
		rulesets: make(map[uint64]AllowRules),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	if len(input) > 1 && input[0]&1 != 0 {
		client.nextRulesetID = ^uint64(0) - uint64(input[1]&1)
	}
	ids := make([]uint64, 0, 16)
	for i, operation := range input[:min(len(input), 64)] {
		rules := cloneAllowRules(base)
		rules.EnableV4 = operation&1 != 0
		rules.EnableV6 = operation&2 != 0
		rules.AllowedPorts = append(
			rules.AllowedPorts,
			string(input[i:min(len(input), i+8)]),
		)
		switch operation % 7 {
		case 0:
			if id, err := client.CreateTMPRuleset(rules); err == nil {
				ids = append(ids, id)
			}
		case 1:
			id := uint64(operation)
			if len(ids) != 0 {
				id = ids[int(operation)%len(ids)]
			}
			_ = client.UpdateTMPRuleset(id, rules)
		case 2:
			id := uint64(operation)
			if len(ids) != 0 {
				id = ids[int(operation)%len(ids)]
			}
			_ = client.DeleteTMPRuleset(id)
		case 3:
			client.setInterfaces([]apiInterface{
				{Name: string(input[i:min(len(input), i+8)])},
				{Name: "wg0"},
			})
		case 4:
			client.resetInterfaces()
		case 5:
			_, _, _, _ = client.snapshot()
		case 6:
			client.notify()
		}
	}
	_ = client.Close()
	_ = client.Close()
	_, _ = client.CreateTMPRuleset(base)
	_ = client.UpdateTMPRuleset(1, base)
	_ = client.DeleteTMPRuleset(1)
}
