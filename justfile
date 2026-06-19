test:
  go test ./... -race -count=10

debug-dns:
	go build -o ./debug ./cmd/debug
	sudo ./debug dns

debug-tun:
	go build -o ./debug ./cmd/debug
	sudo ./debug tun-name debug

debug-subnet:
	go build -o ./debug ./cmd/debug
	./debug subnet

debug-killswitch:
	go build -o ./debug ./cmd/debug
	./debug killswitch

e2e-dns *cases:
	./e2e/dns/run.sh {{cases}}

e2e-routing:
	./e2e/routing/run.sh

test-total: test e2e-dns e2e-routing
