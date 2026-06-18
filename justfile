test:
  go test ./... -race -count=10

debug-dns:
	go build -o ./debug ./cmd/debug
	sudo ./debug dns

debug-subnet:
	go build -o ./debug ./cmd/debug
	./debug subnet

e2e-dns *cases:
	./e2e/dns/run.sh {{cases}}

test-total: test e2e-dns
