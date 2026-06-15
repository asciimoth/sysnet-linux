debug-dns:
	go build -o ./debug ./cmd/debug
	sudo ./debug dns
