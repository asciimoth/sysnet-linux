FROM golang:1.25-bookworm

RUN set -eux; \
	apt-get update; \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates \
		iproute2 \
		nftables; \
	rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENTRYPOINT ["go", "test", "./privilegedfuzz"]
